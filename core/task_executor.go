package core

import (
	"encoding/hex"
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/anoideaopen/foundation/core/cachestub"
	"github.com/anoideaopen/foundation/core/logger"
	"github.com/anoideaopen/foundation/core/telemetry"
	"github.com/anoideaopen/foundation/core/types"
	"github.com/anoideaopen/foundation/hlfcreator"
	"github.com/anoideaopen/foundation/proto"
	pb "github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
)

const ExecuteTasksEvent = "executeTasks"

var ErrTasksNotFound = errors.New("no tasks found")

// TaskExecutor handles the execution of a group of tasks.
type TaskExecutor struct {
	BatchCacheStub *cachestub.BatchCacheStub
	Chaincode      *Chaincode
	SKI            string
	TracingHandler *telemetry.TracingHandler
}

// NewTaskExecutor initializes a new TaskExecutor.
func NewTaskExecutor(stub shim.ChaincodeStubInterface, cc *Chaincode, tracingHandler *telemetry.TracingHandler) *TaskExecutor {
	return &TaskExecutor{
		BatchCacheStub: cachestub.NewBatchCacheStub(stub),
		Chaincode:      cc,
		TracingHandler: tracingHandler,
	}
}

// TasksExecutorHandler executes multiple sub-transactions (tasks) within a single transaction in Hyperledger Fabric,
// using cached state between tasks to solve the MVCC problem. Each request in the arguments contains its own set of
// arguments for the respective chaincode method calls.
func TasksExecutorHandler(
	traceCtx telemetry.TraceContext,
	stub shim.ChaincodeStubInterface,
	cc *Chaincode,
	creatorSKI [32]byte,
	hashedCert [32]byte,
) ([]byte, error) {
	tracingHandler := cc.contract.TracingHandler()
	traceCtx, span := tracingHandler.StartNewSpan(traceCtx, ExecuteTasks)
	defer span.End()

	log := logger.Logger()
	txID := stub.GetTxID()
	span.SetAttributes(attribute.String("tx_id", txID))
	start := time.Now()
	defer func() {
		log.Infof("tasks executor: tx id: %s, elapsed: %s", txID, time.Since(start))
	}()

	robotSKIBytes, _ := hex.DecodeString(cc.contract.ContractConfig().GetRobotSKI())

	err := hlfcreator.ValidateSKI(robotSKIBytes, creatorSKI, hashedCert)
	if err != nil {
		return nil, fmt.Errorf("unauthorized: robotSKI is not equal creatorSKI and hashedCert: %w", err)
	}

	_, args := stub.GetFunctionAndParameters()

	if len(args) != 1 {
		err := fmt.Errorf("failed to validate args for transaction %s: expected exactly 1 argument, received %d", txID, len(args))
		return nil, handleTasksError(span, err)
	}

	var executeTaskRequest proto.ExecuteTasksRequest
	if err := unmarshalExecuteTaskRequest([]byte(args[0]), &executeTaskRequest); err != nil {
		err = fmt.Errorf("failed to unmarshal argument to ExecuteTasksRequest for transaction %s, argument: %s", txID, args[0])
		return nil, handleTasksError(span, err)
	}

	log.Warningf("tasks executor: tx id: %s, txs: %d", txID, len(executeTaskRequest.GetTasks()))

	if len(executeTaskRequest.GetTasks()) == 0 {
		err := fmt.Errorf("failed to validate argument: no tasks found in ExecuteTasksRequest for transaction %s: %w", txID, ErrTasksNotFound)
		return nil, handleTasksError(span, err)
	}

	executor := NewTaskExecutor(stub, cc, tracingHandler)

	response, event, err := executor.ExecuteTasks(traceCtx, executeTaskRequest.GetTasks())
	if err != nil {
		return nil, handleTasksError(span, fmt.Errorf("failed to handle task for transaction %s: %w", txID, err))
	}

	eventData, err := pb.Marshal(event)
	if err != nil {
		return nil, handleTasksError(span, fmt.Errorf("failed to marshal event for transaction %s: %w", txID, err))
	}

	err = stub.SetEvent(ExecuteTasksEvent, eventData)
	if err != nil {
		return nil, handleTasksError(span, fmt.Errorf("failed to set event for transaction %s: %w", txID, err))
	}

	data, err := pb.Marshal(response)
	if err != nil {
		return nil, handleTasksError(span, fmt.Errorf("failed to marshal response for transaction %s: %w", txID, err))
	}

	return data, nil
}

// unmarshalExecuteTaskRequest try to unmarshal proto and if failed unmarshal protojson
func unmarshalExecuteTaskRequest(data []byte, executeTaskRequest *proto.ExecuteTasksRequest) error {
	if err := pb.Unmarshal(data, executeTaskRequest); err != nil {
		// If standard protobuf unmarshalling fails, try JSON format
		if err := protojson.Unmarshal(data, executeTaskRequest); err != nil {
			return err
		}
	}
	return nil
}

// ExecuteTasks processes a group of tasks, returning a group response and event.
func (e *TaskExecutor) ExecuteTasks(
	traceCtx telemetry.TraceContext,
	tasks []*proto.Task,
) (*proto.BatchResponse, *proto.BatchEvent, error) {
	traceCtx, span := e.TracingHandler.StartNewSpan(traceCtx, "TaskExecutor.ExecuteTasks")
	defer span.End()

	batchResponse := &proto.BatchResponse{}
	batchEvent := &proto.BatchEvent{}

	predictACLCalls(e.BatchCacheStub, tasks, e.Chaincode)

	for _, task := range tasks {
		txResponse, txEvent := e.ExecuteTask(traceCtx, task, e.BatchCacheStub)
		batchResponse.TxResponses = append(batchResponse.TxResponses, txResponse)
		batchEvent.Events = append(batchEvent.Events, txEvent)
	}

	if err := e.BatchCacheStub.Commit(); err != nil {
		return nil, nil, fmt.Errorf("failed to commit changes using BatchCacheStub: %w", err)
	}

	return batchResponse, batchEvent, nil
}

// validatedTxSenderMethodAndArgs validates the sender, method, and arguments for a transaction.
func (e *TaskExecutor) validatedTxSenderMethodAndArgs(
	traceCtx telemetry.TraceContext,
	stub *cachestub.BatchCacheStub,
	task *proto.Task,
) (*proto.Address, string, []string, error) {
	_, span := e.TracingHandler.StartNewSpan(traceCtx, "TaskExecutor.validatedTxSenderMethodAndArgs")
	defer span.End()

	span.AddEvent("parsing chaincode method")
	method := e.Chaincode.Router().Method(task.GetMethod())
	if method == "" {
		err := fmt.Errorf(
			"failed to parse chaincode method '%s' for task %s: method '%s' not found",
			task.GetMethod(),
			task.GetId(),
			task.GetMethod(),
		)
		span.SetStatus(codes.Error, err.Error())
		return nil, "", nil, err
	}

	span.AddEvent("validating and extracting invocation context")
	senderAddress, invocationArgs, nonce, err := e.Chaincode.validateAndExtractInvocationContext(
		stub,
		task.GetMethod(),
		task.GetArgs(),
	)
	if err != nil {
		err = fmt.Errorf("failed to validate and extract invocation context for task %s: %w", task.GetId(), err)
		span.SetStatus(codes.Error, err.Error())
		return nil, "", nil, err
	}

	span.AddEvent("validating authorization")
	if !e.Chaincode.Router().AuthRequired(method) {
		return nil, method, invocationArgs, nil
	}
	if senderAddress == nil {
		err = fmt.Errorf("failed to validate authorization for task %s: sender address is missing", task.GetId())
		span.SetStatus(codes.Error, err.Error())
		return nil, "", nil, err
	}
	argsToValidate := append([]string{senderAddress.AddrString()}, invocationArgs...)

	span.AddEvent("validating arguments")
	if err = e.Chaincode.Router().Check(stub, method, argsToValidate...); err != nil {
		err = fmt.Errorf("failed to validate arguments for task %s: %w", task.GetId(), err)
		span.SetStatus(codes.Error, err.Error())
		return nil, "", nil, err
	}

	span.AddEvent("validating nonce")
	sender := types.NewSenderFromAddr((*types.Address)(senderAddress))
	err = checkNonce(stub, sender, nonce)
	if err != nil {
		err = fmt.Errorf("failed to validate nonce for task %s, nonce %d: %w", task.GetId(), nonce, err)
		span.SetStatus(codes.Error, err.Error())
		return nil, "", nil, err
	}

	argCount := e.Chaincode.Router().ArgCount(method)

	return senderAddress, method, invocationArgs[:argCount-1], nil
}

// ExecuteTask processes an individual task, returning a transaction response and event.
func (e *TaskExecutor) ExecuteTask(
	traceCtx telemetry.TraceContext,
	task *proto.Task,
	stub *cachestub.BatchCacheStub,
) (txResponse *proto.TxResponse, batchTxEvent *proto.BatchTxEvent) {
	traceCtx, span := e.TracingHandler.StartNewSpan(traceCtx, "TaskExecutor.ExecuteTasks")
	defer span.End()

	log := logger.Logger()
	start := time.Now()
	span.SetAttributes(attribute.String("task_method", task.GetMethod()))
	span.SetAttributes(attribute.StringSlice("task_args", task.GetArgs()))
	span.SetAttributes(attribute.String("task_id", task.GetId()))
	defer func() {
		log.Infof("task method %s task %s elapsed: %s", task.GetMethod(), task.GetId(), time.Since(start))
	}()

	defer func() {
		if rc := recover(); rc != nil {
			txResponse = &proto.TxResponse{Id: []byte(task.GetId()), Method: task.GetMethod(), Error: &proto.ResponseError{Error: "panic while executing task"}}
			batchTxEvent = &proto.BatchTxEvent{Id: []byte(task.GetId()), Method: task.GetMethod(), Error: &proto.ResponseError{Error: "panic ExecuteTask"}}
			log.Criticalf("Task id: %s, panic: %s", task.GetId(), string(debug.Stack()))
		}
	}()

	txCacheStub := stub.NewTxCacheStub(task.GetId())

	span.AddEvent("validating tx sender method and args")
	senderAddress, method, args, err := e.validatedTxSenderMethodAndArgs(traceCtx, stub, task)
	if err != nil {
		err = fmt.Errorf("failed to validate transaction sender, method, and arguments for task %s: %w", task.GetId(), err)
		return handleTaskError(span, task, err)
	}

	span.AddEvent("calling method")
	response, err := e.Chaincode.InvokeContractMethod(traceCtx, txCacheStub, senderAddress, method, args)
	if err != nil {
		return handleTaskError(span, task, err)
	}

	span.AddEvent("commit")
	writes, events := txCacheStub.Commit()

	sort.Slice(txCacheStub.Accounting, func(i, j int) bool {
		return strings.Compare(txCacheStub.Accounting[i].String(), txCacheStub.Accounting[j].String()) < 0
	})

	span.SetStatus(codes.Ok, "")
	return &proto.TxResponse{
			Id:     []byte(task.GetId()),
			Method: task.GetMethod(),
			Writes: writes,
		},
		&proto.BatchTxEvent{
			Id:         []byte(task.GetId()),
			Method:     task.GetMethod(),
			Accounting: txCacheStub.Accounting,
			Events:     events,
			Result:     response,
		}
}

func handleTasksError(span trace.Span, err error) error {
	logger.Logger().Error(err)
	span.SetStatus(codes.Error, err.Error())
	return err
}

func handleTaskError(span trace.Span, task *proto.Task, err error) (*proto.TxResponse, *proto.BatchTxEvent) {
	logger.Logger().Errorf("%s: %s: %s", task.GetMethod(), task.GetId(), err)
	span.SetStatus(codes.Error, err.Error())

	ee := proto.ResponseError{Error: err.Error()}
	return &proto.TxResponse{Id: []byte(task.GetId()), Method: task.GetMethod(), Error: &ee},
		&proto.BatchTxEvent{Id: []byte(task.GetId()), Method: task.GetMethod(), Error: &ee}
}
