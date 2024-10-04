package mock

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/anoideaopen/foundation/core/acl"
	st "github.com/anoideaopen/foundation/mock/stub"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	keyRight        = "acl_access_matrix"
	keyAddressRight = "acl_access_matrix_principal_addresses"
	keyUserID       = "userID" // For tests only. Prefix to keep userIDs in test state for furhter comparison.
)

// mockACL emulates alc chaincode, rights are stored in state
type mockACL struct{}

func (ma *mockACL) Init(_ shim.ChaincodeStubInterface) peer.Response { // stub
	return shim.Success(nil)
}

func (ma *mockACL) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	fn, args := stub.GetFunctionAndParameters()
	switch fn {
	case acl.FnAddUser:
		return ma.invokeAddUser(stub, args...)
	case acl.FnCheckAddress:
		return ma.invokeCheckAddress(stub, args...)
	case acl.FnCheckKeys:
		return ma.invokeCheckKeys(stub, args...)
	case acl.FnGetAccountInfo:
		return ma.invokeGetAccountInfo()
	case acl.FnGetAccOpRight:
		return ma.invokeGetAccountOperationRight(stub, args...)
	case acl.FnAddRights:
		return ma.invokeAddRights(stub, args...)
	case acl.FnRemoveRights:
		return ma.invokeRemoveRights(stub, args...)
	case acl.FnGetAccountsInfo:
		return ma.invokeGetAccountsInfo(stub, args...)
	case acl.FnAddAddressRightForNominee:
		return ma.invokeAddAddressRightForNominee(stub, args...)
	case acl.FnRemoveAddressRightFromNominee:
		return ma.invokeRemoveAddressRightForNominee(stub, args...)
	case acl.FnGetAddressRightForNominee:
		return ma.invokeGetAddressRightForNominee(stub, args...)
	case acl.FnGetAddressesListForNominee:
		return ma.invokeGetAddressesListForNominee(stub, args...)
	default:
		panic("should not be here")
	}
}

func (ma *mockACL) invokeAddUser(stub shim.ChaincodeStubInterface, args ...string) peer.Response {
	publicKeyBase58Encoded, userID := args[0], args[1]

	bytes, err := decodeBase58PublicKey(publicKeyBase58Encoded)
	if err != nil {
		return shim.Error("failed decoding public key: " + err.Error())
	}
	hashed := sha3.Sum256(bytes)

	address := base58.CheckEncode(hashed[1:], hashed[0])
	key, err := stub.CreateCompositeKey(keyUserID, []string{address})
	if err != nil {
		return shim.Error("create composite key: " + err.Error())
	}

	data, err := proto.Marshal(&pb.Address{
		Address: append([]byte{hashed[0]}, hashed[1:]...)[:32],
		UserID:  userID,
	})
	if err != nil {
		return shim.Error("proto marshal: " + err.Error())
	}
	err = stub.PutState(key, data)
	if err != nil {
		return shim.Error("put state: " + err.Error())
	}
	return shim.Success(nil)
}

func (ma *mockACL) invokeCheckAddress(stub shim.ChaincodeStubInterface, args ...string) peer.Response {
	address := args[0]
	key, err := stub.CreateCompositeKey(keyUserID, []string{address})
	if err != nil {
		return shim.Error("create composite key: " + err.Error())
	}
	pbAddressRaw, err := stub.GetState(key)
	if err != nil {
		return shim.Error("get state: " + err.Error())
	}
	return shim.Success(pbAddressRaw)
}

func (ma *mockACL) invokeCheckKeys(stub shim.ChaincodeStubInterface, args ...string) peer.Response {
	keys := strings.Split(args[0], "/")
	binPubKeys := make([][]byte, len(keys))
	for i, k := range keys {
		binPubKeys[i] = base58.Decode(k)
	}
	sort.Slice(binPubKeys, func(i, j int) bool {
		return bytes.Compare(binPubKeys[i], binPubKeys[j]) < 0
	})

	hashed := sha3.Sum256(bytes.Join(binPubKeys, []byte("")))
	keyType := getWalletKeyType(stub, base58.CheckEncode(hashed[1:], hashed[0]))

	data, err := proto.Marshal(&pb.AclResponse{
		Account: &pb.AccountInfo{
			KycHash:    "123",
			GrayListed: false,
		},
		Address: &pb.SignedAddress{
			Address: &pb.Address{Address: hashed[:]},
			SignaturePolicy: &pb.SignaturePolicy{
				N: 2, //nolint:gomnd
			},
		},
		KeyTypes: []pb.KeyType{
			keyType,
		},
	})
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(data)
}

func (ma *mockACL) invokeGetAccountInfo() peer.Response {
	data, err := json.Marshal(&pb.AccountInfo{
		KycHash:     "123",
		GrayListed:  false,
		BlackListed: false,
	})
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(data)
}

func (ma *mockACL) invokeGetAccountOperationRight(stub shim.ChaincodeStubInterface, args ...string) peer.Response {
	if len(args) != acl.ArgsQtyGetAccOpRight {
		return shim.Error(fmt.Sprintf(acl.ErrWrongArgsCount, len(args), acl.ArgsQtyGetAccOpRight))
	}

	channel, cc, role, operationFn, address := args[0], args[1], args[2], args[3], args[4]
	key, err := stub.CreateCompositeKey(keyRight, []string{channel, cc, role, operationFn})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAddresses, err := stub.GetState(key)
	if err != nil {
		return shim.Error(err.Error())
	}

	haveRight := false
	if len(rawAddresses) != 0 {
		addrs := &pb.Accounts{Addresses: []*pb.Address{}}
		err = proto.Unmarshal(rawAddresses, addrs)
		if err != nil {
			return shim.Error(err.Error())
		}

		value, ver, err := base58.CheckDecode(address)
		if err != nil {
			return shim.Error(err.Error())
		}
		address := pb.Address{Address: append([]byte{ver}, value...)[:32]}

		for _, existedAddr := range addrs.GetAddresses() {
			if existedAddr.String() == address.String() {
				haveRight = true
				break
			}
		}
	}

	rawResultData, err := proto.Marshal(&pb.HaveRight{HaveRight: haveRight})
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(rawResultData)
}

func (ma *mockACL) invokeAddRights(stub shim.ChaincodeStubInterface, args ...string) peer.Response {
	if len(args) != acl.ArgsQtyAddRights {
		return shim.Error(fmt.Sprintf(acl.ErrWrongArgsCount, len(args), acl.ArgsQtyAddRights))
	}

	ch, cc, role, operationName, addr := args[0], args[1], args[2], args[3], args[4]
	key, err := stub.CreateCompositeKey(keyRight, []string{ch, cc, role, operationName})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAddresses, err := stub.GetState(key)
	if err != nil {
		return shim.Error(err.Error())
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		err = proto.Unmarshal(rawAddresses, addresses)
		if err != nil {
			return shim.Error(err.Error())
		}
	}

	value, ver, err := base58.CheckDecode(addr)
	if err != nil {
		return shim.Error(err.Error())
	}
	address := pb.Address{Address: append([]byte{ver}, value...)[:32]}

	for _, existedAddr := range addresses.GetAddresses() {
		if address.String() == existedAddr.String() {
			return shim.Success(nil)
		}
	}

	addresses.Addresses = append(addresses.Addresses, &address)
	rawAddresses, err = proto.Marshal(addresses)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.PutState(key, rawAddresses)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (ma *mockACL) invokeRemoveRights(stub shim.ChaincodeStubInterface, args ...string) peer.Response {
	if len(args) != acl.ArgsQtyRemoveRights {
		return shim.Error(fmt.Sprintf(acl.ErrWrongArgsCount, len(args), acl.ArgsQtyRemoveRights))
	}

	channel, cc, role, operation, addr := args[0], args[1], args[2], args[3], args[4]
	key, err := stub.CreateCompositeKey(keyRight, []string{channel, cc, role, operation})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAddresses, err := stub.GetState(key)
	if err != nil {
		return shim.Error(err.Error())
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		err := proto.Unmarshal(rawAddresses, addresses)
		if err != nil {
			return shim.Error(err.Error())
		}
	}

	value, ver, err := base58.CheckDecode(addr)
	if err != nil {
		return shim.Error(err.Error())
	}
	address := pb.Address{Address: append([]byte{ver}, value...)[:32]}

	for i, existedAddr := range addresses.GetAddresses() {
		if existedAddr.String() == address.String() {
			addresses.Addresses = append(addresses.Addresses[:i], addresses.GetAddresses()[i+1:]...)
			rawAddresses, err = proto.Marshal(addresses)
			if err != nil {
				return shim.Error(err.Error())
			}
			err = stub.PutState(key, rawAddresses)
			if err != nil {
				return shim.Error(err.Error())
			}
			break
		}
	}

	return shim.Success(nil)
}

func (ma *mockACL) invokeGetAccountsInfo(stub shim.ChaincodeStubInterface, args ...string) peer.Response {
	responses := make([]peer.Response, 0)
	for _, a := range args {
		var argsTmp []string
		err := json.Unmarshal([]byte(a), &argsTmp)
		if err != nil {
			continue
		}
		argsTmp2 := make([][]byte, 0, len(argsTmp))
		for _, a2 := range argsTmp {
			argsTmp2 = append(argsTmp2, []byte(a2))
		}
		st1, ok := stub.(*st.Stub)
		if !ok {
			continue
		}
		st1.Args = argsTmp2
		resp := ma.Invoke(stub)
		responses = append(responses, resp)
	}
	b, err := json.Marshal(responses)
	if err != nil {
		return shim.Error(fmt.Sprintf("failed get accounts info: marshal GetAccountsInfoResponse: %s", err))
	}
	return shim.Success(b)
}

func (ma *mockACL) invokeAddAddressRightForNominee(stub shim.ChaincodeStubInterface, args ...string) peer.Response {
	if len(args) != acl.ArgsQtyAddAddressRightForNominee {
		return shim.Error(fmt.Sprintf(acl.ErrWrongArgsCount, len(args), acl.ArgsQtyAddAddressRightForNominee))
	}

	channelName, chaincodeName, nomineeAddress, principalAddress := args[0], args[1], args[2], args[3]
	key, err := stub.CreateCompositeKey(keyAddressRight, []string{channelName, chaincodeName, nomineeAddress})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAddresses, err := stub.GetState(key)
	if err != nil {
		return shim.Error(err.Error())
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		err = protojson.Unmarshal(rawAddresses, addresses)
		if err != nil {
			return shim.Error(err.Error())
		}
	}

	value, ver, err := base58.CheckDecode(principalAddress)
	if err != nil {
		return shim.Error(err.Error())
	}
	address := pb.Address{Address: append([]byte{ver}, value...)[:32]}

	for _, existedAddr := range addresses.GetAddresses() {
		if address.String() == existedAddr.String() {
			return shim.Success(nil)
		}
	}

	addresses.Addresses = append(addresses.Addresses, &address)
	rawAddresses, err = protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(addresses)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.PutState(key, rawAddresses)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (ma *mockACL) invokeRemoveAddressRightForNominee(stub shim.ChaincodeStubInterface, args ...string) peer.Response {
	if len(args) != acl.ArgsQtyRemoveAddressRightFromNominee {
		return shim.Error(fmt.Sprintf(acl.ErrWrongArgsCount, len(args), acl.ArgsQtyRemoveAddressRightFromNominee))
	}

	channelName, chaincodeName, nomineeAddress, principalAddress := args[0], args[1], args[2], args[3]
	key, err := stub.CreateCompositeKey(keyAddressRight, []string{channelName, chaincodeName, nomineeAddress})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAddresses, err := stub.GetState(key)
	if err != nil {
		return shim.Error(err.Error())
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		err = protojson.Unmarshal(rawAddresses, addresses)
		if err != nil {
			return shim.Error(err.Error())
		}
	}

	value, ver, err := base58.CheckDecode(principalAddress)
	if err != nil {
		return shim.Error(err.Error())
	}
	address := pb.Address{Address: append([]byte{ver}, value...)[:32]}

	for i, existedAddr := range addresses.GetAddresses() {
		if existedAddr.String() == address.String() {
			addresses.Addresses = append(addresses.Addresses[:i], addresses.GetAddresses()[i+1:]...)
			rawAddresses, err = protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(addresses)
			if err != nil {
				return shim.Error(err.Error())
			}
			err = stub.PutState(key, rawAddresses)
			if err != nil {
				return shim.Error(err.Error())
			}
			break
		}
	}

	return shim.Success(nil)
}

func (ma *mockACL) invokeGetAddressRightForNominee(stub shim.ChaincodeStubInterface, args ...string) peer.Response {
	if len(args) != acl.ArgsQtyGetAddressRightForNominee {
		return shim.Error(fmt.Sprintf(acl.ErrWrongArgsCount, len(args), acl.ArgsQtyGetAddressRightForNominee))
	}

	channelName, chaincodeName, nomineeAddress, principalAddress := args[0], args[1], args[2], args[3]
	key, err := stub.CreateCompositeKey(keyAddressRight, []string{channelName, chaincodeName, nomineeAddress})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAddresses, err := stub.GetState(key)
	if err != nil {
		return shim.Error(err.Error())
	}

	haveRight := false
	if len(rawAddresses) != 0 {
		addrs := &pb.Accounts{Addresses: []*pb.Address{}}
		err = protojson.Unmarshal(rawAddresses, addrs)
		if err != nil {
			return shim.Error(err.Error())
		}

		value, ver, err := base58.CheckDecode(principalAddress)
		if err != nil {
			return shim.Error(err.Error())
		}
		address := pb.Address{Address: append([]byte{ver}, value...)[:32]}

		for _, existedAddr := range addrs.GetAddresses() {
			if existedAddr.String() == address.String() {
				haveRight = true
				break
			}
		}
	}

	rawResultData, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(&pb.HaveRight{HaveRight: haveRight})
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(rawResultData)
}

func (ma *mockACL) invokeGetAddressesListForNominee(stub shim.ChaincodeStubInterface, args ...string) peer.Response {
	if len(args) != acl.ArgsQtyGetAddressesListForNominee {
		return shim.Error(fmt.Sprintf(acl.ErrWrongArgsCount, len(args), acl.ArgsQtyGetAddressesListForNominee))
	}

	channelName, chaincodeName, nomineeAddress := args[0], args[1], args[2]
	key, err := stub.CreateCompositeKey(keyAddressRight, []string{channelName, chaincodeName, nomineeAddress})
	if err != nil {
		return shim.Error(err.Error())
	}

	rawAddresses, err := stub.GetState(key)
	if err != nil {
		return shim.Error(err.Error())
	}

	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		err = protojson.Unmarshal(rawAddresses, addresses)
		if err != nil {
			return shim.Error(err.Error())
		}
	}

	return shim.Success(rawAddresses)
}

// decodeBase58PublicKey decode public key from base58 to a byte array
func decodeBase58PublicKey(encodedBase58PublicKey string) ([]byte, error) {
	if len(encodedBase58PublicKey) == 0 {
		return nil, errors.New("encoded base 58 public key is empty")
	}
	decode := base58.Decode(encodedBase58PublicKey)
	if len(decode) == 0 {
		return nil, fmt.Errorf("failed base58 decoding of key %s", encodedBase58PublicKey)
	}
	return decode, nil
}
