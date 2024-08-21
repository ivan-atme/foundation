package mock

import (
	"bytes"
	"encoding/hex"
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
)

const (
	rightKey                       = "acl_access_matrix"
	KeyLengthEd25519               = 32
	KeyLengthSecp256k1             = 65
	PrefixUncompressedSecp259k1Key = 0x04
	failIfExists                   = false
	True                           = "true"
	SignedAddressPrefix            = "address"
	PublicKeyPrefix                = "pk"
	PublicKeyTypePrefix            = "pk_type"
)

// mockACL emulates alc chaincode, rights are stored in state
type mockACL struct{}

type PublicKey struct {
	InBase58          string
	Bytes             []byte
	Hash              []byte
	HashInHex         string
	HashInBase58Check string
	Type              string
}

func (key *PublicKey) validateLength() error {
	valid := false

	switch key.Type {
	case pb.KeyType_secp256k1.String():
		valid = key.isSecp256k1()
	default:
		valid = key.isEd25519()
	}
	if !valid {
		return fmt.Errorf("unexpected key length %d", len(key.Bytes))
	}
	return nil
}

func (key *PublicKey) isSecp256k1() bool {
	return len(key.Bytes) == KeyLengthSecp256k1 && key.Bytes[0] == PrefixUncompressedSecp259k1Key
}

func (key *PublicKey) isEd25519() bool {
	return len(key.Bytes) == KeyLengthEd25519
}

func (ma *mockACL) Init(_ shim.ChaincodeStubInterface) peer.Response { // stub
	return shim.Success(nil)
}

func (ma *mockACL) Invoke(stub shim.ChaincodeStubInterface) peer.Response { //nolint:funlen,gocognit
	fn, args := stub.GetFunctionAndParameters()
	switch fn {
	case acl.AddUserFn:
		if len(args) != acl.AddUserArgsCount {
			return shim.Error(fmt.Sprintf(acl.WrongArgsCount, len(args), acl.AddUserArgsCount))
		}

		publicKeyString, kycHash, userID, isIndustrial, publicKeyType := args[0], args[1], args[2], args[3], args[4]
		publicKey, err := publicKeyFromBase58String(publicKeyString)
		if err != nil {
			return shim.Error(fmt.Errorf("failed decoding public key: %w", err).Error())
		}
		if len(kycHash) == 0 {
			return shim.Error(errors.New("empty kyc hash").Error())
		}
		if len(userID) == 0 {
			return shim.Error(errors.New("empty userID").Error())
		}
		isIndustrialBool := isIndustrial == True

		publicKey.Type = publicKeyType
		if !ValidatePublicKeyType(publicKey.Type) {
			return shim.Error(fmt.Errorf("unknow public key type %s", publicKeyType).Error())
		}

		if err := publicKey.validateLength(); err != nil {
			return shim.Error(fmt.Errorf("failed validating key length: %w", err).Error())
		}

		err = ma.addUser(stub, publicKey, kycHash, userID, isIndustrialBool, publicKeyType)
		if err != nil {
			return shim.Error(err.Error())
		}

		return shim.Success(nil)

	case "checkAddress":
		addressBase58Check := args[0]
		if len(addressBase58Check) == 0 {
			return shim.Error("address is empty")
		}

		addressPublicKeyCompositeKey, err := PublicKeyCompositeKey(stub, addressBase58Check)
		if err != nil {
			return shim.Error(fmt.Sprintf("publicKeyCompositeKey: %+v", err))
		}

		// Check if the public key hash exists in the ACL
		rawPublicKeyHash, err := stub.GetState(addressPublicKeyCompositeKey)
		if err != nil {
			return shim.Error(fmt.Sprintf("getState addressPublicKeyCompositeKey: %+v", err))
		}
		if len(rawPublicKeyHash) == 0 {
			return shim.Error(fmt.Errorf("no public keys for address %s", addressBase58Check).Error())
		}

		publicKeyHash := string(rawPublicKeyHash)

		// Retrieve pb.SignedAddress
		signedAddressCompositeKey, err := SignedAddressCompositeKey(stub, publicKeyHash)
		if err != nil {
			return shim.Error(fmt.Errorf("signedAddressCompositeKey: %w", err).Error())
		}

		signedAddressBytes, err := stub.GetState(signedAddressCompositeKey)
		if err != nil {
			return shim.Error(fmt.Errorf("getState signedAddressCompositeKey: %w", err).Error())
		}
		if len(signedAddressBytes) == 0 {
			return shim.Error(errors.New("no such address in the ledger").Error())
		}

		signedAddress := &pb.SignedAddress{}
		if err = proto.Unmarshal(signedAddressBytes, signedAddress); err != nil {
			return shim.Error(fmt.Errorf("unmarshal: %w", err).Error())
		}

		addr := signedAddress.GetAddress()
		data, err := proto.Marshal((*pb.Address)(addr))
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Success(data)
	case "checkKeys":
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
	case "getAccountInfo":
		data, err := json.Marshal(&pb.AccountInfo{
			KycHash:     "123",
			GrayListed:  false,
			BlackListed: false,
		})
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Success(data)
	case acl.GetAccOpRightFn:
		if len(args) != acl.GetAccOpRightArgCount {
			return shim.Error(fmt.Sprintf(acl.WrongArgsCount, len(args), acl.GetAccOpRightArgCount))
		}

		ch, cc, role, operation, addr := args[0], args[1], args[2], args[3], args[4]
		haveRight, err := ma.getRight(stub, ch, cc, role, addr, operation)
		if err != nil {
			return shim.Error(err.Error())
		}

		rawResultData, err := proto.Marshal(&pb.HaveRight{HaveRight: haveRight})
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Success(rawResultData)
	case acl.AddRightsFn:
		if len(args) != acl.AddRightsArgsCount {
			return shim.Error(fmt.Sprintf(acl.WrongArgsCount, len(args), acl.AddRightsArgsCount))
		}

		ch, cc, role, operation, addr := args[0], args[1], args[2], args[3], args[4]
		err := ma.addRight(stub, ch, cc, role, addr, operation)
		if err != nil {
			return shim.Error(err.Error())
		}

		return shim.Success(nil)
	case acl.RemoveRightsFn:
		if len(args) != acl.RemoveRightsArgsCount {
			return shim.Error(fmt.Sprintf(acl.WrongArgsCount, len(args), acl.RemoveRightsArgsCount))
		}

		ch, cc, role, operation, addr := args[0], args[1], args[2], args[3], args[4]
		err := ma.removeRight(stub, ch, cc, role, addr, operation)
		if err != nil {
			return shim.Error(err.Error())
		}

		return shim.Success(nil)
	case "getAccountsInfo":
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
	default:
		panic("should not be here")
	}
}

func (ma *mockACL) addRight(stub shim.ChaincodeStubInterface, channel, cc, role, addr, operation string) error {
	key, err := stub.CreateCompositeKey(rightKey, []string{channel, cc, role, operation})
	if err != nil {
		return err
	}

	rawAddresses, err := stub.GetState(key)
	if err != nil {
		return err
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		err = proto.Unmarshal(rawAddresses, addresses)
		if err != nil {
			return err
		}
	}

	value, ver, err := base58.CheckDecode(addr)
	if err != nil {
		return err
	}
	address := pb.Address{Address: append([]byte{ver}, value...)[:32]}

	for _, existedAddr := range addresses.GetAddresses() {
		if address.String() == existedAddr.String() {
			return nil
		}
	}

	addresses.Addresses = append(addresses.Addresses, &address)
	rawAddresses, err = proto.Marshal(addresses)
	if err != nil {
		return err
	}

	err = stub.PutState(key, rawAddresses)
	if err != nil {
		return err
	}

	return nil
}

// addUser adds user-related info to the state. It differs from acl smart-contract that:
//   - parameter rewriteIfExists is removed
//   - parameter KYCHash is not saved to the state
//   - public key type is not handled here
func (ma *mockACL) addUser(stub shim.ChaincodeStubInterface, publicKey PublicKey, _, userID string, isIndustrial bool, _ string) error {

	if err := saveSignedAddress(
		stub,
		&pb.SignedAddress{
			Address: &pb.Address{
				UserID:       userID,
				Address:      publicKey.Hash,
				IsIndustrial: isIndustrial,
				IsMultisig:   false,
			},
		},
		publicKey.HashInHex,
	); err != nil {
		return fmt.Errorf("failed saving signed address: %w", err)
	}
	if err := savePublicKey(stub, publicKey); err != nil {
		return fmt.Errorf("failed saving public key: %w", err)
	}

	return nil
}

func (ma *mockACL) removeRight(stub shim.ChaincodeStubInterface, channel, cc, role, addr, operation string) error {
	key, err := stub.CreateCompositeKey(rightKey, []string{channel, cc, role, operation})
	if err != nil {
		return err
	}

	rawAddresses, err := stub.GetState(key)
	if err != nil {
		return err
	}
	addresses := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		err := proto.Unmarshal(rawAddresses, addresses)
		if err != nil {
			return err
		}
	}

	value, ver, err := base58.CheckDecode(addr)
	if err != nil {
		return err
	}
	address := pb.Address{Address: append([]byte{ver}, value...)[:32]}

	for i, existedAddr := range addresses.GetAddresses() {
		if existedAddr.String() == address.String() {
			addresses.Addresses = append(addresses.Addresses[:i], addresses.GetAddresses()[i+1:]...)
			rawAddresses, err = proto.Marshal(addresses)
			if err != nil {
				return err
			}
			err = stub.PutState(key, rawAddresses)
			if err != nil {
				return err
			}
			break
		}
	}

	return nil
}

func (ma *mockACL) getRight(stub shim.ChaincodeStubInterface, channel, cc, role, addr, operation string) (bool, error) {
	key, err := stub.CreateCompositeKey(rightKey, []string{channel, cc, role, operation})
	if err != nil {
		return false, err
	}

	rawAddresses, err := stub.GetState(key)
	if err != nil {
		return false, err
	}

	if len(rawAddresses) == 0 {
		return false, nil
	}

	addrs := &pb.Accounts{Addresses: []*pb.Address{}}
	if len(rawAddresses) != 0 {
		err = proto.Unmarshal(rawAddresses, addrs)
		if err != nil {
			return false, err
		}
	}

	value, ver, err := base58.CheckDecode(addr)
	if err != nil {
		return false, err
	}
	address := pb.Address{Address: append([]byte{ver}, value...)[:32]}

	for _, existedAddr := range addrs.GetAddresses() {
		if existedAddr.String() == address.String() {
			return true, nil
		}
	}

	return false, nil
}

// DecodeBase58PublicKey decode public key from base58 to a byte array
func DecodeBase58PublicKey(encodedBase58PublicKey string) ([]byte, error) {
	if len(encodedBase58PublicKey) == 0 {
		return nil, errors.New("encoded base 58 public key is empty")
	}
	decode := base58.Decode(encodedBase58PublicKey)
	if len(decode) == 0 {
		return nil, fmt.Errorf("failed base58 decoding of key %s", encodedBase58PublicKey)
	}
	if !ValidateKeyLength(decode) {
		return nil, fmt.Errorf(
			"incorrect len of decoded from base58 public key '%s': '%d'",
			encodedBase58PublicKey,
			len(decode),
		)
	}

	return decode, nil
}

func DefaultPublicKeyType() string {
	return pb.KeyType_ed25519.String()
}

func ValidateKeyLength(key []byte) bool {
	if len(key) == KeyLengthEd25519 {
		return true
	}
	if len(key) == KeyLengthSecp256k1 && key[0] == PrefixUncompressedSecp259k1Key {
		return true
	}
	return false
}

func ValidatePublicKeyType(keyType string, notAllowedTypes ...string) bool {
	_, ok := pb.KeyType_value[keyType]
	if !ok {
		return false
	}
	for _, notAllowed := range notAllowedTypes {
		if notAllowed == keyType {
			return false
		}
	}
	return true
}

func SignedAddressCompositeKey(stub shim.ChaincodeStubInterface, publicKeysHashHex string) (string, error) {
	return stub.CreateCompositeKey(
		SignedAddressPrefix,
		[]string{publicKeysHashHex},
	)
}

func PublicKeyCompositeKey(stub shim.ChaincodeStubInterface, addressBase58Check string) (string, error) {
	return stub.CreateCompositeKey(
		PublicKeyPrefix,
		[]string{addressBase58Check},
	)
}

func PublicKeyType(stub shim.ChaincodeStubInterface, publicKeysHashHex string) (string, error) {
	return stub.CreateCompositeKey(
		PublicKeyTypePrefix,
		[]string{publicKeysHashHex},
	)
}

// saveSignedAddress saves the address to the state.
// It differs from acl smart-contract that parameter rewriteIfExists is removed and
// that here there are no checks that the address is already exists in acl.
func saveSignedAddress(
	stub shim.ChaincodeStubInterface,
	address *pb.SignedAddress,
	publicKeysHashHex string,
) error {
	pkToAddrCompositeKey, err := SignedAddressCompositeKey(stub, publicKeysHashHex)
	if err != nil {
		return fmt.Errorf("failed creating signed address composite key: %w", err)
	}
	addrMsg, err := proto.Marshal(address)
	if err != nil {
		return fmt.Errorf("failed marshalling signed address: %w", err)
	}

	if err = stub.PutState(pkToAddrCompositeKey, addrMsg); err != nil {
		return fmt.Errorf("failed putting signed address into the state: %w", err)
	}

	return nil
}

func savePublicKey(
	stub shim.ChaincodeStubInterface,
	key PublicKey,
) error {
	addrToPkCompositeKey, err := PublicKeyCompositeKey(stub, key.HashInBase58Check)
	if err != nil {
		return fmt.Errorf("failed creating public key composite key: %w", err)
	}
	// TODO: remove
	fmt.Printf("put state key %s\n", key.HashInBase58Check)
	if err = stub.PutState(addrToPkCompositeKey, []byte(key.HashInHex)); err != nil {
		return fmt.Errorf("failed putting address into the state: %w", err)
	}

	typeKey, err := PublicKeyType(stub, key.HashInHex)
	if err != nil {
		return fmt.Errorf("failed creating public key type composite key: %w", err)
	}

	if err = stub.PutState(typeKey, []byte(key.Type)); err != nil {
		return fmt.Errorf("failed putting public key type into the state: %w", err)
	}

	return nil
}

func publicKeyFromBase58String(base58Encoded string) (PublicKey, error) {
	bytes, err := DecodeBase58PublicKey(base58Encoded)
	if err != nil {
		return PublicKey{}, fmt.Errorf("failed decoding public key: %w", err)
	}
	hashed := sha3.Sum256(bytes)

	return PublicKey{
		InBase58:          base58Encoded,
		Bytes:             bytes,
		Hash:              hashed[:],
		HashInHex:         hex.EncodeToString(hashed[:]),
		HashInBase58Check: base58.CheckEncode(hashed[1:], hashed[0]),
		Type:              DefaultPublicKeyType(),
	}, nil
}
