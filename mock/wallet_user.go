package mock

import (
	"errors"

	"github.com/hyperledger/fabric-chaincode-go/shim"
)

const (
	AddUser operation = "addUser"
)

// User represents a user in the acl
type User struct {
	// Channel       string
	// Chaincode     string
	PublicKey     string
	KYCHash       string
	UserID        string
	IsIndustrial  string
	PublicKeyType string
}

// IsValid checks if the user is valid
func (u User) IsValid() error {
	if len(u.PublicKey) == 0 {
		return errors.New("user is broken, public key is not set")
	}
	if len(u.KYCHash) == 0 {
		return errors.New("user is broken, KYC hash is not set")
	}
	if len(u.UserID) == 0 {
		return errors.New("user is broken, user ID is not set")
	}
	if len(u.PublicKeyType) == 0 {
		return errors.New("user is broken, public key type is not set")
	}
	return nil
}

// RemoveAccountRight removes a right from the access matrix
func (w *Wallet) AddUser(user *User) error {
	return w.addUser(AddUser, user)
}

func (w *Wallet) addUser(opFn operation, user *User) error {
	if user == nil {
		return errors.New("user is not set")
	}

	validationErr := user.IsValid()
	if validationErr != nil {
		return validationErr
	}

	params := [][]byte{
		[]byte(opFn),
		[]byte(user.PublicKey),
		[]byte(user.KYCHash),
		[]byte(user.UserID),
		[]byte(user.IsIndustrial),
		[]byte(user.PublicKeyType),
	}
	const acl = "acl"
	aclstub := w.ledger.GetStub(acl)
	aclstub.TxID = txIDGen()
	aclstub.MockPeerChaincodeWithChannel(acl, aclstub, acl)

	rsp := aclstub.InvokeChaincode(acl, params, acl)
	if rsp.GetStatus() != shim.OK {
		return errors.New(rsp.GetMessage())
	}

	return nil
}
