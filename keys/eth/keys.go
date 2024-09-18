package eth

import (
	"crypto/ecdsa"

	crypto2 "github.com/anoideaopen/foundation/keys/eth/crypto"
)

// NewKey generates new secp256k1 key using copied Ethereum crypto functions
func NewKey() (*ecdsa.PrivateKey, error) {
	return crypto2.GenerateKey()
}

// PublicKeyBytes returns bytes representation of secp256p1 public key
func PublicKeyBytes(publicKey *ecdsa.PublicKey) []byte {
	return crypto2.FromECDSAPub(publicKey)
}

// PrivateKeyFromBytes creates a secp256k1 private key from its bytes representation
func PrivateKeyFromBytes(bytes []byte) (*ecdsa.PrivateKey, error) {
	return crypto2.ToECDSA(bytes)
}

// PrivateKeyBytes returns bytes representation of secp256p1 private key
func PrivateKeyBytes(privateKey *ecdsa.PrivateKey) []byte {
	return crypto2.FromECDSA(privateKey)
}
