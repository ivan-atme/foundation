package eth

import (
	"crypto/ecdsa"

	crypto2 "github.com/anoideaopen/foundation/keys/eth/crypto"
)

const signatureLength = 64

// Sign calculates an ECDSA signature using copied Ethereum crypto functions
func Sign(digest []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	const recoveryBits = 27

	signature, err := crypto2.Sign(digest, privateKey)
	if err != nil {
		return nil, err
	}
	if len(signature) == signatureLength+1 {
		signature[signatureLength] += recoveryBits
	}
	return signature, nil
}

// Verify checks that the given public key created signature over digest
// using copied Ethereum crypto functions
func Verify(publicKey, digest, signature []byte) bool {
	if len(signature) > signatureLength {
		signature = signature[:signatureLength]
	}
	return crypto2.VerifySignature(publicKey, digest, signature)
}
