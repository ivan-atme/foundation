package unit

import (
	"crypto/ecdsa"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/anoideaopen/foundation/keys/eth"
	"github.com/anoideaopen/foundation/mock"
	"github.com/anoideaopen/foundation/token"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	TestTokenName     = "Test Token"
	TestTokenSymbol   = "TT"
	TestTokenDecimals = 8
	TestTokenAdmin    = ""
)

const (
	FiatChaincodeName = "fiat"
	FiatChannelName   = "fiat"
	EmitFunctionName  = "emit"
	EmitAmount        = "1000"
	ExpectedAmount    = 1000
)

var (
	ErrEmptyString   = &decError{"empty hex string"}
	ErrSyntax        = &decError{"invalid hex string"}
	ErrMissingPrefix = &decError{"hex string without 0x prefix"}
	ErrOddLength     = &decError{"hex string of odd length"}
	ErrUint64Range   = &decError{"hex number > 64 bits"}
)

type decError struct{ msg string }

func (err decError) Error() string { return err.msg }

func Test_KeysEth(t *testing.T) {
	const (
		messageHex       = "0xb412a9afc250a81b76a64bf59f960839489577ccc5a9b545c574de11a2769455"
		privateKeyBase58 = "C9esAjsYJEhaTvfMRrPcFnY2WLnmTdohvVzd8dzxPZ3v"
		publicKeyBase58  = "PmNVcznMPM7xg5eSGWA7LLrW2kqfNMbnpEBVWhKg3yGShfEj6Eec5KrahQFTWBuQQ8ZHecPtXVCUm88ensE6ztKG"

		expectedMessageHashHex = "0x5bfd8fe42a24d57342ac211dcf319ec148302c17b0f0bfa85d83fb82bb13ac5b"
		expectedSignatureHex   = "0xf39b93ed322d7334c891516d8bee70b44c6b46b2dc3b9f6ad06d896975ffca0511f712296cc705d435cff51391275f8ae3dd09a4d5619df7a295606cc8e555d21c"
	)

	var (
		digest     []byte
		signature  []byte
		privateKey *ecdsa.PrivateKey
	)

	t.Run("ethereum hash", func(t *testing.T) {
		var (
			message  = MustDecode(messageHex)
			expected = MustDecode(expectedMessageHashHex)
		)
		digest = eth.Hash(message)
		assert.Equal(t, expected, digest)
	})

	t.Run("ethereum signature", func(t *testing.T) {
		var (
			err      error
			expected = MustDecode(expectedSignatureHex)
		)
		privateKey, err = eth.PrivateKeyFromBytes(base58.Decode(privateKeyBase58))
		require.NoError(t, err)
		signature, err = eth.Sign(digest, privateKey)
		require.NoError(t, err)
		assert.Equal(t, expected, signature)
	})

	t.Run("verify ethereum signature", func(t *testing.T) {
		publicKey := base58.Decode(publicKeyBase58)
		assert.True(t, eth.Verify(publicKey, digest, signature))
	})
}

func Test_Secp256k1Signatures(t *testing.T) {
	var (
		m                = mock.NewLedger(t)
		owner            = m.NewWallet()
		feeAddressSetter = m.NewWallet()
		feeSetter        = m.NewWallet()
		user1            = m.NewWallet()
		fiat             = NewFiatTestToken(token.BaseToken{})
	)

	owner.UseSecp256k1Key()

	config := makeBaseTokenConfig(
		TestTokenName,
		TestTokenSymbol,
		TestTokenDecimals,
		owner.Address(),
		feeSetter.Address(),
		feeAddressSetter.Address(),
		TestTokenAdmin,
		nil,
	)

	m.NewCC(
		FiatChaincodeName,
		fiat,
		config,
	)

	owner.SignedInvoke(FiatChannelName, EmitFunctionName, user1.Address(), EmitAmount)
	user1.BalanceShouldBe(FiatChannelName, ExpectedAmount)
}

// MustDecode decodes a hex string with 0x prefix. It panics for invalid input.
// function was copied from github.com/ethereum/go-ethereum/common/hexutil
func MustDecode(input string) []byte {
	dec, err := Decode(input)
	if err != nil {
		panic(err)
	}
	return dec
}

// Decode decodes a hex string with 0x prefix.
func Decode(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrEmptyString
	}
	if !has0xPrefix(input) {
		return nil, ErrMissingPrefix
	}
	b, err := hex.DecodeString(input[2:])
	if err != nil {
		err = mapError(err)
	}
	return b, err
}

func has0xPrefix(input string) bool {
	return len(input) >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')
}

func mapError(err error) error {
	if err, ok := err.(*strconv.NumError); ok {
		switch err.Err {
		case strconv.ErrRange:
			return ErrUint64Range
		case strconv.ErrSyntax:
			return ErrSyntax
		}
	}
	if _, ok := err.(hex.InvalidByteError); ok {
		return ErrSyntax
	}
	if err == hex.ErrLength {
		return ErrOddLength
	}
	return err
}
