package ed25519

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewKeyPair(t *testing.T) {
	keyPair, err := NewKeyPair()
	assert.NotNil(t, keyPair)
	assert.Nil(t, err)
	assert.NotNil(t, keyPair.PublicKey)
	assert.NotNil(t, keyPair.PrivateKey)
	assert.Equal(t, 32, len(keyPair.PublicKey))
	assert.Equal(t, 64, len(keyPair.PrivateKey))
}

func TestSign(t *testing.T) {
	// Setup
	keyPair, err := NewKeyPair()

	// Case 1: Should work
	sig, err := keyPair.Sign([]byte("test"))
	assert.Nil(t, err)
	assert.NotNil(t, sig)
}

func TestVerifySignature(t *testing.T) {
	// Setup
	keyPair, _ := NewKeyPair()
	sig, _ := keyPair.Sign([]byte("don't shoot the messenger"))

	// Case 1: Should work with a valid signature and a valid message
	v, err := keyPair.VerifySignature(sig, []byte("don't shoot the messenger"))
	assert.Nil(t, err)
	assert.True(t, v)

	// Case 2: Should FAIL with a valid signature and an INVALID message
	v, err = keyPair.VerifySignature(sig, []byte("shoot the messenger"))
	assert.Nil(t, err)
	assert.False(t, v)

	// Case 3: Should FAIL with a INVALID signature and a valid message
	v, err = keyPair.VerifySignature([]byte("fake"), []byte("don't shoot the messenger"))
	assert.Nil(t, err)
	assert.False(t, v)
}

func TestGenerateTimeSignature(t *testing.T) {
	// Setup
	keyPair, err := NewKeyPair()

	// Case 1: Should work
	sig, err := keyPair.GenerateTimeSignature(30)

	assert.NotNil(t, sig)
	assert.Nil(t, err)
}

func TestVerifyTimeSignature(t *testing.T) {
	// Setup
	keyPair, _ := NewKeyPair()
	sig, _ := keyPair.GenerateTimeSignature(30)

	// Case 1: Should work
	v := keyPair.VerifyTimeSignature(sig, 30)
	assert.Equal(t, true, v)

	// Case 2: Should not work with another key pair
	fakePair, _ := NewKeyPair()
	sig, _ = fakePair.GenerateTimeSignature(30)
	v = keyPair.VerifyTimeSignature(sig, 30)
	assert.Equal(t, false, v)

	// Case 3: Should not work with an expired key
	publicString := "p1uJ93IFClT3nLcLkrPIe2q5ddjZ5aXm+lkDVdEleAA="
	privateString := "LkoybxL7xjnNLnh5resGx42nhtrRVHEzl+LBTCQpdV+nW4n3cgUKVPectwuSs8h7arl12Nnlpeb6WQNV0SV4AA=="
	pub, _ := base64.StdEncoding.DecodeString(publicString)
	priv, _ := base64.StdEncoding.DecodeString(privateString)

	deterministicKeyPair, _ := LoadKeyPair(pub, priv)
	sig, _ = deterministicKeyPair.GenerateTimeSignature(30)
	sig = []byte{217, 81, 61, 195, 137, 7, 117, 170, 218, 177, 186, 215, 87, 87, 121, 33, 28, 255, 24, 97, 91, 41, 188, 234, 230, 171, 151, 57, 79, 44, 202, 2, 101, 105, 241, 165, 31, 244, 181, 166, 17, 129, 76, 50, 13, 166, 183, 25, 231, 119, 226, 90, 36, 135, 1, 229, 25, 54, 215, 125, 167, 38, 163, 2}

	v = deterministicKeyPair.VerifyTimeSignature(sig, 30)
	assert.Equal(t, false, v)
}
