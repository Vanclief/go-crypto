package nacl

import (
	"testing"

	libnacl "github.com/kevinburke/nacl"
	"github.com/vanclief/go-crypto/argon2"
	"github.com/vanclief/go-crypto/keys"
	"github.com/vanclief/go-crypto/utils"

	"github.com/stretchr/testify/assert"
)

func TestNewKey(t *testing.T) {
	key := NewKey()
	assert.NotNil(t, key)
	assert.NotNil(t, &key)
}

func TestNewKeypair(t *testing.T) {
	keyPair, err := NewKeyPair()
	assert.NotNil(t, keyPair)
	assert.NotNil(t, &keyPair)
	assert.Nil(t, err)
	assert.NotNil(t, keyPair.PublicKey)
	assert.NotNil(t, keyPair.PrivateKey)
	assert.Equal(t, keys.C25519, keyPair.Type)
}

func TestLoadNaclKey(t *testing.T) {
	// Case 1: Should work
	key, err := KeyFromHex("e1268fe78e064700fe6b98e47dc0758a4f966bd027299b685642c607ea376b7d47")
	assert.NotNil(t, key)
	assert.Nil(t, err)

	// Case 2: Should work with an Argon2 Key
	argonKey, err := argon2.KDF("password123", "tester@gmail.com")
	argonHex := utils.BytesToHex(argonKey.Value)

	naclKey, err := KeyFromHex(argonHex)
	naclBase64 := utils.BytesToBase64(naclKey.Value)

	assert.NotNil(t, naclKey)
	assert.Nil(t, err)
	assert.Equal(t, "ry86D23WlX277BAkXN6Em8Q9WV0hoiPr2LIIAAYmdlw", naclBase64)
}

func TestKeyToBytes(t *testing.T) {
	key := libnacl.NewKey()
	b := KeyToBytes(&key)

	assert.NotNil(t, b)
	assert.Equal(t, len(*key), len(b))
}

func TestKeyFromBytes(t *testing.T) {
	key := libnacl.NewKey()
	b := KeyToBytes(&key)
	k := KeyFromBytes(b)

	assert.NotNil(t, k)
	assert.Equal(t, len(*k), len(b))
	assert.Equal(t, key, *k)
}

func TestNewNonce(t *testing.T) {
	nonce := NewNonce()
	assert.NotNil(t, nonce)
	assert.NotNil(t, &nonce)
}

func TestNaclNonceToBytes(t *testing.T) {
	nonce := NewNonce()
	b := NonceToBytes(nonce)

	assert.NotNil(t, b)
	assert.Equal(t, len(*nonce), len(b))
}

func TestNaclNonceFromBytes(t *testing.T) {
	nonce := NewNonce()
	b := NonceToBytes(nonce)
	n := NonceFromBytes(b)

	assert.NotNil(t, n)
	assert.Equal(t, len(*n), len(b))
	assert.Equal(t, *n, *nonce)
}

func TestSecretboxSeal(t *testing.T) {
	key := NewKey()
	nonce := NewNonce()
	msg := []byte("Secret message")

	encrypted, err := SecretboxSeal(msg, key.Value, nonce)
	assert.Nil(t, err)
	assert.NotNil(t, encrypted)
}

func TestSecretboxOpen(t *testing.T) {
	// Setup
	key := NewKey()
	nonce := NewNonce()
	nonce2 := NewNonce()
	msg := []byte("Secret message")
	encrypted, _ := SecretboxSeal(msg, key.Value, nonce)

	// Case 1: Successs
	decrypted, err := SecretboxOpen(encrypted, key.Value, nonce)
	assert.NotNil(t, decrypted)
	assert.Nil(t, err)
	assert.Equal(t, decrypted, msg)

	// Case 2: Should fail with wrong nonce
	decrypted, err = SecretboxOpen(encrypted, key.Value, nonce2)
	assert.Nil(t, decrypted)
	assert.NotNil(t, err)
}

func TestBoxSeal(t *testing.T) {
	keyPair1, _ := NewKeyPair()
	keyPair2, _ := NewKeyPair()
	nonce := NewNonce()

	msg := []byte("Secret message")

	encrypted, err := BoxSeal(msg, keyPair1.PublicKey, keyPair2.PrivateKey, nonce)

	assert.Nil(t, err)
	assert.NotNil(t, encrypted)
}

func TestBoxOpen(t *testing.T) {
	// Setup
	keyPair1, _ := NewKeyPair()
	keyPair2, _ := NewKeyPair()
	nonce := NewNonce()
	nonce2 := NewNonce()
	msg := []byte("Secret message")
	encrypted, _ := BoxSeal(msg, keyPair1.PublicKey, keyPair2.PrivateKey, nonce)

	// Case 1: Successs
	decrypted, err := BoxOpen(encrypted, keyPair2.PublicKey, keyPair1.PrivateKey, nonce)
	assert.NotNil(t, decrypted)
	assert.Nil(t, err)
	assert.Equal(t, decrypted, msg)

	// Case 2: Should fail with wrong nonce
	decrypted, err = BoxOpen(encrypted, keyPair2.PublicKey, keyPair1.PrivateKey, nonce2)
	assert.Nil(t, decrypted)
	assert.NotNil(t, err)

	// Case 3: Should fail with same keys
	decrypted, err = BoxOpen(encrypted, keyPair2.PublicKey, keyPair2.PrivateKey, nonce)
	assert.Nil(t, decrypted)
	assert.NotNil(t, err)
}
