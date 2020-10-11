package nacl

import (
	"crypto/rand"
	"fmt"

	libnacl "github.com/kevinburke/nacl"
	box "github.com/kevinburke/nacl/box"
	secretbox "github.com/kevinburke/nacl/secretbox"
	"github.com/vanclief/ez"
	"github.com/vanclief/go-crypto/keys"
)

// Key represents a NaCL Key
type Key struct {
	*keys.Key
}

// KeyPair represents a NaCL Key Pair
type KeyPair struct {
	*keys.KeyPair
}

// NewKey returns a new NaCl Key with cryptographic random data. It will panic
// if it can't read the correct amount of random data
func NewKey() *Key {
	naclKey := libnacl.NewKey()
	key := KeyToBytes(&naclKey)

	return &Key{keys.New(key, keys.C25519)}
}

// KeyFromHex returns a NaCl key from a 64 byte hex string
func KeyFromHex(hex string) (*Key, error) {
	const op = "Crypto.LoadNaclKey"

	naclKey, err := libnacl.Load(hex[2:])
	if err != nil {
		return nil, ez.Wrap(op, err)
	}

	key := KeyToBytes(&naclKey)

	return &Key{keys.New(key, keys.C25519)}, err
}

// NewKeyPair returns a pair of NaCl keys (Public and Private key)
func NewKeyPair() (*KeyPair, error) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)

	pub := KeyToBytes(&publicKey)
	priv := KeyToBytes(&privateKey)

	return &KeyPair{keys.NewKeyPair(pub, priv, keys.C25519)}, err
}

// KeyToBytes converts a Nacl Key to a byte array
func KeyToBytes(key *libnacl.Key) []byte {
	k := *key
	var b []byte = k[:]
	return b
}

// KeyFromBytes converts a byte array to a Nacl Key
func KeyFromBytes(b []byte) *libnacl.Key {
	var key libnacl.Key = new([libnacl.KeySize]byte)
	copy(key[:], b)

	return &key
}

// NewNonce returns a new NaCl Nonce with cryptographically random data. It will
// panic if it can't read the correct amount of random data.
func NewNonce() *libnacl.Nonce {
	n := libnacl.NewNonce()
	return &n
}

// NonceToBytes converts a NaCl Nonce to a byte array
func NonceToBytes(nonce *libnacl.Nonce) []byte {
	n := *nonce
	var b []byte = n[:]
	return b
}

// NonceFromBytes converts a byte array to a Nacl Nonce
func NonceFromBytes(b []byte) *libnacl.Nonce {
	var nonce libnacl.Nonce = new([libnacl.NonceSize]byte)
	copy(nonce[:], b)

	return &nonce
}

// SecretboxSeal creates an encrypted secretbox from a message, a NaCl key and a NaCl nonce
func SecretboxSeal(message []byte, key []byte, nonce *libnacl.Nonce) ([]byte, error) {
	const op = "NaCL.SecretboxSeal"
	var err error

	defer func() {
		if r := recover(); r != nil {
			err = ez.New(op, ez.EINTERNAL, fmt.Sprint(r), nil)
		}
	}()

	k := KeyFromBytes(key)
	box := secretbox.Seal(nil, message, *nonce, *k)

	return box, err
}

// SecretboxOpen decrypts a secretbox using a NaCl key and a NaCl nonce
func SecretboxOpen(box, key []byte, nonce *libnacl.Nonce) ([]byte, error) {
	const op = "NaCL.SecretboxOpen"
	var err error

	defer func() {
		if r := recover(); r != nil {
			err = ez.New(op, ez.EINTERNAL, fmt.Sprint(r), nil)
		}
	}()

	k := KeyFromBytes(key)

	msg, success := secretbox.Open(nil, box, *nonce, *k)
	if !success {
		return nil, ez.New(op, ez.EINVALID, "Could not open Secretbox, invalid box or credentials", nil)
	}

	return msg, err
}

// BoxSeal creates an encrypted box from a message, a public key, a private key and a NaCl nonce
func BoxSeal(message []byte, publicKey, privateKey []byte, nonce *libnacl.Nonce) ([]byte, error) {
	const op = "NaCL.BoxSeal"
	var err error

	defer func() {
		if r := recover(); r != nil {
			err = ez.New(op, ez.EINTERNAL, fmt.Sprint(r), nil)
		}
	}()

	pub := KeyFromBytes(publicKey)
	priv := KeyFromBytes(privateKey)

	box := box.Seal(nil, message, *nonce, *pub, *priv)

	return box, err
}

// BoxOpen decrypts a box using a public key, a private key and a NaCl nonce.
func BoxOpen(b []byte, publicKey, privateKey []byte, nonce *libnacl.Nonce) ([]byte, error) {
	const op = "NaCL.BoxOpen"
	var err error

	defer func() {
		if r := recover(); r != nil {
			err = ez.New(op, ez.EINTERNAL, fmt.Sprint(r), nil)
		}
	}()

	pub := KeyFromBytes(publicKey)
	priv := KeyFromBytes(privateKey)

	msg, success := box.Open(nil, b, *nonce, *pub, *priv)
	if !success {
		return nil, ez.New(op, ez.EINVALID, "Could not open Box, invalid box or credentials", nil)
	}

	return msg, err
}
