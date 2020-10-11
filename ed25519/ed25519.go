package ed25519

import (
	"math"
	"strconv"
	"time"

	"github.com/vanclief/ez"

	"github.com/vanclief/go-crypto/keys"
	"golang.org/x/crypto/ed25519"
)

// KeyPair represents a pair of ed25519 cryptographic keys
type KeyPair struct {
	*keys.KeyPair
}

// NewKeyPair generates a random ed25519 public/private key pair
func NewKeyPair() (*KeyPair, error) {
	const op = "ed25519.NewKeyPair"

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, ez.New(op, ez.EINTERNAL, "Error while generating ed25519 keypair", err)
	}

	kp := keys.NewKeyPair(pub, priv, keys.ED25519)
	return &KeyPair{kp}, nil
}

// LoadKeyPair returns a keypair from existing keys key pair
func LoadKeyPair(publicKey, privateKey []byte) (*KeyPair, error) {
	const op = "ed25519.LoadKeyPair"

	kp := keys.NewKeyPair(publicKey, privateKey, keys.ED25519)
	return &KeyPair{kp}, nil
}

// Sign creates a signature that can be verified
func (kp *KeyPair) Sign(message []byte) ([]byte, error) {
	const op = "ed25519.Sign"

	if kp.PrivateKey == nil {
		return nil, ez.New(op, ez.EINVALID, "A signature can not be generated if the PrivateKey from the KeyPair is not defined", nil)
	}

	sig := ed25519.Sign(kp.PrivateKey, message)
	return sig, nil
}

// VerifySignature validates a signature
func (kp *KeyPair) VerifySignature(signature, message []byte) (bool, error) {
	const op = "ed25519.VerifySignature"

	if kp.PublicKey == nil {
		return false, ez.New(op, ez.EINVALID, "A signature can not be verified if the PublicKey from the KeyPair is not defined", nil)
	}

	v := ed25519.Verify(kp.PublicKey, message, signature)

	return v, nil
}

// GenerateTimeSignature creates a signature that can be used for the determined period in seconds
func (kp *KeyPair) GenerateTimeSignature(period int) ([]byte, error) {
	const op = "ed25519.GenerateTimeSignature"

	if kp.PrivateKey == nil {
		return nil, ez.New(op, ez.EINVALID, "A signature can not be generated if the PrivateKey from the KeyPair is not defined", nil)
	}

	counter := uint64(math.Floor(float64(time.Now().Unix()) / float64(period)))
	str := strconv.FormatUint(counter, 10)
	sig := ed25519.Sign(kp.PrivateKey, []byte(str))

	return sig, nil
}

// VerifyTimeSignature verifies a signature for the determined time period
func (kp *KeyPair) VerifyTimeSignature(signature []byte, period int) bool {
	const op = "ed25519.VerifyTimeSignature"

	counter := uint64(math.Floor(float64(time.Now().Unix()) / float64(period)))
	str := strconv.FormatUint(counter, 10)
	v := ed25519.Verify(kp.PublicKey, []byte(str), signature)

	if !v {
		return kp.verifyPreviousTimeSignature(signature, counter)
	}

	return v
}

func (kp *KeyPair) verifyPreviousTimeSignature(signature []byte, counter uint64) bool {
	const op = "ed25519.verifyPreviousTimeSignature"

	str := strconv.FormatUint(counter-1, 10)
	return ed25519.Verify(kp.PublicKey, []byte(str), signature)
}
