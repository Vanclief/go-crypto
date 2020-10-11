package keys

const (
	// Argon2 is a type of Key from appying Argon2 KDF
	Argon2 Type = "argon2"
	// ED25519 is a type of KeyPair that uses the ed25519 curve
	ED25519 Type = "ed25519"
	// C25519 is a type of KeyPair that uses the curve25519
	C25519 Type = "Curve25519"
)

// Type is the type of key
type Type string

// Key represents a cryptographic key
type Key struct {
	Value []byte
	Type  Type
}

// New returns new key instance
func New(value []byte, t Type) *Key {
	return &Key{value, t}
}

// KeyPair represents a pair of cryptographic keys
type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
	Type       Type
}

// NewKeyPair returns new KeyPair instance
func NewKeyPair(pub []byte, priv []byte, t Type) *KeyPair {
	return &KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
		Type:       t,
	}
}
