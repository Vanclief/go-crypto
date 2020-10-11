package hash

const (
	// SHA3x256 is a type of Hash that utilizes SHA3 with 256 bits
	SHA3x256 Type = "sha3_256"
)

// Type is the type of function and bits of the hash
type Type string

// Hash represents the result of a hashing function
type Hash struct {
	Value []byte
	Type  Type
}

// New returns a new Hash
func New(value []byte, t Type) *Hash {
	return &Hash{value, t}
}
