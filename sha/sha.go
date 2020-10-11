package sha

import (
	"time"

	"github.com/vanclief/go-crypto/hash"
	"golang.org/x/crypto/sha3"
)

// NewSHA256 returns a new SHA3-256 hash from a byte array
func NewSHA256(data []byte) *hash.Hash {
	sha256 := sha3.New256()
	sha256.Write([]byte(data))
	val := sha256.Sum(nil)

	return hash.New(val, hash.SHA3x256)
}

// RandomSHA256 returns a new random SHA3-256 hash from a string salt
func RandomSHA256(salt string) *hash.Hash {
	sha256 := sha3.New256()
	sha256.Write([]byte(salt + time.Now().String()))
	val := sha256.Sum(nil)

	return hash.New(val, hash.SHA3x256)
}
