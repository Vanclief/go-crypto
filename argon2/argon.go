package argon2

import (
	"github.com/vanclief/ez"
	"github.com/vanclief/go-crypto/keys"
	"golang.org/x/crypto/argon2"
)

const (
	iterations  uint32 = 3
	memory      uint32 = 64 * 1024
	parallelism uint8  = 2
	keyLength   uint32 = 32
)

// KDF will use Argon2 to derivate a key from a string secret and a string salt
func KDF(secret string, salt string) (*keys.Key, error) {
	const op = "Argon2.KDF"
	if secret == "" {
		return nil, ez.New(op, ez.EINVALID, "Secret can not be empty", nil)
	} else if salt == "" {
		return nil, ez.New(op, ez.EINVALID, "Salt can not be empty", nil)
	}

	key := argon2.IDKey([]byte(secret), []byte(salt), iterations, memory, parallelism, keyLength)

	return keys.New(key, keys.Argon2), nil
}
