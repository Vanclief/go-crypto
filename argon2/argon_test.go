package argon2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vanclief/ez"
	"github.com/vanclief/go-crypto/utils"
)

func TestArgon2KD(t *testing.T) {

	// Should be able to hash a password
	key, err := KDF("password123", "tester@gmail.com")
	assert.NotEqual(t, "", key)
	assert.Nil(t, err)
	expectedKey := utils.BytesToBase64(key.Value)
	assert.Equal(t, "ry86D23WlX277BAkXN6Em8Q9WV0hoiPr2LIIAAYmdlw", expectedKey)

	// Should fail to hash a without a password
	key, err = KDF("", "tester@gmail.com")
	assert.Nil(t, key)
	assert.NotNil(t, err)
	assert.Equal(t, ez.EINVALID, ez.ErrorCode(err))

	// Should fail to hash a without salt
	key, err = KDF("password123", "")
	assert.Nil(t, key)
	assert.NotNil(t, err)
	assert.Equal(t, ez.EINVALID, ez.ErrorCode(err))
}
