package totp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vanclief/ez"
)

func TestHOTPSecretFromString(t *testing.T) {

	// Case 1: Should work with a valid secret
	secret, err := HOTPSecretFromString("CHICKENISCHICKEN")
	assert.NotNil(t, secret)
	assert.Nil(t, err)

	// Case 2: Should work with numbers
	secret, err = HOTPSecretFromString("ONXW2ZJAMRQXIYJA")
	assert.NotNil(t, secret)
	assert.Nil(t, err)

	// Case 2: Should NOT work with an invalid secret
	secret, err = HOTPSecretFromString("CHICKEN")
	assert.Nil(t, secret)
	assert.NotNil(t, err)
	assert.Equal(t, ez.EINVALID, ez.ErrorCode(err))
}

func TestGenerateHOTP(t *testing.T) {
	var secret = []byte("CHICKENISCHICKEN")

	// Case 1: Should work
	hotp, err := GenerateHOTP(secret, 1)
	assert.Nil(t, err)
	assert.Equal(t, hotp, "550360")
}

func TestGenerateTOTP(t *testing.T) {
	secret, _ := HOTPSecretFromString("CHICKENISCHICKEN")

	// Case 1: Should work
	totp, err := GenerateTOTP(secret, 0)
	assert.Nil(t, err)
	assert.Len(t, totp, 6)
}

func TestVerifyTOTP(t *testing.T) {
	secret, _ := HOTPSecretFromString("CHICKENISCHICKEN")
	prevToken, _ := GenerateTOTP(secret, -1)
	token, _ := GenerateTOTP(secret, 0)
	nextToken, _ := GenerateTOTP(secret, 1)

	// Case 1: Should work with a previously valid code
	err := VerifyTOTP(prevToken, secret)
	assert.Nil(t, err)

	// Case 2: Should work with the currently valid code
	err = VerifyTOTP(token, secret)
	assert.Nil(t, err)

	// Case 3: Should work with the next token
	err = VerifyTOTP(nextToken, secret)
	assert.Nil(t, err)

	// Case 4: S
	err = VerifyTOTP("000000", secret)
	assert.NotNil(t, err)
	assert.Equal(t, ez.EINVALID, ez.ErrorCode(err))
}
