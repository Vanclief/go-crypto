package totp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"strconv"
	"strings"
	"time"

	"github.com/vanclief/ez"
)

// HOTPSecretFromString returns a HOTP secret as an array of bytes from a
// string
func HOTPSecretFromString(secret string) ([]byte, error) {
	const op = "totp.HOTPSecretFromString"
	if len(secret) != 16 {
		return nil, ez.New(op, ez.EINVALID, "Secret must be 16 characters long", nil)
	}

	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return nil, ez.Wrap(op, err)
	}

	return key, nil
}

// GenerateHOTP computes the HOTP value of a secret and an interval
// acording to RFC4226
func GenerateHOTP(secret []byte, interval int64) (string, error) {
	const op = "totp.GenerateHOTP"

	// Create array of 8 bits and seed it with interval
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(interval))

	// Sign the value using HMAC-SHA1
	hash := hmac.New(sha1.New, secret)
	hash.Write(b)
	hashSum := hash.Sum(nil)

	// Use the half of the last byte (nibble) to choose the index from
	// where to start for selecting a subset of the generated hash
	subset := (hashSum[19] & 15)

	var header uint32

	// Get 32 bit chunk from hash starting at with the subset
	r := bytes.NewReader(hashSum[subset : subset+4])
	err := binary.Read(r, binary.BigEndian, &header)
	if err != nil {
		return "", ez.Wrap(op, err)
	}

	// Ignore the most significant bits
	h12 := (int(header) & 0x7fffffff) % 1000000

	// Convert to string
	otp := strconv.Itoa(int(h12))

	return otp, nil
}

// GenerateTOTP uses current Unix time with a 30 second period
// as the counter for GenerateHOTP
func GenerateTOTP(secret []byte, window int64) (string, error) {
	const op = "totp.GenerateTOTP"

	interval := time.Now().Unix() / 30
	totp, err := GenerateHOTP(secret, interval+window)
	if err != nil {
		return "", ez.Wrap(op, err)
	}

	return totp, nil
}

// VerifyTOTP checks the validity of a token in a +-1 window period
func VerifyTOTP(token string, secret []byte) error {
	const op = "totp.VerifyTOTP"

	for i := -1; i < 2; i++ {
		totp, err := GenerateTOTP(secret, int64(i))
		if err != nil {
			return err
		}

		if totp == token {
			return nil
		}
	}

	return ez.New(op, ez.EINVALID, "Token does not match the generated TOTP", nil)
}
