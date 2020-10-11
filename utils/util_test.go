package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBytesToHex(t *testing.T) {
	b := []byte("This is a string")
	hex := BytesToHex(b)

	assert.NotNil(t, hex)
	assert.Equal(t, "0x54686973206973206120737472696e67", hex)
}

func TestHexToBytes(t *testing.T) {
	// Case 1: Should work
	hex := "0x54686973206973206120686578"
	b, err := HexToBytes(hex)

	assert.NotNil(t, b)
	assert.Nil(t, err)
	assert.Equal(t, "This is a hex", string(b))

	// Case 2: Should not panic if slice is shorter than 2
	hex = "1"
	b, err = HexToBytes(hex)

	assert.Nil(t, b)
	assert.NotNil(t, err)
}

func TestBytesToBase64(t *testing.T) {
	b := []byte("This is a string")
	base := BytesToBase64(b)

	assert.NotNil(t, base)
	assert.Equal(t, "VGhpcyBpcyBhIHN0cmluZw", base)
}

func TestBase64ToBytes(t *testing.T) {
	base64 := "VGhpcyBpcyBhIGJhc2U2NA"
	b, err := Base64ToBytes(base64)

	assert.NotNil(t, b)
	assert.Nil(t, err)
	assert.Equal(t, "This is a base64", string(b))
}
