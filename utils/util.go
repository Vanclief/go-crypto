package utils

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

// BytesToHex encodes an array of bytes to a Hex string
func BytesToHex(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

// HexToBytes decodes a hex string to an array of bytes
func HexToBytes(s string) ([]byte, error) {
	if len(s) < 2 {
		return nil, errors.New("Invalid format")
	} else if s[:2] != "0x" {
		return nil, errors.New("Hex is missing 0x notation")
	}
	return hex.DecodeString(s[2:])
}

// BytesToBase64 encodes an array of bytes to a Base64 string
func BytesToBase64(b []byte) string {
	return base64.RawStdEncoding.EncodeToString(b)
}

// Base64ToBytes decodes a Base64 string to an array of bytes
func Base64ToBytes(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawStdEncoding.DecodeString(s)
}

// GenerateRandomBytes returns a set of securely generated random bytes
func GenerateRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString returns a securely generated random string
func GenerateRandomString(size int) (string, error) {
	const characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	str := make([]byte, size)
	for i := 0; i < size; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(characters))))
		if err != nil {
			return "", err
		}
		str[i] = characters[num.Int64()]
	}

	return string(str), nil
}

// GenerateRandomNumber returns a securely generated random string of numbers
func GenerateRandomNumber(size int) (string, error) {
	const characters = "0123456789"

	str := make([]byte, size)
	for i := 0; i < size; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(characters))))
		if err != nil {
			return "", err
		}
		str[i] = characters[num.Int64()]
	}

	return string(str), nil
}
