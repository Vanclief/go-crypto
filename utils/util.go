package utils

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
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
