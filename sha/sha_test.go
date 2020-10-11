package sha

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	expectedHashInput  string = "Super Secret"
	expectedHashHex    string = "318a5aba09be4fe5d37aa231df523ee9c2e374dad62ce9db8461c5cb7eaf726f"
	expectedHashBase64 string = "MYpaugm+T+XTeqIx31I+6cLjdNrWLOnbhGHFy36vcm8"
)

var expectedHashBytes = []byte{0x31, 0x8a, 0x5a, 0xba, 0x9, 0xbe, 0x4f, 0xe5, 0xd3, 0x7a, 0xa2, 0x31, 0xdf, 0x52, 0x3e, 0xe9, 0xc2, 0xe3, 0x74, 0xda, 0xd6, 0x2c, 0xe9, 0xdb, 0x84, 0x61, 0xc5, 0xcb, 0x7e, 0xaf, 0x72, 0x6f}

func TestNewSha256(t *testing.T) {
	hash := NewSHA256([]byte(expectedHashInput))
	assert.NotNil(t, hash)
	assert.Equal(t, expectedHashBytes, hash.Value)
}

func TestRandomSha256(t *testing.T) {
	hash := RandomSHA256("")
	assert.NotNil(t, hash)
}
