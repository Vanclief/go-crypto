package eth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccountFixture(t *testing.T) {
	ethAccount, err := AccountFixture()
	assert.Nil(t, err)
	assert.Len(t, ethAccount.Address, 42)
}
