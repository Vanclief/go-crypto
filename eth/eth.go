package eth

import (
	"github.com/vanclief/ez"
	"github.com/vanclief/go-crypto/ed25519"
	"github.com/vanclief/go-crypto/nacl"
	"github.com/vanclief/go-crypto/sha"
	"github.com/vanclief/go-crypto/utils"
)

// EthereumAccount defines the required data of an Ethereum Account
type EthereumAccount struct {
	Address    string
	PublicKey  []byte
	PrivateKey []byte
}

// RandomHexAddress generates a random hex that is a valid ethereum address
func RandomHexAddress() (string, error) {
	const op = "Eth.RandomHexAddress"

	keyPair, err := nacl.NewKeyPair()
	if err != nil {
		return "", ez.Wrap(op, err)
	}

	hex := utils.BytesToHex(keyPair.PublicKey)
	return hex[0:42], nil
}

// AccountFixture generates a new "valid" ethereum account
func AccountFixture() (*EthereumAccount, error) {
	const op = "Eth.NewAccount"

	keyPair, err := ed25519.NewKeyPair()
	if err != nil {
		return nil, ez.Wrap(op, err)
	}

	hash := sha.NewSHA256(keyPair.PublicKey)
	address := utils.BytesToHex(hash.Value)

	account := &EthereumAccount{
		Address:    address[:42],
		PublicKey:  keyPair.PublicKey,
		PrivateKey: keyPair.PrivateKey,
	}

	return account, nil
}
