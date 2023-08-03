package keychain

import (
	"github.com/yumemi-inc/go-oidc/pkg/jwt"
)

type Keychain struct {
	Keypairs map[string]jwt.Keypair
}

func New() *Keychain {
	return &Keychain{
		Keypairs: make(map[string]jwt.Keypair),
	}
}

func (k *Keychain) Add(keypair jwt.Keypair) {
	k.Keypairs[keypair.KeyID()] = keypair
}

func (k *Keychain) Keypair(id string) jwt.Keypair {
	keypair, ok := k.Keypairs[id]
	if !ok {
		return nil
	}

	return keypair
}

func (k *Keychain) PrivateKey(id string) jwt.PrivateKey {
	return k.Keypair(id)
}

func (k *Keychain) PublicKey(id string) jwt.PublicKey {
	return k.Keypair(id)
}
