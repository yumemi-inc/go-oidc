package keychain

import (
	"github.com/samber/lo"

	"github.com/yumemi-inc/go-oidc/pkg/jwt"
)

type Keychain struct {
	keypairs map[string]jwt.Keypair
}

func New() *Keychain {
	return &Keychain{
		keypairs: make(map[string]jwt.Keypair),
	}
}

func (k *Keychain) Add(keypair jwt.Keypair) {
	k.keypairs[keypair.KeyID()] = keypair
}

func (k *Keychain) Keypairs() []jwt.Keypair {
	return lo.Values(k.keypairs)
}

func (k *Keychain) Keypair(id string) jwt.Keypair {
	keypair, ok := k.keypairs[id]
	if !ok {
		return nil
	}

	return keypair
}

func (k *Keychain) PrivateKeys() []jwt.PrivateKey {
	return lo.Map(
		k.Keypairs(),
		func(item jwt.Keypair, _ int) jwt.PrivateKey {
			return item
		},
	)
}

func (k *Keychain) PrivateKey(id string) jwt.PrivateKey {
	return k.Keypair(id)
}

func (k *Keychain) PublicKeys() []jwt.PublicKey {
	return lo.Map(
		k.Keypairs(),
		func(item jwt.Keypair, _ int) jwt.PublicKey {
			return item
		},
	)
}

func (k *Keychain) PublicKey(id string) jwt.PublicKey {
	return k.Keypair(id)
}
