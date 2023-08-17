package keychain

import (
	"github.com/samber/lo"

	"github.com/yumemi-inc/go-oidc/pkg/jwt"
)

type Keychain struct {
	encryptionKeypairs map[string]jwt.EncryptionKeypair
	signingKeypairs    map[string]jwt.SigningKeypair
}

func New() *Keychain {
	return &Keychain{
		encryptionKeypairs: make(map[string]jwt.EncryptionKeypair),
		signingKeypairs:    make(map[string]jwt.SigningKeypair),
	}
}

func (k *Keychain) Add(keypair jwt.Keypair) {
	switch keypair := keypair.(type) {
	case jwt.EncryptionKeypair:
		k.encryptionKeypairs[keypair.KeyID()] = keypair

	case jwt.SigningKeypair:
		k.signingKeypairs[keypair.KeyID()] = keypair

	default:
		panic("BUG: Unsupported keypair type")
	}
}

func (k *Keychain) Keypairs() []jwt.Keypair {
	keypairs := make([]jwt.Keypair, 0, len(k.encryptionKeypairs)+len(k.signingKeypairs))

	for _, key := range k.encryptionKeypairs {
		keypairs = append(keypairs, key)
	}

	for _, key := range k.signingKeypairs {
		keypairs = append(keypairs, key)
	}

	return keypairs
}

func (k *Keychain) Keypair(id string) jwt.Keypair {
	encryptionKeypair, ok := k.encryptionKeypairs[id]
	if ok {
		return encryptionKeypair
	}

	signingKeypair, ok := k.signingKeypairs[id]
	if ok {
		return signingKeypair
	}

	return nil
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

func (k *Keychain) EncryptionKeypairs() []jwt.EncryptionKeypair {
	return lo.Values(k.encryptionKeypairs)
}

func (k *Keychain) EncryptionKeypair(id string) jwt.EncryptionKeypair {
	keypair, ok := k.encryptionKeypairs[id]
	if !ok {
		return nil
	}

	return keypair
}

func (k *Keychain) PublicEncryptionKeys() []jwt.PublicEncryptionKey {
	return lo.Map(
		k.EncryptionKeypairs(),
		func(item jwt.EncryptionKeypair, _ int) jwt.PublicEncryptionKey {
			return item
		},
	)
}

func (k *Keychain) PublicEncryptionKey(id string) jwt.PublicEncryptionKey {
	return k.EncryptionKeypair(id)
}

func (k *Keychain) PrivateEncryptionKeys() []jwt.PrivateEncryptionKey {
	return lo.Map(
		k.EncryptionKeypairs(),
		func(item jwt.EncryptionKeypair, _ int) jwt.PrivateEncryptionKey {
			return item
		},
	)
}

func (k *Keychain) PrivateEncryptionKey(id string) jwt.PrivateEncryptionKey {
	return k.EncryptionKeypair(id)
}

func (k *Keychain) SigningKeypairs() []jwt.SigningKeypair {
	return lo.Values(k.signingKeypairs)
}

func (k *Keychain) SigningKeypair(id string) jwt.SigningKeypair {
	keypair, ok := k.signingKeypairs[id]
	if !ok {
		return nil
	}

	return keypair
}

func (k *Keychain) PublicSigningKeys() []jwt.PublicSigningKey {
	return lo.Map(
		k.SigningKeypairs(),
		func(item jwt.SigningKeypair, _ int) jwt.PublicSigningKey {
			return item
		},
	)
}

func (k *Keychain) PublicSigningKey(id string) jwt.PublicSigningKey {
	return k.SigningKeypair(id)
}

func (k *Keychain) PrivateSigningKeys() []jwt.PrivateSigningKey {
	return lo.Map(
		k.SigningKeypairs(),
		func(item jwt.SigningKeypair, _ int) jwt.PrivateSigningKey {
			return item
		},
	)
}

func (k *Keychain) PrivateSigningKey(id string) jwt.PrivateSigningKey {
	return k.SigningKeypair(id)
}
