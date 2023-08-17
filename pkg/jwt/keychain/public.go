package keychain

import (
	"github.com/samber/lo"

	"github.com/yumemi-inc/go-oidc/pkg/jwt"
)

type PublicKeychain struct {
	encryptionKeys map[string]jwt.PublicEncryptionKey
	signingKeys    map[string]jwt.PublicSigningKey
}

func NewPublic() *PublicKeychain {
	return &PublicKeychain{
		encryptionKeys: make(map[string]jwt.PublicEncryptionKey),
		signingKeys:    make(map[string]jwt.PublicSigningKey),
	}
}

func (k *PublicKeychain) Add(key jwt.PublicKey) {
	switch key := key.(type) {
	case jwt.PublicEncryptionKey:
		k.encryptionKeys[key.KeyID()] = key

	case jwt.PublicSigningKey:
		k.signingKeys[key.KeyID()] = key

	default:
		panic("BUG: Unsupported public key type")
	}
}

func (k *PublicKeychain) PublicKeys() []jwt.PublicKey {
	keys := make([]jwt.PublicKey, 0, len(k.encryptionKeys)+len(k.signingKeys))

	for _, key := range k.encryptionKeys {
		keys = append(keys, key)
	}

	for _, key := range k.signingKeys {
		keys = append(keys, key)
	}

	return keys
}

func (k *PublicKeychain) PublicKey(id string) jwt.PublicKey {
	encryptionKey, ok := k.encryptionKeys[id]
	if ok {
		return encryptionKey
	}

	signingKey, ok := k.signingKeys[id]
	if ok {
		return signingKey
	}

	return nil
}

func (k *PublicKeychain) PublicEncryptionKeys() []jwt.PublicEncryptionKey {
	return lo.Values(k.encryptionKeys)
}

func (k *PublicKeychain) PublicEncryptionKey(id string) jwt.PublicEncryptionKey {
	key, ok := k.encryptionKeys[id]
	if !ok {
		return nil
	}

	return key
}

func (k *PublicKeychain) PublicSigningKeys() []jwt.PublicSigningKey {
	return lo.Values(k.signingKeys)
}

func (k *PublicKeychain) PublicSigningKey(id string) jwt.PublicSigningKey {
	key, ok := k.signingKeys[id]
	if !ok {
		return nil
	}

	return key
}
