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
	if key, ok := key.(jwt.PublicEncryptionKey); ok {
		k.encryptionKeys[key.KeyID()] = key
	}

	if key, ok := key.(jwt.PublicSigningKey); ok {
		k.signingKeys[key.KeyID()] = key
	}
}

func (k *PublicKeychain) PublicKeys() []jwt.PublicKey {
	keys := make(map[string]jwt.PublicKey)

	for id, key := range k.encryptionKeys {
		keys[id] = key
	}

	for id, key := range k.signingKeys {
		keys[id] = key
	}

	return lo.Values(keys)
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
