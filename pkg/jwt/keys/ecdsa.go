package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
)

type ECDSAPublicKey struct {
	id  string
	key ecdsa.PublicKey
}

func (k ECDSAPublicKey) KeyID() string {
	return k.id
}

func (k ECDSAPublicKey) PublicKey() any {
	return &k.key
}

type ECDSAPrivateKey struct {
	id  string
	key ecdsa.PrivateKey
}

func (k ECDSAPrivateKey) KeyID() string {
	return k.id
}

func (k ECDSAPrivateKey) PrivateKey() any {
	return &k.key
}

type ECDSAKeypair struct {
	ECDSAPublicKey
	ECDSAPrivateKey
}

func (k ECDSAKeypair) KeyID() string {
	return k.ECDSAPublicKey.KeyID()
}

func GenerateECDSAKeypair() (*ECDSAKeypair, error) {
	keyIDBytes := make([]byte, 16)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return nil, err
	}

	keyID := base64.URLEncoding.EncodeToString(keyIDBytes)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECDSAKeypair{
		ECDSAPublicKey: ECDSAPublicKey{
			id:  keyID,
			key: privateKey.PublicKey,
		},
		ECDSAPrivateKey: ECDSAPrivateKey{
			id:  keyID,
			key: *privateKey,
		},
	}, nil
}
