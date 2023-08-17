package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/go-jose/go-jose/v3"
)

type Ed25519PublicKey struct {
	id  string
	key ed25519.PublicKey
}

func (k Ed25519PublicKey) KeyID() string {
	return k.id
}

func (k Ed25519PublicKey) SigningAlgorithm() jose.SignatureAlgorithm {
	return jose.EdDSA
}

func (k Ed25519PublicKey) PublicKey() any {
	return k.key
}

type Ed25519PrivateKey struct {
	id  string
	key ed25519.PrivateKey
}

func (k Ed25519PrivateKey) KeyID() string {
	return k.id
}

func (k Ed25519PrivateKey) SigningAlgorithm() jose.SignatureAlgorithm {
	return jose.EdDSA
}

func (k Ed25519PrivateKey) PrivateKey() any {
	return k.key
}

type Ed25519Keypair struct {
	Ed25519PublicKey
	Ed25519PrivateKey
}

func (k Ed25519Keypair) KeyID() string {
	return k.Ed25519PublicKey.KeyID()
}

func (k Ed25519Keypair) SigningAlgorithm() jose.SignatureAlgorithm {
	return k.Ed25519PublicKey.SigningAlgorithm()
}

func GenerateEd25519KeypairWith(rand io.Reader) (*Ed25519Keypair, error) {
	keyIDBytes := make([]byte, 16)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return nil, err
	}

	keyID := base64.URLEncoding.EncodeToString(keyIDBytes)

	publicKey, privateKey, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	return &Ed25519Keypair{
		Ed25519PublicKey: Ed25519PublicKey{
			id:  keyID,
			key: publicKey,
		},
		Ed25519PrivateKey: Ed25519PrivateKey{
			id:  keyID,
			key: privateKey,
		},
	}, nil
}

func GenerateEd25519Keypair() (*Ed25519Keypair, error) {
	return GenerateEd25519KeypairWith(rand.Reader)
}
