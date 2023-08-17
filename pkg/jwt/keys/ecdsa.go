package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/go-jose/go-jose/v3"
)

type ECDSAPublicKey struct {
	id  string
	alg jose.SignatureAlgorithm
	key ecdsa.PublicKey
}

func (k ECDSAPublicKey) KeyID() string {
	return k.id
}

func (k ECDSAPublicKey) EncryptionKeyAlgorithm() jose.KeyAlgorithm {
	return jose.ECDH_ES
}

func (k ECDSAPublicKey) SigningAlgorithm() jose.SignatureAlgorithm {
	return k.alg
}

func (k ECDSAPublicKey) PublicKey() any {
	return &k.key
}

type ECDSAPrivateKey struct {
	id  string
	alg jose.SignatureAlgorithm
	key ecdsa.PrivateKey
}

func (k ECDSAPrivateKey) KeyID() string {
	return k.id
}

func (k ECDSAPrivateKey) EncryptionKeyAlgorithm() jose.KeyAlgorithm {
	return jose.ECDH_ES
}

func (k ECDSAPrivateKey) SigningAlgorithm() jose.SignatureAlgorithm {
	return k.alg
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

func (k ECDSAKeypair) EncryptionKeyAlgorithm() jose.KeyAlgorithm {
	return k.ECDSAPublicKey.EncryptionKeyAlgorithm()
}

func (k ECDSAKeypair) SigningAlgorithm() jose.SignatureAlgorithm {
	return k.ECDSAPublicKey.SigningAlgorithm()
}

func GenerateECDSAKeypairWith(
	alg jose.SignatureAlgorithm,
	curve elliptic.Curve,
	rand io.Reader,
) (*ECDSAKeypair, error) {
	keyIDBytes := make([]byte, 16)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return nil, err
	}

	keyID := base64.URLEncoding.EncodeToString(keyIDBytes)

	privateKey, err := ecdsa.GenerateKey(curve, rand)
	if err != nil {
		return nil, err
	}

	return &ECDSAKeypair{
		ECDSAPublicKey: ECDSAPublicKey{
			id:  keyID,
			alg: alg,
			key: privateKey.PublicKey,
		},
		ECDSAPrivateKey: ECDSAPrivateKey{
			id:  keyID,
			alg: alg,
			key: *privateKey,
		},
	}, nil
}

func GenerateECDSAKeypair(alg jose.SignatureAlgorithm) (*ECDSAKeypair, error) {
	var curve elliptic.Curve
	switch alg {
	case jose.ES256:
		curve = elliptic.P256()

	case jose.ES384:
		curve = elliptic.P384()

	case jose.ES512:
		curve = elliptic.P521()

	default:
		return nil, ErrUnsupportedAlgorithm
	}

	return GenerateECDSAKeypairWith(alg, curve, rand.Reader)
}
