package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/go-jose/go-jose/v3"

	"github.com/yumemi-inc/go-oidc/pkg/jwt"
)

type ECDSAPublicKey struct {
	id  string
	alg jose.SignatureAlgorithm
	use jwt.Use
	key ecdsa.PublicKey
}

func (k ECDSAPublicKey) KeyID() string {
	return k.id
}

func (k ECDSAPublicKey) Algorithm() jose.SignatureAlgorithm {
	return k.alg
}

func (k ECDSAPublicKey) Use() jwt.Use {
	return k.use
}

func (k ECDSAPublicKey) PublicKey() any {
	return &k.key
}

type ECDSAPrivateKey struct {
	id  string
	alg jose.SignatureAlgorithm
	use jwt.Use
	key ecdsa.PrivateKey
}

func (k ECDSAPrivateKey) KeyID() string {
	return k.id
}

func (k ECDSAPrivateKey) Algorithm() jose.SignatureAlgorithm {
	return k.alg
}

func (k ECDSAPrivateKey) Use() jwt.Use {
	return k.use
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

func (k ECDSAKeypair) Algorithm() jose.SignatureAlgorithm {
	return k.ECDSAPublicKey.Algorithm()
}

func (k ECDSAKeypair) Use() jwt.Use {
	return k.ECDSAPublicKey.Use()
}

func GenerateECDSAKeypairWith(
	alg jose.SignatureAlgorithm,
	use jwt.Use,
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
			use: use,
			key: privateKey.PublicKey,
		},
		ECDSAPrivateKey: ECDSAPrivateKey{
			id:  keyID,
			alg: alg,
			use: use,
			key: *privateKey,
		},
	}, nil
}

func GenerateECDSAKeypair(alg jose.SignatureAlgorithm, use jwt.Use) (*ECDSAKeypair, error) {
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

	return GenerateECDSAKeypairWith(alg, use, curve, rand.Reader)
}
