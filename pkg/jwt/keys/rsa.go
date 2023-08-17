package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"io"

	"github.com/go-jose/go-jose/v3"
)

type RSAPublicKey struct {
	id  string
	alg jose.SignatureAlgorithm
	enc jose.KeyAlgorithm
	key rsa.PublicKey
}

func (k RSAPublicKey) KeyID() string {
	return k.id
}

func (k RSAPublicKey) EncryptionKeyAlgorithm() jose.KeyAlgorithm {
	return jose.ECDH_ES
}

func (k RSAPublicKey) SigningAlgorithm() jose.SignatureAlgorithm {
	return k.alg
}

func (k RSAPublicKey) PublicKey() any {
	return &k.key
}

type RSAPrivateKey struct {
	id  string
	alg jose.SignatureAlgorithm
	enc jose.KeyAlgorithm
	key rsa.PrivateKey
}

func (k RSAPrivateKey) KeyID() string {
	return k.id
}

func (k RSAPrivateKey) EncryptionKeyAlgorithm() jose.KeyAlgorithm {
	return k.enc
}

func (k RSAPrivateKey) SigningAlgorithm() jose.SignatureAlgorithm {
	return k.alg
}

func (k RSAPrivateKey) PrivateKey() any {
	return &k.key
}

type RSAKeypair struct {
	RSAPublicKey
	RSAPrivateKey
}

func (k RSAKeypair) KeyID() string {
	return k.RSAPublicKey.KeyID()
}

func (k RSAKeypair) EncryptionKeyAlgorithm() jose.KeyAlgorithm {
	return k.RSAPublicKey.EncryptionKeyAlgorithm()
}

func (k RSAKeypair) SigningAlgorithm() jose.SignatureAlgorithm {
	return k.RSAPublicKey.SigningAlgorithm()
}

func RSAPublicKeyFrom(id string, key rsa.PublicKey, alg jose.SignatureAlgorithm, enc jose.KeyAlgorithm) *RSAPublicKey {
	return &RSAPublicKey{
		id:  id,
		alg: alg,
		enc: enc,
		key: key,
	}
}

func RSAPrivateKeyFrom(
	id string,
	key rsa.PrivateKey,
	alg jose.SignatureAlgorithm,
	enc jose.KeyAlgorithm,
) *RSAPrivateKey {
	return &RSAPrivateKey{
		id:  id,
		alg: alg,
		enc: enc,
		key: key,
	}
}

func RSAKeypairFrom(id string, key rsa.PrivateKey, alg jose.SignatureAlgorithm, enc jose.KeyAlgorithm) *RSAKeypair {
	return &RSAKeypair{
		RSAPublicKey:  *RSAPublicKeyFrom(id, key.PublicKey, alg, enc),
		RSAPrivateKey: *RSAPrivateKeyFrom(id, key, alg, enc),
	}
}

func GenerateRSAKeypairWith(
	alg jose.SignatureAlgorithm,
	enc jose.KeyAlgorithm,
	bits int,
	rand io.Reader,
) (*RSAKeypair, error) {
	keyIDBytes := make([]byte, 16)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return nil, err
	}

	keyID := base64.URLEncoding.EncodeToString(keyIDBytes)

	privateKey, err := rsa.GenerateKey(rand, bits)
	if err != nil {
		return nil, err
	}

	return RSAKeypairFrom(keyID, *privateKey, alg, enc), nil
}

func GenerateRSAKeypair(alg jose.SignatureAlgorithm, enc jose.KeyAlgorithm, bits int) (*RSAKeypair, error) {
	return GenerateRSAKeypairWith(alg, enc, bits, rand.Reader)
}
