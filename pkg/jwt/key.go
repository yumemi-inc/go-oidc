package jwt

import (
	"github.com/go-jose/go-jose/v3"
	"github.com/samber/lo"
)

type Use string

const (
	UseSignature  = "sig"
	UseEncryption = "enc"
)

type Key interface {
	KeyID() string
	Algorithm() jose.SignatureAlgorithm
	Use() Use
}

type PublicKey interface {
	Key

	PublicKey() any
}

type PrivateKey interface {
	Key

	PrivateKey() any
}

type Keypair interface {
	PublicKey
	PrivateKey
}

type PublicKeychain interface {
	PublicKeys() []PublicKey
	PublicKey(id string) PublicKey
}

type Keychain interface {
	PublicKeychain

	Keypairs() []Keypair
	Keypair(id string) Keypair
	PrivateKeys() []PrivateKey
	PrivateKey(id string) PrivateKey
}

func JWKFromPublicKey(key PublicKey) jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       key.PublicKey(),
		KeyID:     key.KeyID(),
		Algorithm: string(key.Algorithm()),
		Use:       string(key.Use()),
	}
}

func JWKFromPrivateKey(key PrivateKey) jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       key.PrivateKey(),
		KeyID:     key.KeyID(),
		Algorithm: string(key.Algorithm()),
		Use:       string(key.Use()),
	}
}

func JWKSFromPublicKeychain(keychain PublicKeychain) jose.JSONWebKeySet {
	return jose.JSONWebKeySet{
		Keys: lo.Map(
			keychain.PublicKeys(),
			func(item PublicKey, _ int) jose.JSONWebKey {
				return jose.JSONWebKey{
					Key:       item.PublicKey(),
					KeyID:     item.KeyID(),
					Algorithm: string(item.Algorithm()),
					Use:       string(item.Use()),
				}
			},
		),
	}
}
