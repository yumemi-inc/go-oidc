package jwt

type Key interface {
	KeyID() string
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
