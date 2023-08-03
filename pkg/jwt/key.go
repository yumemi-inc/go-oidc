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
	PublicKey(id string) PublicKey
}

type Keychain interface {
	PublicKeychain

	Keypair(id string) Keypair
	PrivateKey(id string) PrivateKey
}
