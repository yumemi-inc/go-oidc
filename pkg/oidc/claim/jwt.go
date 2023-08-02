package claim

import (
	"encoding/json"

	"github.com/go-jose/go-jose/v3"

	"github.com/yumemi-inc/go-oidc/pkg/jwt"
)

func ClaimsFromJWT(jwt string, keychain jwt.PublicKeychain) (Claims, error) {
	object, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, err
	}

	id := object.Signatures[0].Header.KeyID
	key := keychain.PublicKey(id)
	if key == nil {
		return nil, ErrKeyNotFound
	}

	bytes, err := object.Verify(key.PublicKey())
	if err != nil {
		return nil, err
	}

	values := make(map[string]json.RawMessage)
	if err := json.Unmarshal(bytes, &values); err != nil {
		return nil, err
	}

	return UnmarshalAll(values)
}

func (c Claims) SignJWT(key jwt.PrivateKey, algorithm jose.SignatureAlgorithm) (string, error) {
	bytes, err := c.MarshalJSON()
	if err != nil {
		return "", err
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: algorithm,
			Key: jose.JSONWebKey{
				Key:       key.PrivateKey(),
				KeyID:     key.KeyID(),
				Algorithm: string(jose.ES256),
			},
		},
		nil,
	)
	if err != nil {
		return "", err
	}

	signature, err := signer.Sign(bytes)
	if err != nil {
		return "", err
	}

	return signature.CompactSerialize()
}
