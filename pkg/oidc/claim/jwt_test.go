package claim

import (
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yumemi-inc/go-oidc/pkg/jwt"
	"github.com/yumemi-inc/go-oidc/pkg/jwt/keys"
)

type keychain struct {
	publicKeys map[string]jwt.PublicKey
}

func newKeychain() keychain {
	return keychain{
		publicKeys: make(map[string]jwt.PublicKey),
	}
}

func (k keychain) Add(key jwt.PublicKey) {
	k.publicKeys[key.KeyID()] = key
}

func (k keychain) PublicKey(id string) jwt.PublicKey {
	return k.publicKeys[id]
}

func TestClaims_SignJWT_ClaimsFromJWT(t *testing.T) {
	keypair, err := keys.GenerateECDSAKeypair()
	require.NoError(t, err)

	keychain := newKeychain()
	keychain.Add(keypair)

	claims := NewClaims().
		With(lo.Must(IssFromStr("https://id.example.com/"))).
		With(lo.Must(NewSub("user1"))).
		With(NewAud([]string{"client1"}))

	jwtString, err := claims.SignJWT(keypair, jose.ES256)
	require.NoError(t, err)

	assert.Equal(t, 2, strings.Count(jwtString, "."))
	assert.True(t, strings.HasPrefix(jwtString, "eyJ"))

	claims, err = ClaimsFromJWT(jwtString, keychain)
	require.NoError(t, err)

	iss := url.URL(claims["iss"].(Iss))
	require.Equal(t, "https://id.example.com/", iss.String())
	require.Equal(t, Aud([]string{"client1"}), claims["aud"].(Aud))
	require.Equal(t, Sub("user1"), claims["sub"].(Sub))
}
