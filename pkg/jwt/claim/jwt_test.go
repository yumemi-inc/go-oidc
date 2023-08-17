package claim

import (
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yumemi-inc/go-oidc/pkg/jwt/keychain"
	"github.com/yumemi-inc/go-oidc/pkg/jwt/keys"
)

func TestClaims_SignJWT_ClaimsFromJWT(t *testing.T) {
	keypair, err := keys.GenerateEd25519Keypair()
	require.NoError(t, err)

	chain := keychain.New()
	chain.Add(keypair)

	claims := NewClaims().
		With(Iss("https://id.example.com/")).
		With(Sub("user1")).
		With(Aud([]string{"client1"}))

	jwtString, err := claims.SignJWT(keypair)
	require.NoError(t, err)

	assert.Equal(t, 2, strings.Count(jwtString, "."))
	assert.True(t, strings.HasPrefix(jwtString, "eyJ"))

	claims, err = ClaimsFromJWT(jwtString, chain)
	require.NoError(t, err)

	require.Equal(t, Iss("https://id.example.com/"), claims["iss"].(Iss))
	require.Equal(t, Aud([]string{"client1"}), claims["aud"].(Aud))
	require.Equal(t, Sub("user1"), claims["sub"].(Sub))
}

func TestClaims_EncryptJWT_ClaimsFromJWT(t *testing.T) {
	keypair, err := keys.GenerateECDSAKeypair(jose.ES512)
	require.NoError(t, err)

	chain := keychain.New()
	chain.Add(keypair)

	claims := NewClaims().
		With(Iss("https://id.example.com/")).
		With(Sub("user1")).
		With(Aud([]string{"client1"}))

	jwtString, err := claims.EncryptJWT(keypair, jose.A256CBC_HS512)
	require.NoError(t, err)

	assert.Equal(t, 4, strings.Count(jwtString, "."))
	assert.True(t, strings.HasPrefix(jwtString, "eyJ"))

	claims, err = ClaimsFromJWT(jwtString, chain)
	require.NoError(t, err)

	require.Equal(t, Iss("https://id.example.com/"), claims["iss"].(Iss))
	require.Equal(t, Aud([]string{"client1"}), claims["aud"].(Aud))
	require.Equal(t, Sub("user1"), claims["sub"].(Sub))
}
