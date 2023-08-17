package authz

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yumemi-inc/go-oidc/pkg/jwt/keychain"
	"github.com/yumemi-inc/go-oidc/pkg/jwt/keys"
	"github.com/yumemi-inc/go-oidc/pkg/oidc"
)

func TestRequest_ExtractSignedRequestJWT(t *testing.T) {
	nBytes, err := base64.RawURLEncoding.DecodeString(
		strings.NewReplacer("\t", "", "\n", "").Replace(
			`
				y9Lqv4fCp6Ei-u2-ZCKq83YvbFEk6JMs_pSj76eMkddWRuWX2aBKGHAtKlE5P
				7_vn__PCKZWePt3vGkB6ePgzAFu08NmKemwE5bQI0e6kIChtt_6KzT5OaaXDF
				I6qCLJmk51Cc4VYFaxgqevMncYrzaW_50mZ1yGSFIQzLYP8bijAHGVjdEFgZa
				ZEN9lsn_GdWLaJpHrB3ROlS50E45wxrlg9xMncVb8qDPuXZarvghLL0HzOuYR
				adBJVoWZowDNTpKpk2RklZ7QaBO7XDv3uR7s_sf2g-bAjSYxYUGsqkNA9b3xV
				W53am_UZZ3tZbFTIh557JICWKHlWj5uzeJXaw
			`,
		),
	)
	require.NoError(t, err)

	n := big.Int{}
	n.SetBytes(nBytes)

	chain := keychain.NewPublic()
	chain.Add(
		keys.RSAPublicKeyFrom(
			"k2bdc",
			rsa.PublicKey{
				N: &n,
				E: 65537, // AQAB
			},
			jose.RS256,
			jose.RSA_OAEP_256,
		),
	)

	uri := `
		/authorize
			?response_type=code%20id_token
			&client_id=s6BhdRkqt3
			&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
			&scope=openid
			&state=af0ifjsldkj
			&nonce=n-0S6_WzA2Mj
			&request=eyJhbGciOiJSUzI1NiIsImtpZCI6ImsyYmRjIn0.ew0KICJpc3MiOiA
			iczZCaGRSa3F0MyIsDQogImF1ZCI6ICJodHRwczovL3NlcnZlci5leGFtcGxlLmN
			vbSIsDQogInJlc3BvbnNlX3R5cGUiOiAiY29kZSBpZF90b2tlbiIsDQogImNsaWV
			udF9pZCI6ICJzNkJoZFJrcXQzIiwNCiAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8
			vY2xpZW50LmV4YW1wbGUub3JnL2NiIiwNCiAic2NvcGUiOiAib3BlbmlkIiwNCiA
			ic3RhdGUiOiAiYWYwaWZqc2xka2oiLA0KICJub25jZSI6ICJuLTBTNl9XekEyTWo
			iLA0KICJtYXhfYWdlIjogODY0MDAsDQogImNsYWltcyI6IA0KICB7DQogICAidXN
			lcmluZm8iOiANCiAgICB7DQogICAgICJnaXZlbl9uYW1lIjogeyJlc3NlbnRpYWw
			iOiB0cnVlfSwNCiAgICAgIm5pY2tuYW1lIjogbnVsbCwNCiAgICAgImVtYWlsIjo
			geyJlc3NlbnRpYWwiOiB0cnVlfSwNCiAgICAgImVtYWlsX3ZlcmlmaWVkIjogeyJ
			lc3NlbnRpYWwiOiB0cnVlfSwNCiAgICAgInBpY3R1cmUiOiBudWxsDQogICAgfSw
			NCiAgICJpZF90b2tlbiI6IA0KICAgIHsNCiAgICAgImdlbmRlciI6IG51bGwsDQo
			gICAgICJiaXJ0aGRhdGUiOiB7ImVzc2VudGlhbCI6IHRydWV9LA0KICAgICAiYWN
			yIjogeyJ2YWx1ZXMiOiBbInVybjptYWNlOmluY29tbW9uOmlhcDpzaWx2ZXIiXX0
			NCiAgICB9DQogIH0NCn0.nwwnNsk1-ZkbmnvsF6zTHm8CHERFMGQPhos-EJcaH4H
			h-sMgk8ePrGhw_trPYs8KQxsn6R9Emo_wHwajyFKzuMXZFSZ3p6Mb8dkxtVyjoy2
			GIzvuJT_u7PkY2t8QU9hjBcHs68PkgjDVTrG1uRTx0GxFbuPbj96tVuj11pTnmFC
			UR6IEOXKYr7iGOCRB3btfJhM0_AKQUfqKnRlrRscc8Kol-cSLWoYE9l5QqholImz
			jT_cMnNIznW9E7CDyWXTsO70xnB4SkG6pXfLSjLLlxmPGiyon_-Te111V8uE83Il
			zCYIb_NMXvtTIVc1jpspnTSD7xMbpL-2QgwUsAlMGzw
	`

	uri = strings.NewReplacer("\t", "", "\n", "").Replace(uri)
	httpRequest := httptest.NewRequest("GET", uri, nil)

	request, err := ReadRequest(httpRequest)
	require.NoError(t, err)

	err = request.ExtractSignedRequestJWT(chain)
	require.NoError(t, err)

	assert.Equal(t, oidc.ResponseTypeCodeIDToken, request.ResponseType)
	assert.Equal(t, "s6BhdRkqt3", request.ClientID)
	assert.Equal(t, "https://client.example.org/cb", *request.RedirectURI)
	assert.Equal(t, []string{oidc.ScopeOpenID}, request.Scopes())
	assert.Equal(t, "af0ifjsldkj", *request.State)
	assert.Equal(t, "n-0S6_WzA2Mj", *request.Nonce)
	assert.Equal(t, int64(86400), *request.MaxAge)
	assert.True(t, *request.Claims.Userinfo["given_name"].Essential)
	assert.Nil(t, request.Claims.Userinfo["nickname"])
	assert.True(t, *request.Claims.Userinfo["email"].Essential)
	assert.True(t, *request.Claims.Userinfo["email_verified"].Essential)
	assert.Nil(t, request.Claims.Userinfo["picture"])
	assert.Nil(t, request.Claims.IDToken["gender"])
	assert.True(t, *request.Claims.IDToken["birthdate"].Essential)
	assert.Equal(t, "urn:mace:incommon:iap:silver", request.Claims.IDToken["acr"].Values[0])
}
