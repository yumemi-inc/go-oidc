package authz

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
)

type TestClient struct{}

func (c *TestClient) GetID() string {
	return "test_client"
}

func (c *TestClient) GetRedirectURIs() []string {
	return []string{
		"https://foo.example.com/callback",
	}
}

func (c *TestClient) Authenticate(_ context.Context, secret string) error {
	if secret != "test_client_secret" {
		return oauth2.ErrInvalidClientCredentials
	}

	return nil
}

func TestRequest_ValidateWithOptions(t *testing.T) {
	client := &TestClient{}

	// Minimum
	request := Request{
		ResponseType: ResponseTypeCode,
		ClientID:     "test_client",
		RedirectURI:  lo.ToPtr("https://foo.example.com/callback"),
	}
	require.NoError(t, request.ValidateWithOptions(client, RequestValidateOptions{PKCEMode: PKCEModeDenied}))

	codeVerifier := make([]byte, 64)
	lo.Must(rand.Read(codeVerifier))

	// With PKCE
	request = Request{
		ResponseType:        ResponseTypeCode,
		ClientID:            "test_client",
		RedirectURI:         lo.ToPtr("https://foo.example.com/callback"),
		CodeChallenge:       lo.ToPtr(base64.URLEncoding.EncodeToString(codeVerifier)),
		CodeChallengeMethod: lo.ToPtr(CodeChallengeMethodS256),
	}
	require.NoError(t, request.ValidateWithOptions(client, RequestValidateOptions{PKCEMode: PKCEModeRequiredStrict}))

	// Client ID mismatch
	request = Request{
		ResponseType: ResponseTypeCode,
		ClientID:     "invalid_client",
		RedirectURI:  lo.ToPtr("https://foo.example.com/callback"),
	}
	require.Equal(t, ErrClientIDMismatch, request.Validate(client))

	// Invalid redirect URI
	request = Request{
		ResponseType: ResponseTypeCode,
		ClientID:     "test_client",
		RedirectURI:  lo.ToPtr("https://foo.example.com/"),
	}
	require.Equal(t, ErrInvalidRedirectURI, request.Validate(client))

	// Invalid scope format
	request = Request{
		ResponseType: ResponseTypeCode,
		ClientID:     "test_client",
		RedirectURI:  lo.ToPtr("https://foo.example.com/callback"),
		Scope:        lo.ToPtr("スコープ"),
	}
	require.Equal(t, ErrInvalidScopeFormat, request.Validate(client))

	// PKCE required
	request = Request{
		ResponseType: ResponseTypeCode,
		ClientID:     "test_client",
		RedirectURI:  lo.ToPtr("https://foo.example.com/callback"),
	}
	require.Equal(
		t, ErrPKCERequired,
		request.ValidateWithOptions(client, RequestValidateOptions{PKCEMode: PKCEModeRequired}),
	)

	// PKCE denied
	request = Request{
		ResponseType:  ResponseTypeCode,
		ClientID:      "test_client",
		RedirectURI:   lo.ToPtr("https://foo.example.com/callback"),
		CodeChallenge: lo.ToPtr("code_verifier"),
	}
	require.Equal(
		t, ErrPKCEDenied,
		request.ValidateWithOptions(client, RequestValidateOptions{PKCEMode: PKCEModeDenied}),
	)

	// Invalid code challenge
	request = Request{
		ResponseType:  ResponseTypeCode,
		ClientID:      "test_client",
		RedirectURI:   lo.ToPtr("https://foo.example.com/callback"),
		CodeChallenge: lo.ToPtr("too_short"),
	}
	require.Equal(t, ErrInvalidCodeChallenge, request.Validate(client))

	// Invalid code challenge method
	request = Request{
		ResponseType:        ResponseTypeCode,
		ClientID:            "test_client",
		RedirectURI:         lo.ToPtr("https://foo.example.com/callback"),
		CodeChallenge:       lo.ToPtr(base64.URLEncoding.EncodeToString(codeVerifier)),
		CodeChallengeMethod: lo.ToPtr[CodeChallengeMethod]("invalid_code_challenge"),
	}
	require.Equal(t, ErrInvalidCodeChallengeMethod, request.Validate(client))
}
