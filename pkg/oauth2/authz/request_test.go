package authz

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
	"github.com/yumemi-inc/go-oidc/pkg/oauth2/pkce"
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
	require.Nil(t, request.ValidateWithOptions(client, RequestValidateOptions{PKCEMode: pkce.ModeDenied}))

	codeVerifier := make([]byte, 64)
	lo.Must(rand.Read(codeVerifier))

	// With PKCE
	request = Request{
		ResponseType: ResponseTypeCode,
		ClientID:     "test_client",
		RedirectURI:  lo.ToPtr("https://foo.example.com/callback"),
		Challenge: pkce.Challenge{
			CodeChallenge:       lo.ToPtr(base64.URLEncoding.EncodeToString(codeVerifier)),
			CodeChallengeMethod: lo.ToPtr(pkce.CodeChallengeMethodS256),
		},
	}
	require.Nil(t, request.ValidateWithOptions(client, RequestValidateOptions{PKCEMode: pkce.ModeRequiredStrict}))

	// Client ID mismatch
	request = Request{
		ResponseType: ResponseTypeCode,
		ClientID:     "invalid_client",
		RedirectURI:  lo.ToPtr("https://foo.example.com/callback"),
	}
	require.Equal(t, &ErrClientIDMismatch, request.Validate(client))

	// Invalid redirect URI
	request = Request{
		ResponseType: ResponseTypeCode,
		ClientID:     "test_client",
		RedirectURI:  lo.ToPtr("https://foo.example.com/"),
	}
	require.Equal(t, &ErrInvalidRedirectURI, request.Validate(client))

	// Invalid scope format
	request = Request{
		ResponseType: ResponseTypeCode,
		ClientID:     "test_client",
		RedirectURI:  lo.ToPtr("https://foo.example.com/callback"),
		Scope:        lo.ToPtr("スコープ"),
	}
	require.Equal(t, &ErrInvalidScopeFormat, request.Validate(client))

	// PKCE required
	request = Request{
		ResponseType: ResponseTypeCode,
		ClientID:     "test_client",
		RedirectURI:  lo.ToPtr("https://foo.example.com/callback"),
	}
	require.Equal(
		t, &pkce.ErrPKCERequired,
		request.ValidateWithOptions(client, RequestValidateOptions{PKCEMode: pkce.ModeRequired}),
	)

	// PKCE denied
	request = Request{
		ResponseType: ResponseTypeCode,
		ClientID:     "test_client",
		RedirectURI:  lo.ToPtr("https://foo.example.com/callback"),
		Challenge: pkce.Challenge{
			CodeChallenge: lo.ToPtr("code_verifier"),
		},
	}
	require.Equal(
		t, &pkce.ErrPKCEDenied,
		request.ValidateWithOptions(client, RequestValidateOptions{PKCEMode: pkce.ModeDenied}),
	)

	// Invalid code challenge
	request = Request{
		ResponseType: ResponseTypeCode,
		ClientID:     "test_client",
		RedirectURI:  lo.ToPtr("https://foo.example.com/callback"),
		Challenge: pkce.Challenge{
			CodeChallenge: lo.ToPtr("too_short"),
		},
	}
	require.Equal(t, &pkce.ErrInvalidCodeChallenge, request.Validate(client))

	// Invalid code challenge method
	request = Request{
		ResponseType: ResponseTypeCode,
		ClientID:     "test_client",
		RedirectURI:  lo.ToPtr("https://foo.example.com/callback"),
		Challenge: pkce.Challenge{
			CodeChallenge:       lo.ToPtr(base64.URLEncoding.EncodeToString(codeVerifier)),
			CodeChallengeMethod: lo.ToPtr[pkce.CodeChallengeMethod]("invalid_code_challenge"),
		},
	}
	require.Equal(t, &pkce.ErrInvalidCodeChallengeMethod, request.Validate(client))
}
