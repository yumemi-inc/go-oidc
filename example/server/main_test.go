package main

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	oauth2token "github.com/yumemi-inc/go-oidc/pkg/oauth2/token"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/claim"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/discovery"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/token"
)

func Test_OpenIDConfiguration(t *testing.T) {
	e := app()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, echo.MIMEApplicationJSON, rec.Header().Get(echo.HeaderContentType))

	res := new(discovery.Metadata)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), res))
	assert.Equal(t, "http://example.com", res.Issuer)
	assert.Equal(t, "http://example.com/authorize", res.AuthorizationEndpoint)
	assert.Equal(t, "http://example.com/token", *res.TokenEndpoint)
}

func Test_AuthorizationCodeFlow(t *testing.T) {
	e := app()
	jar := lo.Must(cookiejar.New(nil))
	cookieURL := lo.Must(url.Parse("http://localhost/"))

	{
		query := url.Values{}
		query.Set("response_type", "code")
		query.Set("client_id", "client1")
		query.Set("redirect_uri", "https://client1.example.com/callback")
		query.Set("scope", "openid")
		query.Set("state", "my_state")

		u := url.URL{Path: "/authorize", RawQuery: query.Encode()}
		req := httptest.NewRequest(http.MethodGet, u.RequestURI(), nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		require.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/login", rec.Header().Get(echo.HeaderLocation))
		assert.NotEmpty(t, rec.Header().Get(echo.HeaderSetCookie))

		jar.SetCookies(cookieURL, rec.Result().Cookies())
	}

	var code string
	{
		form := url.Values{}
		form.Set("id", "user1")
		form.Set("password", "password1")

		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		for _, c := range jar.Cookies(cookieURL) {
			req.AddCookie(c)
		}

		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		require.Equal(t, http.StatusFound, rec.Code)
		assert.True(
			t,
			strings.HasPrefix(rec.Header().Get(echo.HeaderLocation), "https://client1.example.com/callback?"),
		)

		q := lo.Must(rec.Result().Location()).Query()
		assert.Equal(t, "my_state", q.Get("state"))

		code = q.Get("code")
	}

	var refreshToken string
	{
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", "https://client1.example.com/callback")

		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "no-store", rec.Header().Get(echo.HeaderCacheControl))
		assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))

		res := new(token.Response)
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), res))
		assert.NotEmpty(t, res.AccessToken)
		assert.NotEmpty(t, res.RefreshToken)
		assert.NotEmpty(t, res.IDToken)
		assert.Equal(t, oauth2token.TypeBearer, res.TokenType)
		assert.Equal(t, "openid", *res.Scope)

		claims, err := claim.UnsafeDecodeClaimsFromJWT(res.IDToken)
		require.NoError(t, err)
		assert.Equal(t, "https://id.example.com/", claims["iss"].(claim.Iss).String())
		assert.Equal(t, claim.Aud{"client1"}, claims["aud"].(claim.Aud))
		assert.Equal(t, claim.Sub("user1"), claims["sub"].(claim.Sub))

		refreshToken = *res.RefreshToken
	}

	{
		form := url.Values{}
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", refreshToken)

		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		res := new(token.Response)
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), res))
		assert.NotEmpty(t, res.AccessToken)
		assert.NotEmpty(t, res.RefreshToken)
		assert.NotEqual(t, refreshToken, res.RefreshToken)
	}
}
