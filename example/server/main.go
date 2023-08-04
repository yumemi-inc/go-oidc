package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/samber/lo"

	"github.com/yumemi-inc/go-oidc/pkg/jwt"
	"github.com/yumemi-inc/go-oidc/pkg/jwt/keychain"
	"github.com/yumemi-inc/go-oidc/pkg/jwt/keys"
	oauth2errors "github.com/yumemi-inc/go-oidc/pkg/oauth2/errors"
	oauth2token "github.com/yumemi-inc/go-oidc/pkg/oauth2/token"
	"github.com/yumemi-inc/go-oidc/pkg/oidc"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/authz"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/claim"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/discovery"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/endsession"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/errors"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/token"
)

//go:embed login.html
var loginHTML string

var users = map[string]User{
	"user1": {
		ID:       "user1",
		Password: "password1",
	},
}

var clients = map[string]Client{
	"client1": {
		ID: "client1",
		RedirectURIs: []string{
			"https://client1.example.com/callback",
		},
		PostLogoutRedirectURIs: []string{
			"https://client1.example.com/end_session_callback",
		},
	},
}

var authorizedCodeMap = make(map[string]*authz.Request)

type Token struct {
	AuthzRequest    *authz.Request
	Scope           *string
	Claims          claim.Claims
	InitiatedAt     time.Time
	LastRefreshedAt *time.Time
}

var refreshableTokenMap = make(map[string]Token)

func init() {
	gob.Register(&authz.Request{})
}

func app() *echo.Echo {
	keypair := lo.Must(keys.GenerateECDSAKeypair(jose.ES256, jwt.UseSignature))
	jwtKeychain := keychain.New()
	jwtKeychain.Add(keypair)

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))

	e.GET(
		"/login",
		func(c echo.Context) error {
			return c.HTML(http.StatusOK, loginHTML)
		},
	)

	e.POST(
		"/login",
		func(c echo.Context) error {
			req := new(User)
			if err := c.Bind(req); err != nil {
				return err
			}

			user, ok := users[req.ID]
			if !ok || user.Password != req.Password {
				return echo.ErrUnauthorized
			}

			sess, _ := session.Get("session", c)
			authzRequest, ok := sess.Values["authz_request"].(*authz.Request)
			if !ok {
				return echo.ErrBadRequest
			}

			delete(sess.Values, "authz_request")
			lo.Must0(sess.Save(c.Request(), c.Response()))

			bytes := make([]byte, 32)
			if _, err := rand.Read(bytes); err != nil {
				return err
			}

			code := base64.RawURLEncoding.EncodeToString(bytes)
			response := authz.NewResponse(code)
			authorizedCodeMap[code] = authzRequest

			u, err := url.Parse(lo.FromPtr(authzRequest.RedirectURI))
			if err != nil {
				return err
			}

			return response.SetState(authzRequest.State).WriteAsRedirect(c.Response(), *u)
		},
	)

	e.GET(
		"/authorize",
		func(c echo.Context) error {
			req, err := authz.ReadRequest(c.Request())
			if err != nil {
				return errors.Write(err, c.Response())
			}

			if err := req.Validate(clients[req.ClientID]); err != nil {
				if req.RedirectURI != nil {
					u, err := url.Parse(*req.RedirectURI)
					if err != nil {
						return err
					}

					return errors.WriteAsRedirect(err, c.Response(), *u, req.State)
				}

				return errors.Write(err, c.Response())
			}

			sess, _ := session.Get("session", c)
			sess.Values["authz_request"] = req
			lo.Must0(sess.Save(c.Request(), c.Response()))

			return c.Redirect(http.StatusFound, "/login")
		},
	)

	e.POST(
		"/token",
		func(c echo.Context) error {
			var currentToken Token

			req, err := token.ReadRequest(c.Request())
			if err != nil {
				return errors.Write(err, c.Response())
			}

			switch req := req.(type) {
			case *token.AuthorizationCodeGrantRequest:
				authzRequest, ok := authorizedCodeMap[req.Code]
				if !ok {
					return errors.
						New(errors.KindInvalidGrant, "invalid authorization code").
						Write(c.Response())
				}

				if err := req.Validate(authzRequest.RedirectURI, authzRequest.Challenge); err != nil {
					return errors.Write(err, c.Response())
				}

				claims := claim.NewClaims().
					With(lo.Must(claim.IssFromStr("https://id.example.com/"))).
					With(claim.Aud{authzRequest.ClientID}).
					With(claim.Sub("user1"))

				currentToken = Token{
					AuthzRequest: authzRequest,
					Scope:        authzRequest.Scope,
					Claims:       claims,
					InitiatedAt:  time.Now(),
				}

			case *token.RefreshTokenGrantRequest:
				fmt.Printf("%+v\n", refreshableTokenMap)
				t, ok := refreshableTokenMap[req.RefreshToken]
				if !ok {
					return oauth2errors.
						New(oauth2errors.KindInvalidGrant, "invalid refresh token").
						Write(c.Response())
				}

				scopes := make([]string, 0)
				if t.Scope != nil {
					scopes = strings.Split(*t.Scope, " ")
				}

				if err := req.Validate(scopes); err != nil {
					return errors.Write(err, c.Response())
				}

				t.LastRefreshedAt = lo.ToPtr(time.Now())
				if req.Scope != nil {
					t.Scope = req.Scope
				}

				currentToken = t
				delete(refreshableTokenMap, req.RefreshToken)
				fmt.Printf("%+v\n", refreshableTokenMap)

			default:
				panic("not implemented")
			}

			idToken, err := currentToken.Claims.SignJWT(keypair)
			if err != nil {
				return err
			}

			bytes := make([]byte, 64)
			if _, err := rand.Read(bytes); err != nil {
				return err
			}

			refreshToken := base64.RawURLEncoding.EncodeToString(bytes)
			refreshableTokenMap[refreshToken] = currentToken
			fmt.Printf("%+v\n", refreshableTokenMap)

			res := token.Response{
				Response: oauth2token.Response{
					AccessToken:  "token",
					TokenType:    oauth2token.TypeBearer,
					ExpiresIn:    lo.ToPtr(uint(3600)),
					RefreshToken: lo.ToPtr(refreshToken),
					Scope:        currentToken.Scope,
				},
				IDToken: idToken,
			}

			return res.Write(c.Response())
		},
	)

	e.Any(
		"/end_session",
		func(c echo.Context) error {
			if c.Request().Method != http.MethodGet && c.Request().Method != http.MethodPost {
				return echo.ErrMethodNotAllowed
			}

			req, err := endsession.ReadRequest(c.Request())
			if err != nil {
				// ignoring error
				req = &endsession.Request{}
			}

			var client endsession.Client
			if req.ClientID != nil {
				client = clients[*req.ClientID]
			}

			if err := req.Validate(client, jwtKeychain); err != nil {
				// ignoring error
				req = &endsession.Request{}
			}

			// Logout
			sess, _ := session.Get("session", c)
			sess.Values = make(map[any]any)
			lo.Must0(sess.Save(c.Request(), c.Response()))

			if req.PostLogoutRedirectURI != nil {
				return c.Redirect(http.StatusFound, *req.PostLogoutRedirectURI)
			}

			return c.NoContent(http.StatusNoContent)
		},
	)

	e.GET(
		"/jwks.json",
		func(c echo.Context) error {
			return c.JSON(http.StatusOK, jwt.JWKSFromPublicKeychain(jwtKeychain))
		},
	)

	e.GET(
		discovery.OpenIDConfigurationPath,
		func(c echo.Context) error {
			issuer := url.URL{
				Scheme: c.Scheme(),
				Host:   c.Request().Host,
			}

			metadata := discovery.Metadata{
				RequiredMetadata: discovery.RequiredMetadata{
					Issuer:                           issuer.String(),
					AuthorizationEndpoint:            issuer.JoinPath("/authorize").String(),
					TokenEndpoint:                    lo.ToPtr(issuer.JoinPath("/token").String()),
					JwksURI:                          issuer.JoinPath("/jwks.json").String(),
					ResponseTypesSupported:           []oidc.ResponseType{oidc.ResponseTypeCode},
					SubjectTypesSupported:            []oidc.SubjectType{oidc.SubjectTypePublic},
					IDTokenSigningAlgValuesSupported: []jose.SignatureAlgorithm{jose.ES256},
				},
			}

			return metadata.Write(c.Response())
		},
	)

	return e
}

func main() {
	e := app()
	e.Logger.Fatal(e.Start(":1323"))
}
