package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/gob"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/samber/lo"
	"github.com/yumemi-inc/go-encoding-form"

	"github.com/yumemi-inc/go-oidc/pkg/oauth2/errors"
	oauth2token "github.com/yumemi-inc/go-oidc/pkg/oauth2/token"
	"github.com/yumemi-inc/go-oidc/pkg/oidc"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/authz"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/token"
	"github.com/yumemi-inc/go-oidc/pkg/urls"
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
	},
}

var authorizedRequests = make(map[string]*authz.Request)

func init() {
	gob.Register(&authz.Request{})
}

func main() {
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
			authorizedRequests[code] = authzRequest

			query, err := form.MarshalForm(response)
			if err != nil {
				return err
			}

			redirectURI, err := urls.AppendQueryString(lo.FromPtr(authzRequest.RedirectURI), string(query))
			if err != nil {
				return err
			}

			return c.Redirect(http.StatusFound, redirectURI)
		},
	)

	e.GET(
		"/authorize",
		func(c echo.Context) error {
			req := new(authz.Request)
			if err := form.UnmarshalForm([]byte(c.QueryString()), req); err != nil {
				return err
			}

			if err := req.Validate(clients[req.ClientID]); err != nil {
				errResponse := *err
				if state := req.State; state != nil {
					errResponse = errResponse.WithState(*state)
				}

				if req.RedirectURI != nil {
					query, err := form.MarshalForm(errResponse)
					if err != nil {
						return err
					}

					redirectURI, err := urls.AppendQueryString(*req.RedirectURI, string(query))
					if err != nil {
						return err
					}

					return c.Redirect(http.StatusFound, redirectURI)
				}

				return c.JSON(http.StatusBadRequest, errResponse)
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
			ctx := c.Request().Context()

			req := new(token.Request)
			if err := c.Bind(req); err != nil {
				return err
			}

			authzRequest, ok := authorizedRequests[lo.FromPtr(req.Code)]
			if !ok {
				return errors.New(errors.KindInvalidGrant, "unknown authorization code")
			}

			if err := req.Validate(
				ctx, c.Request(), authzRequest,
				func(ctx context.Context, id string) oidc.Client {
					return clients[id]
				},
			); err != nil {
				errResponse := *err
				if state := authzRequest.State; state != nil {
					errResponse = errResponse.WithState(*state)
				}

				if err.Kind == errors.KindUnauthorizedClient {
					c.Response().Header().Set(echo.HeaderWWWAuthenticate, "Basic")
				}

				return c.JSON(http.StatusBadRequest, errResponse)
			}

			res := token.Response{
				Response: oauth2token.Response{
					AccessToken: "token",
					TokenType:   oauth2token.TypeBearer,
					ExpiresIn:   lo.ToPtr(uint(3600)),
					Scope:       authzRequest.Scope,
				},
			}

			return c.JSON(http.StatusOK, res)
		},
	)

	e.Logger.Fatal(e.Start(":1323"))
}
