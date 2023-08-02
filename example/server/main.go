package main

import (
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/samber/lo"
	"github.com/yumemi-inc/go-encoding-form"

	oauth2token "github.com/yumemi-inc/go-oidc/pkg/oauth2/token"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/authz"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/token"
	"github.com/yumemi-inc/go-oidc/pkg/urls"
)

var clients = map[string]Client{
	"client1": {
		ID: "client1",
		RedirectURIs: []string{
			"https://client1.example.com/callback",
		},
	},
}

func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))

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

			sess, _ := session.Get("session", c)
			authzRequest := sess.Values["authz_request"].(*authz.Request)

			if err := req.Validate(ctx, authzRequest, clients[req.ClientID]); err != nil {
				errResponse := *err
				if state := authzRequest.State; state != nil {
					errResponse = errResponse.WithState(*state)
				}

				return c.JSON(http.StatusBadRequest, errResponse)
			}

			res := token.Response{
				Response: oauth2token.Response{
					AccessToken: "token",
					TokenType:   oauth2token.TokenTypeBearer,
					ExpiresIn:   lo.ToPtr(uint(3600)),
					Scope:       authzRequest.Scope,
				},
			}

			return c.JSON(http.StatusOK, res)
		},
	)

	e.Logger.Fatal(e.Start(":1323"))
}
