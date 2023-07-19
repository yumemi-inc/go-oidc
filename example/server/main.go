package main

import (
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/yumemi-inc/go-encoding-form"

	oauth2 "github.com/yumemi-inc/go-oidc/pkg/oauth2/authz"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/authz"
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
				errResponse := authz.Error{
					Error: oauth2.Error{
						Kind:        oauth2.ErrorKindInvalidRequest,
						Description: err.Error(),
					},
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

	e.Logger.Fatal(e.Start(":1323"))
}
