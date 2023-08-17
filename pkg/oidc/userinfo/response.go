package userinfo

import (
	"encoding/json"
	"net/http"

	"github.com/yumemi-inc/go-oidc/pkg/jwt"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/claim"
)

type Response claim.Claims

func (r *Response) Write(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	return json.NewEncoder(w).Encode(r)
}

func (r *Response) WriteAsSignedJWT(w http.ResponseWriter, key jwt.PrivateSigningKey) error {
	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)

	jwtString, err := claim.Claims(*r).SignJWT(key)
	if err != nil {
		return err
	}

	if _, err := w.Write([]byte(jwtString)); err != nil {
		return err
	}

	return nil
}
