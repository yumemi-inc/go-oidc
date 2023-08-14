package token

import (
	"encoding/json"
	"net/http"

	oauth2token "github.com/yumemi-inc/go-oidc/pkg/oauth2/token"
)

type Response struct {
	oauth2token.Response

	IDToken string `json:"id_token"`
}

func (r *Response) Write(w http.ResponseWriter) error {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)

	return json.NewEncoder(w).Encode(r)
}
