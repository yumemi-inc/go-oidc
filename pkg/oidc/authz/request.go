package authz

import (
	"errors"

	"github.com/samber/lo"

	oauth2 "github.com/yumemi-inc/go-oidc/pkg/oauth2/authz"
	"github.com/yumemi-inc/go-oidc/pkg/oidc"
)

const (
	ScopeOpenID = "openid"
)

var (
	ErrOpenIDScopeRequired = errors.New("openid scope is required")
)

type ResponseMode string

const (
	ResponseModeQuery    ResponseMode = "query"
	ResponseModeFragment ResponseMode = "query"
)

type Display string

const (
	DisplayPage  Display = "page"
	DisplayPopup Display = "popup"
	DisplayTouch Display = "touch"
	DisplayWap   Display = "wap"
)

type Prompt string

const (
	PromptNone          Prompt = "none"
	PromptLogin         Prompt = "login"
	PromptConsent       Prompt = "consent"
	PromptSelectAccount Prompt = "select_account"
)

type Request struct {
	oauth2.Request

	ResponseMode *ResponseMode `form:"response_mode"`
	Nonce        *string       `form:"nonce"`
	Display      *Display      `form:"display"`
	Prompt       *Prompt       `form:"prompt"`
	MaxAge       *int64        `form:"max_age"`
	UILocales    *string       `form:"ui_locales"`
	IDTokenHint  *string       `form:"id_token_hint"`
	LoginHint    *string       `form:"login_hint"`
	ACRValues    *string       `form:"acr_values"`
}

func (r *Request) Validate(client oidc.Client) error {
	if err := r.Request.Validate(client); err != nil {
		return err
	}

	if !lo.Contains(r.Scopes(), ScopeOpenID) {
		return ErrOpenIDScopeRequired
	}

	return nil
}
