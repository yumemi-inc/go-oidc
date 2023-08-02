package errors

import (
	"fmt"

	oauth2 "github.com/yumemi-inc/go-oidc/pkg/oauth2/errors"
)

type Kind oauth2.Kind

const (
	KindInteractionRequired      Kind = "interaction_required"
	KindLoginRequired            Kind = "login_required"
	KindAccountSelectionRequired Kind = "account_selection_required"
	KindConsentRequired          Kind = "consent_required"
	KindInvalidRequestURI        Kind = "invalid_request_uri"
	KindInvalidRequestObject     Kind = "invalid_request_object"
	KindRequestNotSupported      Kind = "request_not_supported"
	KindRequestURINotSupported   Kind = "request_uri_not_supported"
	KindRegistrationNotSupported Kind = "registration_not_supported"
)

type Oauth2Error = oauth2.Error

type Error struct {
	Oauth2Error
}

func New(kind Kind, description string) Error {
	return Error{
		Oauth2Error: oauth2.Error{
			Kind:        oauth2.Kind(kind),
			Description: description,
		},
	}
}

func NewFromOauth2(e oauth2.Error) Error {
	return Error{
		Oauth2Error: e,
	}
}

func (e Error) WithState(state string) Error {
	e.State = &state

	return e
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Kind, e.Description)
}
