package errors

import (
	"net/http"
	"net/url"

	oauth2 "github.com/yumemi-inc/go-oidc/pkg/oauth2/errors"
)

type Kind = oauth2.Kind

const (
	KindAccessDenied            = oauth2.KindAccessDenied
	KindInvalidClient           = oauth2.KindInvalidClient
	KindInvalidGrant            = oauth2.KindInvalidGrant
	KindInvalidRequest          = oauth2.KindInvalidRequest
	KindInvalidScope            = oauth2.KindInvalidScope
	KindServerError             = oauth2.KindServerError
	KindTemporarilyUnavailable  = oauth2.KindTemporarilyUnavailable
	KindUnauthorizedClient      = oauth2.KindUnauthorizedClient
	KindUnsupportedGrantType    = oauth2.KindUnsupportedGrantType
	KindUnsupportedResponseType = oauth2.KindUnsupportedResponseType

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

type Error = oauth2.Error

func New(kind Kind, description string) *Error {
	return oauth2.New(kind, description)
}

func WriteAsRedirect(err error, w http.ResponseWriter, redirectURI url.URL, state *string) error {
	return oauth2.WriteAsRedirect(err, w, redirectURI, state)
}

func Is(err error, kind Kind) bool {
	return oauth2.Is(err, kind)
}

func Write(err error, w http.ResponseWriter) error {
	return oauth2.Write(err, w)
}
