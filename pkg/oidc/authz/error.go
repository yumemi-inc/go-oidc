package authz

import (
	oauth2 "github.com/yumemi-inc/go-oidc/pkg/oauth2/authz"
)

type ErrorKind oauth2.ErrorKind

const (
	ErrorKindInteractionRequired      ErrorKind = "interaction_required"
	ErrorKindLoginRequired            ErrorKind = "login_required"
	ErrorKindAccountSelectionRequired ErrorKind = "account_selection_required"
	ErrorKindConsentRequired          ErrorKind = "consent_required"
	ErrorKindInvalidRequestURI        ErrorKind = "invalid_request_uri"
	ErrorKindInvalidRequestObject     ErrorKind = "invalid_request_object"
	ErrorKindRequestNotSupported      ErrorKind = "request_not_supported"
	ErrorKindRequestURINotSupported   ErrorKind = "request_uri_not_supported"
	ErrorKindRegistrationNotSupported ErrorKind = "registration_not_supported"
)

type Error struct {
	oauth2.Error
}
