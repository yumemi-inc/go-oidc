package authz

type ErrorKind string

const (
	ErrorKindInvalidRequest          ErrorKind = "invalid_request"
	ErrorKindUnauthorizedRequest     ErrorKind = "unauthorized_request"
	ErrorKindAccessDenied            ErrorKind = "access_denied"
	ErrorKindUnsupportedResponseType ErrorKind = "unsupported_response_type"
	ErrorKindInvalidScope            ErrorKind = "invalid_scope"
	ErrorKindServerError             ErrorKind = "server_error"
	ErrorKindTemporarilyUnavailable  ErrorKind = "temporarily_unavailable"
)

type Error struct {
	Kind        ErrorKind `json:"error" form:"error"`
	Description string    `json:"error_description" form:"error_description"`
	URI         *string   `json:"error_uri" form:"error_uri"`
	State       *string   `json:"state" form:"state"`
}
