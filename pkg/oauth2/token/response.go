package token

type Type string

const (
	TypeBearer Type = "bearer"
	TypeMAC    Type = "mac"
)

type Response struct {
	AccessToken  string  `json:"access_token"`
	TokenType    Type    `json:"token_type"`
	ExpiresIn    *uint   `json:"expires_in,omitempty"`
	RefreshToken *string `json:"refresh_token,omitempty"`
	Scope        *string `json:"scope,omitempty"`
}
