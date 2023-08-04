package token

type Authorization interface {
	GetClientID() string
	GetScopes() []string
}
