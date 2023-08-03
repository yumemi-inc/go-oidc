package pkce

type Mode int

const (
	// ModeRequiredStrict requires the client to initiate PKCE with S256 challenge method.
	ModeRequiredStrict Mode = iota

	// ModeRequired requires the client to initiate PKCE.
	ModeRequired

	// ModeAllowed allows the client to initiate PKCE, but not required.
	ModeAllowed

	// ModeDenied denies any request initiating PKCE.
	ModeDenied
)
