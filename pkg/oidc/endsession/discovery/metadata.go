package discovery

// Metadata is additional metadata on discovery for RP-initiated logout.
type Metadata struct {
	// EndSessionEndpoint is URL at the OP to which an RP can perform a redirect to request that the End-User be logged
	// out at the OP. This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
	EndSessionEndpoint string `json:"end_session_endpoint"`
}
