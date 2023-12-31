package discovery

import (
	"encoding/json"
	"net/http"

	"github.com/go-jose/go-jose/v3"

	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
	"github.com/yumemi-inc/go-oidc/pkg/oidc"
	endsession "github.com/yumemi-inc/go-oidc/pkg/oidc/endsession/discovery"
)

const (
	OpenIDConfigurationPath = "/.well-known/openid-configuration"
)

type RequiredMetadata struct {
	// Issuer is URL using the https scheme with no query or fragment component that the OP asserts as its Issuer
	// Identifier. If Issuer discovery is supported, this value MUST be identical to the issuer value returned by
	// WebFinger. This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.
	Issuer string `json:"issuer"`

	// AuthorizationEndpoint is URL of the OP's OAuth 2.0 Authorization Endpoint
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// TokenEndpoint is URL of the OP's OAuth 2.0 Token Endpoint. This is REQUIRED unless only the Implicit Flow is
	// used.
	TokenEndpoint *string `json:"token_endpoint,omitempty"`

	// JwksURI is URL of the OP's JSON Web Key Set document. This contains the signing key(s) the RP uses to validate
	// signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s), which are used by RPs to
	// encrypt requests to the Server. When both signing and encryption keys are made available, a use (Key Use)
	// parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage.
	// Although some algorithms allow the same key to be used for both signatures and encryption, doing so is NOT
	// RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used to provide X.509 representations of keys
	// provided. When used, the bare key values MUST still be present and MUST match those in the certificate.
	JwksURI string `json:"jwks_uri,omitempty"`

	// ResponseTypesSupported is JSON array containing a list of the OAuth 2.0 response_type values that this OP
	// supports. Dynamic OpenID Providers MUST support the code, id_token, and the token id_token Response Type values.
	ResponseTypesSupported []oidc.ResponseType `json:"response_types_supported,omitempty"`

	// SubjectTypesSupported is JSON array containing a list of the Subject Identifier types that this OP supports.
	// Valid types include pairwise and public.
	SubjectTypesSupported []oidc.SubjectType `json:"subject_types_supported,omitempty"`

	// IDTokenSigningAlgValuesSupported is JSON array containing a list of the JWS signing algorithms (alg values)
	// supported by the OP for the ID Token to encode the Claims in a JWT. The algorithm RS256 MUST be included. The
	// value none MAY be supported, but MUST NOT be used unless the Response Type used returns no ID Token from the
	// Authorization Endpoint (such as when using the Authorization Code Flow).
	IDTokenSigningAlgValuesSupported []jose.SignatureAlgorithm `json:"id_token_signing_alg_values_supported"`
}

type RecommendedMetadata struct {
	// UserinfoEndpoint is URL of the OP's UserInfo Endpoint. This URL MUST use the https scheme and MAY contain port,
	// path, and query parameter components.
	UserinfoEndpoint *string `json:"userinfo_endpoint,omitempty"`

	// RegistrationEndpoint is URL of the OP's Dynamic Client Registration Endpoint.
	RegistrationEndpoint *string `json:"registration_endpoint,omitempty"`

	// ScopesSupported is JSON array containing a list of the OAuth 2.0 scope values that this server supports. The
	// server MUST support the openid scope value. Servers MAY choose not to advertise some supported scope values even
	// when this parameter is used, although those defined in [OpenID.Core] SHOULD be listed, if supported.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// ClaimsSupported is JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be
	// able to supply values for. Note that for privacy or other reasons, this might not be an exhaustive list.
	ClaimsSupported []string `json:"claims_supported,omitempty"`
}

type OptionalMetadata struct {
	// ResponseModesSupported is JSON array containing a list of the OAuth 2.0 response_mode values that this OP
	// supports, as specified in OAuth 2.0 Multiple Response Type Encoding Practices. If omitted, the default for
	// Dynamic OpenID Providers is ["query", "fragment"].
	ResponseModesSupported []oidc.ResponseMode `json:"response_modes_supported,omitempty"`

	// GrantTypesSupported is JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports.
	// Dynamic OpenID Providers MUST support the authorization_code and implicit Grant Type values and MAY support other
	// Grant Types. If omitted, the default value is ["authorization_code", "implicit"].
	GrantTypesSupported []oauth2.GrantType `json:"grant_types_supported,omitempty"`

	// AcrValuesSupported is JSON array containing a list of the Authentication Context Class References that this OP
	// supports.
	AcrValuesSupported []string `json:"acr_values_supported,omitempty"`

	// IDTokenEncryptionAlgValuesSupported is JSON array containing a list of the JWE encryption algorithms (alg values)
	// supported by the OP for the ID Token to encode the Claims in a JWT.
	IDTokenEncryptionAlgValuesSupported []jose.SignatureAlgorithm `json:"id_token_encryption_alg_values_supported,omitempty"`

	// IDTokenEncryptionEncValuesSupported is JSON array containing a list of the JWE encryption algorithms (enc values)
	// supported by the OP for the ID Token to encode the Claims in a JWT.
	IDTokenEncryptionEncValuesSupported []jose.ContentEncryption `json:"id_token_encryption_enc_values_supported,omitempty"`

	// UserinfoSigningAlgValuesSupported is JSON array containing a list of the JWS signing algorithms (alg values)
	// supported by the UserInfo Endpoint to encode the Claims in a JWT.
	UserinfoSigningAlgValuesSupported []jose.SignatureAlgorithm `json:"userinfo_signing_alg_values_supported,omitempty"`

	// UserinfoEncryptionAlgValuesSupported is JSON array containing a list of the JWE encryption algorithms (alg
	// values) supported by the OP for the UserInfo Endpoint to encode the Claims in a JWT.
	UserinfoEncryptionAlgValuesSupported []jose.SignatureAlgorithm `json:"userinfo_encryption_alg_values_supported,omitempty"`

	// UserinfoEncryptionEncValuesSupported is JSON array containing a list of the JWE encryption algorithms (enc
	// values) supported by the OP for the UserInfo Endpoint to encode the Claims in a JWT.
	UserinfoEncryptionEncValuesSupported []jose.ContentEncryption `json:"userinfo_encryption_enc_values_supported,omitempty"`

	// RequestObjectSigningAlgValuesSupported is JSON array containing a list of the JWS signing algorithms (alg values)
	// supported by the OP for Request Objects, which are described in Section 6.1 of OpenID Connect Core 1.0. These
	// algorithms are used both when the Request Object is passed by value (using the request parameter) and when it is
	// passed by reference (using the request_uri parameter). Servers SHOULD support none and RS256.
	RequestObjectSigningAlgValuesSupported []jose.SignatureAlgorithm `json:"request_object_signing_alg_values_supported,omitempty"`

	// RequestObjectEncryptionAlgValuesSupported isJSON array containing a list of the JWE encryption algorithms (alg
	// values) supported by the OP for Request Objects. These algorithms are used both when the Request Object is passed
	// by value and when it is passed by reference.
	RequestObjectEncryptionAlgValuesSupported []jose.SignatureAlgorithm `json:"request_object_encryption_alg_values_supported,omitempty"`

	// RequestObjectEncryptionEncValuesSupported is JSON array containing a list of the JWE encryption algorithms (enc
	// values) supported by the OP for Request Objects. These algorithms are used both when the Request Object is passed
	// by value and when it is passed by reference.
	RequestObjectEncryptionEncValuesSupported []jose.ContentEncryption `json:"request_object_encryption_enc_values_supported,omitempty"`

	// TokenEndpointAuthMethodsSupported is JSON array containing a list of Client Authentication methods supported by
	// this Token Endpoint. The options are client_secret_post, client_secret_basic, client_secret_jwt, and
	// private_key_jwt, as described in Section 9 of OpenID Connect Core 1.0. Other authentication methods MAY be
	// defined by extensions. If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme
	// specified in Section 2.3.1 of OAuth 2.0.
	TokenEndpointAuthMethodsSupported []oidc.ClientAuthenticationMethod `json:"token_endpoint_auth_methods_supported,omitempty"`

	// TokenEndpointAuthSigningAlgValuesSupported is JSON array containing a list of the JWS signing algorithms (alg
	// values) supported by the Token Endpoint for the signature on the JWT used to authenticate the Client at the Token
	// Endpoint for the private_key_jwt and client_secret_jwt authentication methods. Servers SHOULD support RS256. The
	// value none MUST NOT be used.
	TokenEndpointAuthSigningAlgValuesSupported []jose.SignatureAlgorithm `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	// DisplayValuesSupported is JSON array containing a list of the display parameter values that the OpenID Provider
	// supports. These values are described in Section 3.1.2.1 of OpenID Connect Core 1.0.
	DisplayValuesSupported []oidc.Display `json:"display_values_supported,omitempty"`

	// ClaimTypesSupported is JSON array containing a list of the Claim Types that the OpenID Provider supports. These
	// Claim Types are described in Section 5.6 of OpenID Connect Core 1.0. Values defined by this specification are
	// normal, aggregated, and distributed. If omitted, the implementation supports only normal Claims.
	ClaimTypesSupported []oidc.ClaimType `json:"claim_types_supported,omitempty"`

	// ServiceDocumentation is URL of a page containing human-readable information that developers might want or need to
	// know when using the OpenID Provider. In particular, if the OpenID Provider does not support Dynamic Client
	// Registration, then information on how to register Clients needs to be provided in this documentation.
	ServiceDocumentation *string `json:"service_documentation,omitempty"`

	// ClaimLocalesSupported are languages and scripts supported for values in Claims being returned, represented as a
	// JSON array of BCP47 language tag values. Not all languages and scripts are necessarily supported for all Claim
	// values.
	ClaimLocalesSupported []string `json:"claim_locales_supported,omitempty"`

	// UILocalesSupported are languages and scripts supported for the user interface, represented as a JSON array of
	// BCP47 language tag values.
	UILocalesSupported []string `json:"ui_locales_supported,omitempty"`

	// ClaimsParameterSupported is boolean value specifying whether the OP supports use of the claims parameter, with
	// true indicating support. If omitted, the default value is false.
	ClaimsParameterSupported *bool `json:"claims_parameter_supported,omitempty"`

	// RequestParameterSupported is boolean value specifying whether the OP supports use of the request parameter, with
	// true indicating support. If omitted, the default value is false.
	RequestParameterSupported *bool `json:"request_parameter_supported,omitempty"`

	// RequestURIParameterSupported is boolean value specifying whether the OP supports use of the request_uri
	// parameter, with true indicating support. If omitted, the default value is true.
	RequestURIParameterSupported *bool `json:"request_uri_parameter_supported,omitempty"`

	// RequireRequestURIRegistration is boolean value specifying whether the OP requires any request_uri values used to
	// be pre-registered using the request_uris registration parameter. Pre-registration is REQUIRED when the value is
	// true. If omitted, the default value is false.
	RequireRequestURIRegistration *bool `json:"require_request_uri_registration,omitempty"`

	// OPPolicyURI is URL that the OpenID Provider provides to the person registering the Client to read about the OP's
	// requirements on how the Relying Party can use the data provided by the OP. The registration process SHOULD
	// display this URL to the person registering the Client if it is given.
	OPPolicyURI *string `json:"op_policy_uri,omitempty"`

	// OPTosURI is URL that the OpenID Provider provides to the person registering the Client to read about OpenID
	// Provider's terms of service. The registration process SHOULD display this URL to the person registering the
	// Client if it is given.
	OPTosURI *string `json:"op_tos_uri,omitempty"`
}

type EndSessionMetadata = endsession.Metadata

type Metadata struct {
	RequiredMetadata
	RecommendedMetadata
	OptionalMetadata

	// Extensions
	*EndSessionMetadata
}

func (m Metadata) Write(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	return json.NewEncoder(w).Encode(m)
}
