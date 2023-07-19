package idtoken

import (
	"github.com/yumemi-inc/go-oidc/pkg/oidc/claim"
)

type IDToken struct {
	Claims   claim.Claims
	Iss      claim.Iss       `json:"iss"`
	Sub      claim.Sub       `json:"sub"`
	Aud      claim.Aud       `json:"aud"`
	Exp      claim.Exp       `json:"exp"`
	Iat      claim.Iat       `json:"iat"`
	AuthTime *claim.AuthTime `json:"auth_time"`
	Nonce    *claim.Nonce    `json:"nonce"`
	Acr      *claim.Acr      `json:"acr"`
	Amr      *claim.Amr      `json:"amr"`
	Azp      *claim.Azp      `json:"azp"`
}

type IDTokenClaim func(token *IDToken)

func NewIDToken(
	iss claim.Iss,
	sub claim.Sub,
	aud claim.Aud,
	exp claim.Exp,
	iat claim.Iat,
	claims ...IDTokenClaim,
) *IDToken {
	token := &IDToken{
		Iss: iss,
		Sub: sub,
		Aud: aud,
		Exp: exp,
		Iat: iat,
	}

	for _, c := range claims {
		c(token)
	}

	return token
}

func WithAuthTime(authTime claim.AuthTime) IDTokenClaim {
	return func(token *IDToken) {
		token.AuthTime = &authTime
	}
}

func WithNonce(nonce claim.Nonce) IDTokenClaim {
	return func(token *IDToken) {
		token.Nonce = &nonce
	}
}

func WithAcr(acr claim.Acr) IDTokenClaim {
	return func(token *IDToken) {
		token.Acr = &acr
	}
}

func WithAmr(amr claim.Amr) IDTokenClaim {
	return func(token *IDToken) {
		token.Amr = &amr
	}
}

func WithAzp(azp claim.Azp) IDTokenClaim {
	return func(token *IDToken) {
		token.Azp = &azp
	}
}

func WithCustomClaim(key string, value claim.Claim) IDTokenClaim {
	return func(token *IDToken) {
		token.Claims[key] = value
	}
}

func WithCustomClaims(claims claim.Claims) IDTokenClaim {
	return func(token *IDToken) {
		for k, v := range claims {
			token.Claims[k] = v
		}
	}
}
