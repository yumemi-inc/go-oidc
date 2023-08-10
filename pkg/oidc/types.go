package oidc

import (
	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
)

const (
	ScopeOpenID = "openid"

	// ScopeProfile requests access to the End-User's default profile Claims, which are: name, family_name, given_name,
	// middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, and
	// updated_at.
	ScopeProfile = "profile"

	// ScopeEmail requests access to the email and email_verified Claims.
	ScopeEmail = "email"

	// ScopeAddress requests access to the address Claim.
	ScopeAddress = "address"

	// ScopePhone requests access to the phone_number and phone_number_verified Claims.
	ScopePhone = "phone"
)

type SubjectType string

const (
	SubjectTypePairwise SubjectType = "pairwise"
	SubjectTypePublic   SubjectType = "public"
)

type ClaimType string

const (
	ClaimTypeNormal      ClaimType = "normal"
	ClaimTypeAggregated  ClaimType = "aggregated"
	ClaimTypeDistributed ClaimType = "distributed"
)

type ResponseType = oauth2.ResponseType

const (
	ResponseTypeCode                      = oauth2.ResponseTypeCode
	ResponseTypeToken                     = oauth2.ResponseTypeToken
	ResponseTypeIDToken      ResponseType = "id_token"
	ResponseTypeTokenIDToken ResponseType = "token id_token"
)

type ResponseMode string

const (
	ResponseModeQuery    ResponseMode = "query"
	ResponseModeFragment ResponseMode = "fragment"
)

type Display string

const (
	DisplayPage  Display = "page"
	DisplayPopup Display = "popup"
	DisplayTouch Display = "touch"
	DisplayWap   Display = "wap"
)

type Prompt string

const (
	PromptNone          Prompt = "none"
	PromptLogin         Prompt = "login"
	PromptConsent       Prompt = "consent"
	PromptSelectAccount Prompt = "select_account"
)
