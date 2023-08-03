package oidc

import (
	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
)

const (
	ScopeOpenID = "openid"
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
