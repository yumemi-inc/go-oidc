package authz

import (
	oauth2 "github.com/yumemi-inc/go-oidc/pkg/oauth2/authz"
)

type Response struct {
	oauth2.Response
}

func NewResponse(code string) Response {
	return Response{
		Response: oauth2.NewResponse(code),
	}
}

func (r Response) WithState(state string) Response {
	r.Response = r.Response.WithState(state)

	return r
}
