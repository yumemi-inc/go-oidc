package token

import (
	"context"

	"github.com/samber/lo"

	oauth2 "github.com/yumemi-inc/go-oidc/pkg/oauth2/token"
	"github.com/yumemi-inc/go-oidc/pkg/oidc"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/authz"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/errors"
)

type Request struct {
	oauth2.Request
}

type Response struct {
	oauth2.Response
}

func (r *Request) Validate(
	ctx context.Context,
	authzRequest *authz.Request,
	client oidc.Client,
) *errors.Error {
	if err := r.Request.Validate(ctx, &authzRequest.Request, client); err != nil {
		return lo.ToPtr(errors.NewFromOauth2(*err))
	}

	return nil
}
