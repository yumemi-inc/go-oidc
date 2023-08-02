package token

import (
	"context"
	"net/http"

	"github.com/samber/lo"

	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
	oauth2token "github.com/yumemi-inc/go-oidc/pkg/oauth2/token"
	"github.com/yumemi-inc/go-oidc/pkg/oidc"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/authz"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/errors"
)

type Request struct {
	oauth2token.Request
}

type Response struct {
	oauth2token.Response
}

func (r *Request) Validate(
	ctx context.Context,
	httpRequest *http.Request,
	authzRequest *authz.Request,
	clientResolver oidc.ClientResolver,
) *errors.Error {
	if err := r.Request.Validate(
		ctx, httpRequest, &authzRequest.Request,
		func(ctx context.Context, id string) oauth2.Client {
			return clientResolver(ctx, id)
		},
	); err != nil {
		return lo.ToPtr(errors.NewFromOauth2(*err))
	}

	return nil
}
