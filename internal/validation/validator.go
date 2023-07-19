package validation

import (
	"context"
	"errors"
)

var ErrRequired = errors.New("missing required value")

type Validator interface {
	Validate(ctx context.Context) error
}
