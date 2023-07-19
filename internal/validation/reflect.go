package validation

import (
	"context"
	"errors"
	"reflect"
)

var ErrReflectionFailed = errors.New("reflection failed, this is a bug")

type ReflectValidator struct {
	r reflect.Value
}

func NewReflectValidator[T any](v T) (*ReflectValidator, error) {
	return &ReflectValidator{
		r: reflect.ValueOf(v),
	}, nil
}

func (v *ReflectValidator) Validate(ctx context.Context) error {
	ty := v.r.Type()
	errs := NewError()

	for i := 0; i < ty.NumField(); i++ {
		field := ty.Field(i)
		if !field.Type.Implements(reflect.TypeOf(new(Validator))) {
			continue
		}

		validator, ok := v.r.Field(i).Interface().(Validator)
		if !ok {
			return ErrReflectionFailed
		}

		if err := validator.Validate(ctx); err != nil {
			errs.Set(field.Name, err)
		}
	}

	if errs.IsEmpty() {
		return nil
	}

	return errs
}
