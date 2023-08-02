package typeconv

import (
	"github.com/samber/lo"
)

func IsEmptyOrNil[T comparable](value *T) bool {
	return value == nil || lo.IsEmpty(*value)
}
