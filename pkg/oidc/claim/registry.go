package claim

import (
	"encoding/json"
	"sync"

	"github.com/samber/lo"
)

var (
	DefaultRegistry      = make(Registry)
	defaultRegistryMutex = sync.RWMutex{}
)

func init() {
	AddUnmarshaler[Iss](DefaultRegistry)
	AddUnmarshaler[Sub](DefaultRegistry)
	AddUnmarshaler[Aud](DefaultRegistry)
	AddUnmarshaler[Exp](DefaultRegistry)
	AddUnmarshaler[Iat](DefaultRegistry)
	AddUnmarshaler[AuthTime](DefaultRegistry)
	AddUnmarshaler[Nonce](DefaultRegistry)
	AddUnmarshaler[Acr](DefaultRegistry)
	AddUnmarshaler[Amr](DefaultRegistry)
	AddUnmarshaler[Azp](DefaultRegistry)
}

type UnmarshalFunc func(bytes []byte) (Claim, error)

func Unmarshaler[T Claim]() UnmarshalFunc {
	return func(bytes []byte) (Claim, error) {
		ptr := new(T)
		if err := json.Unmarshal(bytes, ptr); err != nil {
			return nil, err
		}

		return *ptr, nil
	}
}

type Registry map[string]UnmarshalFunc

func AddUnmarshaler[T Claim](registry Registry) {
	registry[lo.Empty[T]().ClaimName()] = Unmarshaler[T]()
}

func (r Registry) Unmarshal(name string, value json.RawMessage) (Claim, error) {
	unmarshaler, ok := r[name]
	if !ok {
		return RawClaim{
			Name:  name,
			Value: value,
		}, nil
	}

	return unmarshaler(value)
}

func (r Registry) UnmarshalAll(values map[string]json.RawMessage) (Claims, error) {
	claims := make(Claims)
	for name, value := range values {
		claim, err := r.Unmarshal(name, value)
		if err != nil {
			return nil, err
		}

		claims = claims.With(claim)
	}

	return claims, nil
}

func Unmarshal(name string, value json.RawMessage) (Claim, error) {
	defaultRegistryMutex.RLock()
	defer defaultRegistryMutex.RUnlock()

	return DefaultRegistry.Unmarshal(name, value)
}

func UnmarshalAll(values map[string]json.RawMessage) (Claims, error) {
	defaultRegistryMutex.RLock()
	defer defaultRegistryMutex.RUnlock()

	return DefaultRegistry.UnmarshalAll(values)
}
