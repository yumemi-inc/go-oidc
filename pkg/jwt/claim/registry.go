package claim

import (
	"encoding/json"
	"sync"

	"github.com/samber/lo"
)

var (
	DefaultRegistry = NewRegistryWithMutex()
)

func init() {
	AddUnmarshaler[Iss](&DefaultRegistry)
	AddUnmarshaler[Sub](&DefaultRegistry)
	AddUnmarshaler[Aud](&DefaultRegistry)
	AddUnmarshaler[ClientID](&DefaultRegistry)
	AddUnmarshaler[Exp](&DefaultRegistry)
	AddUnmarshaler[Iat](&DefaultRegistry)
	AddUnmarshaler[Jti](&DefaultRegistry)
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

type Registrar interface {
	Add(name string, fn UnmarshalFunc)
	Unmarshal(name string, value json.RawMessage) (Claim, error)
	UnmarshalAll(values map[string]json.RawMessage) (Claims, error)
}

type Registry map[string]UnmarshalFunc

func AddUnmarshaler[T Claim](registry Registrar) {
	registry.Add(lo.Empty[T]().ClaimName(), Unmarshaler[T]())
}

func (r Registry) Add(name string, fn UnmarshalFunc) {
	r[name] = fn
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

type RegistryWithMutex struct {
	Registry

	mutex sync.RWMutex
}

func NewRegistryWithMutex() RegistryWithMutex {
	return RegistryWithMutex{
		Registry: make(Registry),
		mutex:    sync.RWMutex{},
	}
}

func (r *RegistryWithMutex) Clone() RegistryWithMutex {
	registry := NewRegistryWithMutex()

	for name, fn := range r.Registry {
		registry.Add(name, fn)
	}

	//goland:noinspection GoVetCopyLock
	return registry
}

func (r *RegistryWithMutex) Add(name string, fn UnmarshalFunc) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	r.Registry.Add(name, fn)
}

func (r *RegistryWithMutex) Unmarshal(name string, value json.RawMessage) (Claim, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return r.Registry.Unmarshal(name, value)
}

func (r *RegistryWithMutex) UnmarshalAll(values map[string]json.RawMessage) (Claims, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return r.Registry.UnmarshalAll(values)
}
