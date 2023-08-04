package claim

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
)

func TestClaims_MarshalJSON(t *testing.T) {
	claims := NewClaims().
		With(Iss("https://id.example.com/")).
		With(Sub("user1")).
		With(NewAud([]string{"client1"}))

	assert.JSONEq(
		t,
		`{"aud":["client1"],"iss":"https://id.example.com/","sub":"user1"}`,
		string(lo.Must(claims.MarshalJSON())),
	)
}
