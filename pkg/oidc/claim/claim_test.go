package claim

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
)

func TestClaims_MarshalJSON(t *testing.T) {
	claims := NewClaims().
		With(lo.Must(IssFromStr("https://id.example.com/"))).
		With(lo.Must(NewSub("user1"))).
		With(NewAud([]string{"client1"}))

	assert.JSONEq(
		t,
		`{"aud":["client1"],"iss":"https://id.example.com/","sub":"user1"}`,
		string(lo.Must(claims.MarshalJSON())),
	)
}
