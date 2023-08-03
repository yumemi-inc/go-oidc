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

func TestLocalizedClaim_ClaimName(t *testing.T) {
	claim := LocalizedClaim[FamilyName]{
		Claim:  "たなか",
		Locale: "ja-Kana-JP",
	}

	assert.Equal(t, "family_name#ja-Kana-JP", claim.ClaimName())
}

func TestLocalizedClaim_MarshalJSON(t *testing.T) {
	claim := LocalizedClaim[FamilyName]{
		Claim:  "たなか",
		Locale: "ja-Kana-JP",
	}

	assert.JSONEq(t, `"たなか"`, string(lo.Must(claim.MarshalJSON())))
}
