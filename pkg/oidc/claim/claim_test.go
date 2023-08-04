package claim

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
)

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
