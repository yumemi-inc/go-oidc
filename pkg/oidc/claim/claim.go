package claim

import (
	"encoding/json"
)

type Claim interface {
	json.Marshaler
}

type Claims map[string]Claim
