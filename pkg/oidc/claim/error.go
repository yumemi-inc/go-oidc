package claim

type MalformedClaimError struct {
	Err error
}

func (e *MalformedClaimError) Error() string {
	return e.Err.Error()
}
