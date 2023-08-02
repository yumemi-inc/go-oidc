package authz

type Response struct {
	Code  string  `form:"code"`
	State *string `form:"state,omitempty"`
}

func NewResponse(code string) Response {
	return Response{
		Code: code,
	}
}

func (r Response) WithState(state string) Response {
	r.State = &state

	return r
}
