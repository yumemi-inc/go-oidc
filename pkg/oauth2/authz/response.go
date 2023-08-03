package authz

import (
	"net/http"
	"net/url"

	form "github.com/yumemi-inc/go-encoding-form"
)

type Response struct {
	Code  string  `form:"code"`
	State *string `form:"state,omitempty"`
}

func NewResponse(code string) Response {
	return Response{
		Code: code,
	}
}

func (r *Response) SetState(state *string) *Response {
	r.State = state

	return r
}

func (r *Response) WithState(state string) *Response {
	return r.SetState(&state)
}

func (r *Response) WriteAsRedirect(w http.ResponseWriter, redirectURI url.URL) error {
	values, err := form.Normalize(r)
	if err != nil {
		return err
	}

	q := redirectURI.Query()
	for name, value := range values {
		for _, v := range value {
			q.Add(name, v)
		}
	}

	redirectURI.RawQuery = q.Encode()

	w.Header().Set("Location", redirectURI.String())
	w.WriteHeader(http.StatusFound)

	return nil
}
