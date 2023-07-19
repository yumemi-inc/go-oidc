package validation

type Error struct {
	Errors map[string]error
}

func NewError() *Error {
	return &Error{
		Errors: make(map[string]error),
	}
}

func (e *Error) IsEmpty() bool {
	return len(e.Errors) == 0
}

func (e *Error) Set(key string, err error) {
	e.Errors[key] = err
}

func (e *Error) Error() string {
	return "validation failed"
}
