package assertion

type ClientAssertionType string

const ClientAssertionTypeBearer ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

type ClientAssertion struct {
	ClientAssertionType *ClientAssertionType `form:"client_assertion_type"`
	ClientAssertion     *string              `form:"client_assertion"`
}

func (c *ClientAssertion) Assert() {

}
