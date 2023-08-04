package claim

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/samber/lo"

	"github.com/yumemi-inc/go-oidc/pkg/jwt/claim"
)

const (
	SubMaxLength = 255
)

var (
	ErrIssScheme          = errors.New("scheme of issuer URL must be https")
	ErrIssQueryOrFragment = errors.New("issuer URL must not have query or fragment")
	ErrSubLength          = errors.New("subject must not exceed 255 ASCII characters in length")
	ErrBirthdateMalformed = errors.New("malformed birthdate")
)

type Aud = claim.Aud
type Exp = claim.Exp
type Iat = claim.Iat

// Iss is the identifier for the issuer.
type Iss url.URL

func NewIss(u url.URL) (*Iss, error) {
	if u.Scheme != "https" {
		return nil, ErrIssScheme
	}

	if u.RawQuery != "" || u.RawFragment != "" {
		return nil, ErrIssQueryOrFragment
	}

	return lo.ToPtr(Iss(u)), nil
}

func IssFromStr(s string) (*Iss, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	return NewIss(*u)
}

func (c Iss) ClaimName() string {
	return "iss"
}

func (c Iss) String() string {
	u := url.URL(c)

	return u.String()
}

func (c Iss) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c *Iss) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	p, err := IssFromStr(s)
	if err != nil {
		return err
	}

	*c = *p

	return nil
}

// Sub is the subject identifier.
type Sub string

func NewSub(s string) (*Sub, error) {
	if len(s) > SubMaxLength {
		return nil, ErrSubLength
	}

	return lo.ToPtr(Sub(s)), nil
}

func (c Sub) ClaimName() string {
	return "sub"
}

// AuthTime is the time when the end-user authentication occurred.
type AuthTime time.Time

func NewAuthTime(t time.Time) *AuthTime {
	return lo.ToPtr(AuthTime(t))
}

func AuthTimeFromInt64(i int64) *AuthTime {
	return NewAuthTime(time.Unix(i, 0))
}

func (c AuthTime) ClaimName() string {
	return "auth_time"
}

// Nonce is a string value used to associate a client session with the token, and to mitigate replay attacks.
type Nonce string

func NewNonce(s string) *Nonce {
	return lo.ToPtr(Nonce(s))
}

func (c Nonce) ClaimName() string {
	return "nonce"
}

// Acr is the authentication context class reference.
type Acr string

func NewAcr(s string) *Acr {
	return lo.ToPtr(Acr(s))
}

func (c Acr) ClaimName() string {
	return "acr"
}

// Amr is the authentication methods references.
type Amr []string

func NewAmr(s []string) *Amr {
	return lo.ToPtr[Amr](s)
}

func (c Amr) ClaimName() string {
	return "amr"
}

// Azp is the authorized party - the party to which the token was issued.
type Azp string

func NewAzp(s string) *Azp {
	return lo.ToPtr(Azp(s))
}

func (c Azp) ClaimName() string {
	return "azp"
}

// Name is End-User's full name in displayable form including all name parts, possibly including titles and
// suffixes, ordered according to the End-User's locale and preferences.
type Name string

func NewName(s string) (*Name, error) {
	return lo.ToPtr(Name(s)), nil
}

func (c Name) ClaimName() string {
	return "name"
}

// GivenName is given name(s) or first name(s) of the End-User. Note that in some cultures, people can have multiple
// given names; all can be present, with the names being separated by space characters.
type GivenName string

func NewGivenName(s string) (*GivenName, error) {
	return lo.ToPtr(GivenName(s)), nil
}

func (c GivenName) ClaimName() string {
	return "given_name"
}

// FamilyName is surname(s) or last name(s) of the End-User. Note that in some cultures, people can have multiple family
// names or no family name; all can be present, with the names being separated by space characters.
type FamilyName string

func NewFamilyName(s string) (*FamilyName, error) {
	return lo.ToPtr(FamilyName(s)), nil
}

func (c FamilyName) ClaimName() string {
	return "family_name"
}

// MiddleName is middle name(s) of the End-User. Note that in some cultures, people can have multiple middle names; all
// can be present, with the names being separated by space characters. Also note that in some cultures, middle names are
// not used.
type MiddleName string

func NewMiddleName(s string) (*MiddleName, error) {
	return lo.ToPtr(MiddleName(s)), nil
}

func (c MiddleName) ClaimName() string {
	return "middle_name"
}

// Nickname is casual name of the End-User that may or may not be the same as the given_name. For instance, a nickname
// value of Mike might be returned alongside a given_name value of Michael.
type Nickname string

func NewNickname(s string) (*Nickname, error) {
	return lo.ToPtr(Nickname(s)), nil
}

func (c Nickname) ClaimName() string {
	return "nickname"
}

// PreferredUsername is shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or
// j.doe. This value MAY be any valid JSON string including special characters such as @, /, or whitespace. The RP MUST
// NOT rely upon this value being unique, as discussed in Section 5.7.
type PreferredUsername string

func NewPreferredUsername(s string) (*PreferredUsername, error) {
	return lo.ToPtr(PreferredUsername(s)), nil
}

func (c PreferredUsername) ClaimName() string {
	return "preferred_username"
}

// Profile is URL of the End-User's profile page. The contents of this Web page SHOULD be about the End-User.
type Profile url.URL

func NewProfile(u url.URL) (*Profile, error) {
	return lo.ToPtr(Profile(u)), nil
}

func ProfileFromStr(s string) (*Profile, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	return NewProfile(*u)
}

func (c Profile) ClaimName() string {
	return "profile"
}

func (c Profile) String() string {
	u := url.URL(c)

	return u.String()
}

func (c Profile) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c *Profile) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	p, err := ProfileFromStr(s)
	if err != nil {
		return err
	}

	*c = *p

	return nil
}

// Picture is URL of the End-User's profile picture. This URL MUST refer to an image file (for example, a PNG, JPEG, or
// GIF image file), rather than to a Web page containing an image. Note that this URL SHOULD specifically reference a
// profile photo of the End-User suitable for displaying when describing the End-User, rather than an arbitrary photo
// taken by the End-User.
type Picture url.URL

func NewPicture(u url.URL) (*Picture, error) {
	return lo.ToPtr(Picture(u)), nil
}

func PictureFromStr(s string) (*Picture, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	return NewPicture(*u)
}

func (c Picture) ClaimName() string {
	return "picture"
}

func (c Picture) String() string {
	u := url.URL(c)

	return u.String()
}

func (c Picture) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c *Picture) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	p, err := PictureFromStr(s)
	if err != nil {
		return err
	}

	*c = *p

	return nil
}

// Website is URL of the End-User's Web page or blog. This Web page SHOULD contain information published by the End-User
// or an organization that the End-User is affiliated with.
type Website url.URL

func NewWebsite(u url.URL) (*Website, error) {
	return lo.ToPtr(Website(u)), nil
}

func WebsiteFromStr(s string) (*Website, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	return NewWebsite(*u)
}

func (c Website) ClaimName() string {
	return "website"
}

func (c Website) String() string {
	u := url.URL(c)

	return u.String()
}

func (c Website) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c *Website) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	p, err := WebsiteFromStr(s)
	if err != nil {
		return err
	}

	*c = *p

	return nil
}

// Email is URL of the End-User's email page. The contents of this Web page SHOULD be about the End-User.
type Email string

func NewEmail(s string) (*Email, error) {
	// TODO: AuthenticateClient against RFC 5322 addr-spec syntax
	return lo.ToPtr(Email(s)), nil
}

func (c Email) ClaimName() string {
	return "email"
}

// EmailVerified represents End-User at the time the verification was performed. The means by which an e-mail address is
// verified is context-specific, and dependent upon the trust framework or contractual agreements within which the
// parties are operating.
type EmailVerified bool

func NewEmailVerified(b bool) (*EmailVerified, error) {
	return lo.ToPtr(EmailVerified(b)), nil
}

func (c EmailVerified) ClaimName() string {
	return "email_verified"
}

// Gender is End-User's gender. Values defined by this specification are female and male. Other values MAY be used when
// neither of the defined values are applicable.
type Gender string

const (
	GenderMale   Gender = "male"
	GenderFemale Gender = "female"
)

func NewGender(s string) (*Gender, error) {
	return lo.ToPtr(Gender(s)), nil
}

func (c Gender) ClaimName() string {
	return "gender"
}

// Birthdate is End-User's birthday, represented as an ISO 8601:2004 YYYY-MM-DD format. The year MAY be 0000, indicating
// that it is omitted. To represent only the year, YYYY format is allowed. Note that depending on the underlying
// platform's date related function, providing just year can result in varying month and day, so the implementers need
// to take this factor into account to correctly process the dates.
type Birthdate struct {
	Year       uint
	Month      uint
	DayOfMonth uint
}

func NewBirthdate(y, m, d uint) (*Birthdate, error) {
	return &Birthdate{
		Year:       y,
		Month:      m,
		DayOfMonth: d,
	}, nil
}

func NewBirthdateOnlyYear(y uint) (*Birthdate, error) {
	return NewBirthdate(y, 0, 0)
}

func NewBirthdateFromStr(s string) (*Birthdate, error) {
	var y, m, d uint
	if _, err := fmt.Sscanf(s, "%04d-%02d-%02d", &y, &m, &d); err == nil {
		return NewBirthdate(y, m, d)
	} else if _, err := fmt.Sscanf(s, "%04d", &y); err != nil {
		return NewBirthdateOnlyYear(y)
	}

	return nil, ErrBirthdateMalformed
}

func (c Birthdate) ClaimName() string {
	return "birthdate"
}

func (c Birthdate) String() string {
	return fmt.Sprintf("%04d-%02d-%02d", c.Year, c.Month, c.DayOfMonth)
}

func (c Birthdate) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

// Zoneinfo is string from zoneinfo time zone database representing the End-User's time zone. For example, Europe/Paris
// or America/Los_Angeles.
type Zoneinfo string

func NewZoneinfo(s string) (*Zoneinfo, error) {
	return lo.ToPtr(Zoneinfo(s)), nil
}

func (c Zoneinfo) ClaimName() string {
	return "zoneinfo"
}

// Locale is End-User's locale, represented as a BCP47 language tag. This is typically an ISO 639-1 Alpha-2 language
// code in lowercase and an ISO 3166-1 Alpha-2 country code in uppercase, separated by a dash. For example, en-US or
// fr-CA. As a compatibility note, some implementations have used an underscore as the separator rather than a dash, for
// example, en_US; Relying Parties MAY choose to accept this locale syntax as well.
type Locale string

func NewLocale(s string) (*Locale, error) {
	return lo.ToPtr(Locale(s)), nil
}

func (c Locale) ClaimName() string {
	return "locale"
}

// PhoneNumber is End-User's preferred telephone number. E.164 is RECOMMENDED as the format of this Claim, for example,
// +1 (425) 555-1212 or +56 (2) 687 2400. If the phone number contains an extension, it is RECOMMENDED that the
// extension be represented using the RFC 3966 [RFC3966] extension syntax, for example, +1 (604) 555-1234;ext=5678.
type PhoneNumber string

func NewPhoneNumber(s string) (*PhoneNumber, error) {
	return lo.ToPtr(PhoneNumber(s)), nil
}

func (c PhoneNumber) ClaimName() string {
	return "phone_number"
}

// PhoneNumberVerified is true if the End-User's phone number has been verified; otherwise false. When this Claim Value
// is true, this means that the OP took affirmative steps to ensure that this phone number was controlled by the
// End-User at the time the verification was performed. The means by which a phone number is verified is
// context-specific, and dependent upon the trust framework or contractual agreements within which the parties are
// operating. When true, the phone_number Claim MUST be in E.164 format and any extensions MUST be represented in
// RFC 3966 format.
type PhoneNumberVerified bool

func NewPhoneNumberVerified(b bool) (*PhoneNumberVerified, error) {
	return lo.ToPtr(PhoneNumberVerified(b)), nil
}

func (c PhoneNumberVerified) ClaimName() string {
	return "phone_number_verified"
}

type Address struct {
	// Formatted is full mailing address, formatted for display or use on a mailing label. This field MAY contain
	// multiple lines, separated by newlines. Newlines can be represented either as a carriage return/line feed pair
	// ("\r\n") or as a single line feed character ("\n").
	Formatted string `json:"formatted,omitempty"`

	// StreetAddress is full street address component, which MAY include house number, street name, Post Office Box, and
	// multi-line extended street address information. This field MAY contain multiple lines, separated by newlines.
	// Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed
	// character ("\n").
	StreetAddress string `json:"street_address,omitempty"`

	// Locality is city or locality component.
	Locality string `json:"locality,omitempty"`

	// Region is state, province, prefecture, or region component.
	Region string `json:"region,omitempty"`

	// PostalCode is zip code or postal code component.
	PostalCode string `json:"postal_code,omitempty"`

	// Country is country name component.
	Country string `json:"country,omitempty"`
}

// UpdatedAt is time the End-User's information was last updated. Its value is a JSON number representing the number
// of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
type UpdatedAt time.Time

func NewUpdatedAt(t time.Time) (*UpdatedAt, error) {
	return lo.ToPtr(UpdatedAt(t)), nil
}

func UpdatedAtFromInt64(i int64) (*UpdatedAt, error) {
	return NewUpdatedAt(time.Unix(i, 0))
}

func (c UpdatedAt) Int64() int64 {
	return time.Time(c).Unix()
}

func (c UpdatedAt) ClaimName() string {
	return "updated_at"
}

func (c UpdatedAt) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.Int64())
}

func (c *UpdatedAt) UnmarshalJSON(data []byte) error {
	var i int64
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}

	p, err := UpdatedAtFromInt64(i)
	if err != nil {
		return err
	}

	*c = *p

	return nil
}
