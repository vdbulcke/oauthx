package oauthx

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
)

// sentinel error
var (
	ErrValidationMissingAtHash = errors.New("id_token: missing 'at_hash' claims")
)

// openid-core-spec 2. ID Token
//
//	The primary extension that OpenID Connect makes to OAuth 2.0 to
//	enable End-Users to be Authenticated is the ID Token data structure.
//	The ID Token is a security token that contains Claims about the
//	Authentication of an End-User by an Authorization Server when using a
//	Client, and potentially other requested Claims.  The ID Token is
//	represented as a JSON Web Token (JWT) [JWT].
//
// The following Claims are used within the ID Token for all OAuth 2.0
// flows used by OpenID Connect:
type IDToken struct {

	// iss
	//    REQUIRED.  Issuer Identifier for the Issuer of the response.  The
	//    "iss" value is a case-sensitive URL using the "https" scheme that
	//    contains scheme, host, and optionally, port number and path
	//    components and no query or fragment components.
	Issuer string `json:"iss,omitempty" validate:"required"`

	// sub
	//    REQUIRED.  Subject Identifier.  A locally unique and never
	//    reassigned identifier within the Issuer for the End-User, which is
	//    intended to be consumed by the Client, e.g., "24400320" or
	//    "AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4".  It MUST NOT exceed 255
	//    ASCII [RFC20] characters in length.  The "sub" value is a case-
	//    sensitive string.
	Subject string `json:"sub,omitempty" validate:"required"`

	// aud
	//    REQUIRED.  Audience(s) that this ID Token is intended for.  It
	//    MUST contain the OAuth 2.0 "client_id" of the Relying Party as an
	//    audience value.  It MAY also contain identifiers for other
	//    audiences.  In the general case, the "aud" value is an array of
	//    case-sensitive strings.  In the common special case when there is
	//    one audience, the "aud" value MAY be a single case-sensitive
	//    string.
	Audience jwt.ClaimStrings `json:"aud,omitempty" validate:"required"`

	// exp
	//    REQUIRED.  Expiration time on or after which the ID Token MUST NOT
	//    be accepted by the RP when performing authentication with the OP.
	//    The processing of this parameter requires that the current date/
	//    time MUST be before the expiration date/time listed in the value.
	//    Implementers MAY provide for some small leeway, usually no more
	//    than a few minutes, to account for clock skew.  Its value is a
	//    JSON [RFC8259] number representing the number of seconds from
	//    1970-01-01T00:00:00Z as measured in UTC until the date/time.  See
	//    RFC 3339 [RFC3339] for details regarding date/times in general and
	//    UTC in particular.  NOTE: The ID Token expiration time is
	//    unrelated the lifetime of the authenticated session between the RP
	//    and the OP.
	ExpiresAt *jwt.NumericDate `json:"exp,omitempty" validate:"required"`

	// iat
	//    REQUIRED.  Time at which the JWT was issued.  Its value is a JSON
	//    number representing the number of seconds from 1970-01-
	//    01T00:00:00Z as measured in UTC until the date/time.
	IssuedAt *jwt.NumericDate `json:"iat,omitempty" validate:"required"`

	// auth_time
	//    Time when the End-User authentication occurred.  Its value is a
	//    JSON number representing the number of seconds from 1970-01-
	//    01T00:00:00Z as measured in UTC until the date/time.  When a
	//    "max_age" request is made or when "auth_time" is requested as an
	//    Essential Claim, then this Claim is REQUIRED; otherwise, its
	//    inclusion is OPTIONAL.  (The "auth_time" Claim semantically
	//    corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] "auth_time"
	//    response parameter.)
	AuthTime *jwt.NumericDate `json:"auth_time,omitempty" `

	// nonce
	//    String value used to associate a Client session with an ID Token,
	//    and to mitigate replay attacks.  The value is passed through
	//    unmodified from the Authentication Request to the ID Token.  If
	//    present in the ID Token, Clients MUST verify that the "nonce"
	//    Claim Value is equal to the value of the "nonce" parameter sent in
	//    the Authentication Request.  If present in the Authentication
	//    Request, Authorization Servers MUST include a "nonce" Claim in the
	//    ID Token with the Claim Value being the nonce value sent in the
	//    Authentication Request.  Authorization Servers SHOULD perform no
	//    other processing on "nonce" values used.  The "nonce" value is a
	//    case-sensitive string.
	Nonce string `json:"nonce,omitempty"`

	// acr
	//    OPTIONAL.  Authentication Context Class Reference.  String
	//    specifying an Authentication Context Class Reference value that
	//    identifies the Authentication Context Class that the
	//    authentication performed satisfied.  The value "0" indicates the
	//    End-User authentication did not meet the requirements of ISO/IEC
	//    29115 [ISO29115] level 1.  For historic reasons, the value "0" is
	//    used to indicate that there is no confidence that the same person
	//    is actually there.  Authentications with level 0 SHOULD NOT be
	//    used to authorize access to any resource of any monetary value.
	//    (This corresponds to the OpenID 2.0 PAPE [OpenID.PAPE]
	//    "nist_auth_level" 0.)  An absolute URI or an RFC 6711 [RFC6711]
	//    registered name SHOULD be used as the "acr" value; registered
	//    names MUST NOT be used with a different meaning than that which is
	//    registered.  Parties using this claim will need to agree upon the
	//    meanings of the values used, which may be context specific.  The
	//    "acr" value is a case-sensitive string.
	Acr string `json:"acr,omitempty"`

	// amr
	//    OPTIONAL.  Authentication Methods References.  JSON array of
	//    strings that are identifiers for authentication methods used in
	//    the authentication.  For instance, values might indicate that both
	//    password and OTP authentication methods were used.  The "amr"
	//    value is an array of case-sensitive strings.  Values used in the
	//    "amr" Claim SHOULD be from those registered in the IANA
	//    Authentication Method Reference Values registry [IANA.AMR]
	//    established by [RFC8176]; parties using this claim will need to
	//    agree upon the meanings of any unregistered values used, which may
	//    be context specific.
	Amr []string `json:"amr,omitempty"`

	// azp
	//    OPTIONAL.  Authorized party - the party to which the ID Token was
	//    issued.  If present, it MUST contain the OAuth 2.0 Client ID of
	//    this party.  The "azp" value is a case-sensitive string containing
	//    a StringOrURI value.  Note that in practice, the "azp" Claim only
	//    occurs when extensions beyond the scope of this specification are
	//    used; therefore, implementations not using such extensions are
	//    encouraged to not use "azp" and to ignore it when it does occur.
	Azp string `json:"azp,omitempty"`

	// at_hash
	//    OPTIONAL.  Access Token hash value.  Its value is the base64url
	//    encoding of the left-most half of the hash of the octets of the
	//    ASCII representation of the "access_token" value, where the hash
	//    algorithm used is the hash algorithm used in the "alg" Header
	//    Parameter of the ID Token's JOSE Header.  For instance, if the
	//    "alg" is "RS256", hash the "access_token" value with SHA-256, then
	//    take the left-most 128 bits and base64url-encode them.  The
	//    "at_hash" value is a case-sensitive string.
	AtHash string `json:"at_hash,omitempty"`

	// other jwt standard claims

	// the `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	NotBefore *jwt.NumericDate `json:"nbf,omitempty"`

	// the `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	Jti string `json:"jti,omitempty"`

	// raw claims
	RawPayload []byte `json:"-"`
	RawHeader  []byte `json:"-"`
	RawSig     []byte `json:"-"`

	RawToken       string `json:"-"`
	RawSignedToken string `json:"-"`

	Sig jose.Signature `json:"-"`
}

// openid-core-spec 5.1.  Standard Claims
//
// This specification defines a set of standard Claims.  They can be
// requested to be returned either in the UserInfo Response, per
// Section 5.3.2, or in the ID Token, per Section 2.
type OpendIdStandardClaims struct {

	//  Subject - Identifier for the End-User at the Issuer.
	Sub string `json:"sub,omitempty"`

	// End-User's full name in displayable form including all name parts, possibly including titles and suffixes, ordered according to
	// the End-User's locale and preferences.
	Name string `json:"name,omitempty"`

	// Given name(s) or first name(s) of the End-User. Note that in some cultures, people can have multiple given names;
	// all can be present, with the names being separated by space characters.
	GivenName string `json:"given_name,omitempty"`

	// Surname(s) or last name(s) of the End-User. Note that in some cultures, people can have multiple family names or no family name;
	// all can be present, with the names being separated by space characters.
	FamilyName string `json:"family_name,omitempty"`

	// Middle name(s) of the End-User. Note that in some cultures, people can have multiple middle names; all can be present,
	// with the names being separated by space characters. Also note that in some cultures, middle names are not used.
	MiddleName string `json:"middle_name,omitempty"`

	// Casual name of the End-User that may or may not be the same as the given_name.
	Nickname string `json:"nickname,omitempty"`

	// Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe. This value MAY be any valid JSON string
	// including special characters such as @, /, or whitespace. The RP MUST NOT rely upon this value being unique, as discussed in Section 5.7.
	PreferredUsername string `json:"preferred_username,omitempty"`

	// URL of the End-User's profile page. The contents of this Web page SHOULD be about the End-User.
	Profile string `json:"profile,omitempty"`

	// URL of the End-User's profile picture. This URL MUST refer to an image file (for example, a PNG, JPEG, or GIF image file),
	// rather than to a Web page containing an image. Note that this URL SHOULD specifically reference a profile photo of the End-User
	// suitable for displaying when describing the End-User, rather than an arbitrary photo taken by the End-User.
	Picture string `json:"picture,omitempty"`

	// URL of the End-User's Web page or blog. This Web page SHOULD contain information published by the End-User or an organization
	// that the End-User is affiliated with.
	Website string `json:"website,omitempty"`

	// End-User's preferred e-mail address. Its value MUST conform to the RFC 5322 [RFC5322] addr-spec syntax.
	// The RP MUST NOT rely upon this value being unique, as discussed in Section 5.7.
	Email string `json:"email,omitempty"`

	// True if the End-User's e-mail address has been verified; otherwise false. When this Claim Value is true, this means that
	// the OP took affirmative steps to ensure that this e-mail address was controlled by the End-User at the time the
	// verification was performed. The means by which an e-mail address is verified is context specific, and dependent
	// upon the trust framework or contractual agreements within which the parties are operating.
	EmailVerified bool `json:"email_verified,omitempty"`

	// End-User's gender. Values defined by this specification are female and male.
	// Other values MAY be used when neither of the defined values are applicable.
	Gender string `json:"gender,omitempty"`

	// End-User's birthday, represented as an ISO 8601-1 [ISO8601‑1] YYYY-MM-DD format. The year MAY be 0000, indicating
	// that it is omitted. To represent only the year, YYYY format is allowed. Note that depending on the underlying
	// platform's date related function, providing just year can result in varying month and day, so the implementers
	// need to take this factor into account to correctly process the dates.
	Birthdate string `json:"birthdate,omitempty"`

	// String from IANA Time Zone Database [IANA.time‑zones] representing the End-User's time zone.
	// For example, Europe/Paris or America/Los_Angeles.
	Zoneinfo string `json:"zoneinfo,omitempty"`

	// End-User's locale, represented as a BCP47 [RFC5646] language tag. This is typically an ISO 639 Alpha-2 [ISO639] language code
	// in lowercase and an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash. For example, en-US or fr-CA.
	// As a compatibility note, some implementations have used an underscore as the separator rather than a dash, for example, en_US;
	// Relying Parties MAY choose to accept this locale syntax as well.
	Locale string `json:"locale,omitempty"`

	// End-User's preferred telephone number. E.164 [E.164] is RECOMMENDED as the format of this Claim,
	// for example, +1 (425) 555-1212 or +56 (2) 687 2400. If the phone number contains an extension,
	// it is RECOMMENDED that the extension be represented using the RFC 3966 [RFC3966] extension syntax,
	// for example, +1 (604) 555-1234;ext=5678.
	PhoneNumber string `json:"phone_number,omitempty"`

	// True if the End-User's phone number has been verified; otherwise false. When this Claim Value is true, this means that the
	// OP took affirmative steps to ensure that this phone number was controlled by the End-User at the time the verification was performed.
	// The means by which a phone number is verified is context specific, and dependent upon the trust framework or contractual agreements
	// within which the parties are operating. When true, the phone_number Claim MUST be in E.164 format and
	// any extensions MUST be represented in RFC 3966 format.
	PhoneNumberVerified bool `json:"phone_number_verified,omitempty"`

	// End-User's preferred postal address. The value of the address member is a JSON [RFC8259] structure containing
	// some or all of the members defined in Section 5.1.1.
	Address *OpenIdStandardClaimAddress `json:"address,omitempty"`

	// Time the End-User's information was last updated. Its value is a JSON number representing the number of seconds
	// from 1970-01-01T00:00:00Z as measured in UTC until the date/time.
	UpdatedAt *jwt.NumericDate `json:"updated_at,omitempty"`
}

// openid-core-spec 5.1.1.  Address Claim
//
//	The Address Claim represents a physical mailing address.
//	Implementations MAY return only a subset of the fields of an
//	"address", depending upon the information available and the End-
//	User's privacy preferences.  For example, the "country" and "region"
//	might be returned without returning more fine-grained address
//	information.
//
//
//	Implementations MAY return just the full address as a single string
//	in the formatted sub-field, or they MAY return just the individual
//	component fields using the other sub-fields, or they MAY return both.
//	If both variants are returned, they SHOULD represent the same
//	address, with the formatted address indicating how the component
//	fields are combined.
//
//	All the address values defined below are represented as JSON strings.
type OpenIdStandardClaimAddress struct {
	// Full mailing address, formatted for display or use on a mailing label. This field MAY contain multiple lines, separated by newlines.
	// Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
	Formatted string `json:"formatted,omitempty"`

	// Full street address component, which MAY include house number, street name, Post Office Box, and multi-line extended
	// street address information. This field MAY contain multiple lines, separated by newlines. Newlines can be represented either
	// as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
	StreetAddress string `json:"street_address,omitempty"`

	// City or locality component.
	Locality string `json:"locality,omitempty"`
	// State, province, prefecture, or region component.
	Region string `json:"region,omitempty"`

	// Zip code or postal code component.
	PostalCode string `json:"postal_code,omitempty"`

	// Country name component.
	Country string `json:"country,omitempty"`
}

// UnmarshallClaims [json.Unmarshal] jwt payload into
// custom claims struct.
//
// Example:
//
//	// try to parse idToken payload to extract
//	// openid standard claims set
//	var stdClaims oauthx.OpendIdStandardClaims
//	err := idToken.UnmarshallClaims(&stdClaims)
//	if err != nil {
//	    return err
//	}
func (t *IDToken) UnmarshallClaims(claims any) error {

	err := json.Unmarshal(t.RawPayload, claims)
	if err != nil {
		return fmt.Errorf("id_token: claims %w", err)
	}

	return nil
}

type IDTokenValidationFunc func(cxt context.Context, t *IDToken) error

// WithIDTokenRequiredClaimsValidation validate the [oauthx.IDToken] struct
// fields tagged as 'validate:"required"'
func WithIDTokenRequiredClaimsValidation() IDTokenValidationFunc {
	return func(ctx context.Context, t *IDToken) error {

		validate := validator.New()
		validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
			name := strings.SplitN(fld.Tag.Get("toml"), ",", 2)[0]

			if name == "-" {
				return ""
			}

			return name
		})

		err := validate.Struct(t)
		if err != nil {
			return fmt.Errorf("id_token: required claims validation %w", err)
		}

		return nil
	}
}

// WithIDTokenIssuerValidation
//  2. The Issuer Identifier for the OpenID Provider (which is
//     typically obtained during Discovery) MUST exactly match the
//     value of the "iss" (issuer) Claim.
func (c *OAuthClient) WithIDTokenIssuerValidation() IDTokenValidationFunc {
	return func(ctx context.Context, t *IDToken) error {
		if c.wk.Issuer == t.Issuer {
			return nil
		}

		return fmt.Errorf("id_token: 'iss' validation error, expected '%s' got '%s'", c.wk.Issuer, t.Issuer)
	}
}

// WithIDTokenAudianceValidation
//  3. The Client MUST validate that the "aud" (audience) Claim
//     contains its "client_id" value registered at the Issuer
//     identified by the "iss" (issuer) Claim as an audience.  The
//     "aud" (audience) Claim MAY contain an array with more than one
//     element.  The ID Token MUST be rejected if the ID Token does not
//     list the Client as a valid audience, or if it contains
//     additional audiences not trusted by the Client.
func (c *OAuthClient) WithIDTokenAudianceValidation() IDTokenValidationFunc {
	return func(ctx context.Context, t *IDToken) error {

		if slices.Contains(t.Audience, c.ClientId) {
			return nil
		}

		return fmt.Errorf("id_token: 'aud' validation error, expected '%s' in '%s'", c.ClientId, strings.Join(t.Audience, ","))
	}
}

// WithIDTokenAuthorizePartyValidation
//  4. If the implementation is using extensions (which are beyond the
//     scope of this specification) that result in the "azp"
//     (authorized party) Claim being present, it SHOULD validate the
//     "azp" value as specified by those extensions.
//  5. This validation MAY include that when an "azp" (authorized
//     party) Claim is present, the Client SHOULD verify that its
//     "client_id" is the Claim Value.
func (c *OAuthClient) WithIDTokenAuthorizePartyValidation() IDTokenValidationFunc {
	return func(ctx context.Context, t *IDToken) error {

		// azp
		//    OPTIONAL.  Authorized party - the party to which the ID Token was
		//    issued.  If present, it MUST contain the OAuth 2.0 Client ID of
		//    this party.  The "azp" value is a case-sensitive string containing
		//    a StringOrURI value.  Note that in practice, the "azp" Claim only
		//    occurs when extensions beyond the scope of this specification are
		//    used; therefore, implementations not using such extensions are
		//    encouraged to not use "azp" and to ignore it when it does occur.
		if t.Azp == c.ClientId {
			return nil
		}

		return fmt.Errorf("id_token: 'azp' validation error, expected '%s' got '%s'", c.ClientId, t.Azp)
	}
}

// WithIDTokenSignatureValidation
//  6. If the ID Token is received via direct communication between the
//     Client and the Token Endpoint (which it is in this flow), the
//     TLS server validation MAY be used to validate the issuer in
//     place of checking the token signature.  The Client MUST validate
//     the signature of all other ID Tokens according to JWS [JWS]
//     using the algorithm specified in the JWT "alg" Header Parameter.
//     The Client MUST use the keys provided by the Issuer.
//  7. The "alg" value SHOULD be the default of "RS256" or the
//     algorithm sent by the Client in the
//     "id_token_signed_response_alg" parameter during Registration.
func (c *OAuthClient) WithIDTokenSignatureValidation(overrideSupportedAlg []string) IDTokenValidationFunc {
	return func(ctx context.Context, t *IDToken) error {

		var supportedSigAlgs []jose.SignatureAlgorithm
		if len(overrideSupportedAlg) > 0 {
			for _, alg := range overrideSupportedAlg {
				supportedSigAlgs = append(supportedSigAlgs, jose.SignatureAlgorithm(alg))
			}
		} else {
			// default to provider metadata supported alg
			for _, alg := range c.wk.IDTokenSigningAlgValuesSupported {
				supportedSigAlgs = append(supportedSigAlgs, jose.SignatureAlgorithm(alg))
			}
		}

		if len(supportedSigAlgs) == 0 {
			// If no algorithms were specified by both the config and discovery, default
			// to the one mandatory algorithm "RS256".
			supportedSigAlgs = []jose.SignatureAlgorithm{jose.RS256}
		}

		jws, err := jose.ParseSigned(t.RawSignedToken, supportedSigAlgs)
		if err != nil {
			return fmt.Errorf("id_token: signature validation malformed jwt: %w", err)
		}

		// assert only one signature
		if len(jws.Signatures) != 1 {
			return fmt.Errorf("id_token: signature validation invalid signature nbr %d expected 1", len(jws.Signatures))
		}

		err = c.keySet.VerifySignature(ctx, jws)
		if err != nil {
			return fmt.Errorf("id_token: signature validation %w", err)
		}

		// set token siganture
		sig := jws.Signatures[0]
		t.Sig = sig

		return nil

	}
}

// WithIDTokenExpirationValidation
//
//  9. The current time MUST be before the time represented by the
//     "exp" Claim.
//
//  10. The "iat" Claim can be used to reject tokens that were issued
//     too far away from the current time, limiting the amount of time
//     that nonces need to be stored to prevent attacks.  The
//     acceptable range is Client specific.
func WithIDTokenExpirationValidation() IDTokenValidationFunc {
	return func(ctx context.Context, t *IDToken) error {
		now := time.Now()

		if t.ExpiresAt.Time.Before(now) {
			return fmt.Errorf("id_token: expiration 'exp' '%s' before '%s'", t.ExpiresAt.Time.String(), now.String())
		}

		if t.IssuedAt.Time.After(now) {
			return fmt.Errorf("id_token: expiration 'iat' '%s' after '%s'", t.IssuedAt.Time.String(), now.String())
		}

		return nil
	}
}

// WithIDTokenNonceValidation
//  11. If a nonce value was sent in the Authentication Request, a
//     "nonce" Claim MUST be present and its value checked to verify
//     that it is the same value as the one that was sent in the
//     Authentication Request.  The Client SHOULD check the "nonce"
//     value for replay attacks.  The precise method for detecting
//     replay attacks is Client specific.
func WithIDTokenNonceValidation(nonce string) IDTokenValidationFunc {
	return func(ctx context.Context, t *IDToken) error {
		if t.Nonce == nonce {
			return nil
		}
		return fmt.Errorf("id_token: 'nonce' validation expected '%s' got '%s'", nonce, t.Nonce)

	}
}

//  12. If the "acr" Claim was requested, the Client SHOULD check that
//     the asserted Claim Value is appropriate.  The meaning and
//     processing of "acr" Claim Values is out of scope for this
//     specification.
func WithIDTokenAcrWhitelist(whitelist []string) IDTokenValidationFunc {
	return func(ctx context.Context, t *IDToken) error {
		if slices.Contains(whitelist, t.Acr) {
			return nil
		}
		return fmt.Errorf("id_token: 'acr' validation expected '%s' in '%s'", t.Acr, strings.Join(whitelist, ","))
	}
}

// WithIDTokenAuthTimeValidation
//  13. If the "auth_time" Claim was requested, either through a
//     specific request for this Claim or by using the "max_age"
//     parameter, the Client SHOULD check the "auth_time" Claim value
//     and request re-authentication if it determines too much time has
//     elapsed since the last End-User authentication.
func WithIDTokenAuthTimeValidation(maxDuration time.Duration) IDTokenValidationFunc {
	return func(ctx context.Context, t *IDToken) error {
		now := time.Now()
		if t.AuthTime.Time.After(now.Add(-maxDuration)) {
			return fmt.Errorf("id_token: 'auth_time' validation '%s' after '%s'", t.AuthTime.Time.String(), now.Add(-maxDuration).String())
		}
		return nil
	}
}

// NewIDTokenDefaultValidation creates default validation options for IDToken validation
//   - [oauthx.WithIDTokenRequiredClaimsValidation]
//   - [OAuthClient.WithIDTokenIssuerValidation]
//   - [OAuthClient.WithIDTokenAudianceValidation]
//   - [OAuthClient.WithIDTokenSignatureValidation]
//   - [oauthx.WithIDTokenExpirationValidation]
//   - add extraOtps in the list
func (c *OAuthClient) NewIDTokenDefaultValidation(extraOpts ...IDTokenValidationFunc) []IDTokenValidationFunc {
	defaultOpts := []IDTokenValidationFunc{
		WithIDTokenRequiredClaimsValidation(),
		// 2.   The Issuer Identifier for the OpenID Provider (which is
		//    typically obtained during Discovery) MUST exactly match the
		//    value of the "iss" (issuer) Claim.
		c.WithIDTokenIssuerValidation(),
		//  3. The Client MUST validate that the "aud" (audience) Claim
		//     contains its "client_id" value registered at the Issuer
		//     identified by the "iss" (issuer) Claim as an audience.  The
		//     "aud" (audience) Claim MAY contain an array with more than one
		//     element.  The ID Token MUST be rejected if the ID Token does not
		//     list the Client as a valid audience, or if it contains
		//     additional audiences not trusted by the Client.
		c.WithIDTokenAudianceValidation(),
		//  6. If the ID Token is received via direct communication between the
		//     Client and the Token Endpoint (which it is in this flow), the
		//     TLS server validation MAY be used to validate the issuer in
		//     place of checking the token signature.  The Client MUST validate
		//     the signature of all other ID Tokens according to JWS [JWS]
		//     using the algorithm specified in the JWT "alg" Header Parameter.
		//     The Client MUST use the keys provided by the Issuer.
		//  7. The "alg" value SHOULD be the default of "RS256" or the
		//     algorithm sent by the Client in the
		//     "id_token_signed_response_alg" parameter during Registration.
		c.WithIDTokenSignatureValidation([]string{}),
		//  9. The current time MUST be before the time represented by the
		//     "exp" Claim.
		//  10. The "iat" Claim can be used to reject tokens that were issued
		//     too far away from the current time, limiting the amount of time
		//     that nonces need to be stored to prevent attacks.  The
		//     acceptable range is Client specific.
		WithIDTokenExpirationValidation(),
	}

	return append(defaultOpts, extraOpts...)
}

type IDTokenParseOptFunc func(opt *IDTokenParseOption)

type IDTokenParseOption struct {
	validationOpts    []IDTokenValidationFunc
	requireEncryption bool
}

func (c *OAuthClient) newDefaultIDTokenParseOpt() *IDTokenParseOption {

	return &IDTokenParseOption{
		validationOpts:    c.NewIDTokenDefaultValidation(),
		requireEncryption: false,
	}
}

// WithIDTokenParseOptRequiredEncryption requires the [oauthx.IDToken] to
// be encrypted and supported by the [oauthx.OAuthPrivateKey] for this client
func WithIDTokenParseOptRequiredEncryption() IDTokenParseOptFunc {
	return func(opt *IDTokenParseOption) {
		opt.requireEncryption = true
	}
}

// WithIDTokenParseOptExtraValidation adds extra validation to
// default validations [oauthx.NewIDTokenDefaultValidation]
func WithIDTokenParseOptExtraValidation(extra ...IDTokenValidationFunc) IDTokenParseOptFunc {
	return func(opt *IDTokenParseOption) {
		opt.validationOpts = append(opt.validationOpts, extra...)
	}
}

// WithIDTokenParseOptCustomValidation replace defaults validations
// with the validationOpts
func WithIDTokenParseOptCustomValidation(validationOpts ...IDTokenValidationFunc) IDTokenParseOptFunc {
	return func(opt *IDTokenParseOption) {
		opt.validationOpts = validationOpts
	}
}

// ParseIDToken parse and validate the idToken string, using
// [OAuthClient.NewIDTokenDefaultValidation] by default or
// override validation options from the parseOpts
func (c *OAuthClient) ParseIDToken(ctx context.Context, idToken string, parseOpts ...IDTokenParseOptFunc) (*IDToken, error) {
	rawToken := idToken

	opt := c.newDefaultIDTokenParseOpt()

	for _, fn := range parseOpts {
		fn(opt)
	}

	header, err := getJwtHeader(idToken)
	if err != nil {
		return nil, fmt.Errorf("id_token: parse header %w", err)
	}

	var algHeader jwtHeader
	err = json.Unmarshal(header, &algHeader)
	if err != nil {
		return nil, fmt.Errorf("id_token: parse json header %w", err)
	}

	// 3.1.3.7.  ID Token Validation

	//    Clients MUST validate the ID Token in the Token Response in the
	//    following manner:

	// 1.   If the ID Token is encrypted, decrypt it using the keys and
	//      algorithms that the Client specified during Registration that
	//      the OP was to use to encrypt the ID Token.  If encryption was
	//      negotiated with the OP at Registration time and the ID Token is
	//      not encrypted, the RP SHOULD reject it.
	idToken, err = c.decryptJwtOrEcho(idToken, algHeader.Alg, opt.requireEncryption)
	if err != nil {
		return nil, fmt.Errorf("id_token: decryption %w", err)
	}

	payload, err := getJwtPayload(idToken)
	if err != nil {
		return nil, fmt.Errorf("id_token: parse jwt payload %w", err)
	}

	sig, err := getJwtSig(idToken)
	if err != nil {
		return nil, fmt.Errorf("id_token: parse jwt sig %w", err)
	}

	var token IDToken
	err = json.Unmarshal(payload, &token)
	if err != nil {
		return nil, fmt.Errorf("id_token: parse json payload %w", err)
	}

	token.RawHeader = header
	token.RawPayload = payload
	token.RawSig = sig
	token.RawToken = rawToken
	token.RawSignedToken = idToken

	// apply validations functions
	for _, validationFunc := range opt.validationOpts {
		err = validationFunc(ctx, &token)
		if err != nil {
			// return the token to still have
			// access to the Raw properties
			return &token, err
		}
	}

	return &token, nil
}

// Validate apply the [oauthx.IDTokenValidationFunc] validation opts in order
func (t *IDToken) Validate(ctx context.Context, opts ...IDTokenValidationFunc) error {

	// apply validations functions
	for _, validationFunc := range opts {
		err := validationFunc(ctx, t)
		if err != nil {
			// return the token to still have
			// access to the Raw properties
			return fmt.Errorf("id_token: validation %w", err)
		}
	}
	return nil
}

func (c *OAuthClient) decryptJwtOrEcho(idToken string, alg string, requireEnc bool) (decryptedJwt string, err error) {

	if requireEnc && c.privateKey == nil {
		return decryptedJwt, errors.New("id_token: encryption required but privateKey is nil")
	}

	if requireEnc && !c.privateKey.SupportedDecryptAlg(alg) {
		return decryptedJwt, fmt.Errorf("id_token: encryption required but privateKey does not support alg: %s", alg)
	}

	if c.privateKey != nil && c.privateKey.SupportedDecryptAlg(alg) {

		decryptedJwt, err = c.privateKey.DecryptJWT(idToken, alg)
		if err == nil {
			return decryptedJwt, nil
		}

		// if err != nil && requireEnc {
		// 	return decryptedJwt, err
		// }
		if err != nil {
			return decryptedJwt, err
		}
	}

	// if decryption key does not support alg
	// the jwt was only signed
	// echo back the jwt
	return idToken, nil
}

// ValidateAccessTokenHash validate 'at_hash' claim
// at_hash
//
//	OPTIONAL.  Access Token hash value.  Its value is the base64url
//	encoding of the left-most half of the hash of the octets of the
//	ASCII representation of the "access_token" value, where the hash
//	algorithm used is the hash algorithm used in the "alg" Header
//	Parameter of the ID Token's JOSE Header.  For instance, if the
//	"alg" is "RS256", hash the "access_token" value with SHA-256, then
//	take the left-most 128 bits and base64url-encode them.  The
//	"at_hash" value is a case-sensitive string.
func (t *IDToken) ValidateAccessTokenHash(accessToken string) error {
	if t.AtHash == "" {
		return ErrValidationMissingAtHash
	}

	var h hash.Hash
	switch t.Sig.Header.Algorithm {
	case string(jose.RS256), string(jose.ES256), string(jose.PS256):
		h = sha256.New()
	case string(jose.RS384), string(jose.ES384), string(jose.PS384):
		h = sha512.New384()
	case string(jose.RS512), string(jose.ES512), string(jose.PS512):
		h = sha512.New()

	default:
		return fmt.Errorf("id_token: unsupported alg %s", t.Sig.Header.Algorithm)
	}

	computed := GenerateAtHash(accessToken, h)
	if t.AtHash != computed {
		return fmt.Errorf("id_token: validation error expected 'at_hash' %s got %s", t.AtHash, computed)
	}

	return nil
}

// GenerateAtHash generate the at_hash claim
//
//	at_hash
//
//		OPTIONAL.  Access Token hash value.  Its value is the base64url
//		encoding of the left-most half of the hash of the octets of the
//		ASCII representation of the "access_token" value, where the hash
//		algorithm used is the hash algorithm used in the "alg" Header
//		Parameter of the ID Token's JOSE Header.  For instance, if the
//		"alg" is "RS256", hash the "access_token" value with SHA-256, then
//		take the left-most 128 bits and base64url-encode them.  The
//		"at_hash" value is a case-sensitive string.
func GenerateAtHash(accessToken string, h hash.Hash) string {
	// the octets of the ASCII representation of the "access_token" value
	accessTokenBytes := []byte(accessToken)

	// the hash of the octets
	_, _ = h.Write(accessTokenBytes)
	hashedToken := h.Sum(nil)
	// the left-most half of the hash
	half := hashedToken[:h.Size()/2]

	// the base64url encoding of the left-most half
	return base64.RawURLEncoding.EncodeToString(half)
}

type jwtHeader struct {
	Alg string
}

func getJwtHeader(token string) ([]byte, error) {

	parts := strings.Split(token, ".")

	// header must be the first part
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt: malformed jwt header: %w", err)
	}

	return header, nil
}

// from coreos/go-oidc
func getJwtPayload(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("jwt: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: malformed jwt payload: %v", err)
	}
	return payload, nil
}

func getJwtSig(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("jwt: malformed jwt, expected 3 parts got %d", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt: malformed jwt sig: %v", err)
	}
	return sig, nil
}
