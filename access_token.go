package oauthx

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
)

// rfc9068
//
// 2.2.  Data Structure
//
// The following claims are used in the JWT access token data structure.
type JwtAccessToken struct {
	// iss as defined in Section 4.1.1 of [RFC7519].
	Issuer string `json:"iss,omitempty" validate:"required"`

	// exp  REQUIRED - as defined in Section 4.1.4 of [RFC7519].
	ExpiresAt *jwt.NumericDate `json:"exp,omitempty" validate:"required"`

	// aud  REQUIRED - as defined in Section 4.1.3 of [RFC7519].  See
	//    Section 3 for indications on how an authorization server should
	//    determine the value of "aud" depending on the request.
	Audience jwt.ClaimStrings `json:"aud,omitempty" validate:"required"`

	// sub  REQUIRED - as defined in Section 4.1.2 of [RFC7519].  In cases
	//    of access tokens obtained through grants where a resource owner is
	//    involved, such as the authorization code grant, the value of "sub"
	//    SHOULD correspond to the subject identifier of the resource owner.
	//    In cases of access tokens obtained through grants where no
	//    resource owner is involved, such as the client credentials grant,
	//    the value of "sub" SHOULD correspond to an identifier the
	//    authorization server uses to indicate the client application.  See
	//    Section 5 for more details on this scenario.  Also, see Section 6
	//    for a discussion about how different choices in assigning "sub"
	//    values can impact privacy.
	Subject string `json:"sub,omitempty" validate:"required"`

	// client_id  REQUIRED - as defined in Section 4.3 of [RFC8693].
	ClientId string `json:"client_id,omitempty" validate:"required"`

	// iat  REQUIRED - as defined in Section 4.1.6 of [RFC7519].  This claim
	//    identifies the time at which the JWT access token was issued.
	IssuedAt *jwt.NumericDate `json:"iat,omitempty" validate:"required"`

	// jti  REQUIRED - as defined in Section 4.1.7 of [RFC7519].
	Jti string `json:"jti,omitempty" validate:"required"`

	// internal props

	RawPayload []byte `json:"-"`
	RawHeader  []byte `json:"-"`
	RawSig     []byte `json:"-"`

	RawToken       string `json:"-"`
	RawSignedToken string `json:"-"`

	Sig jose.Signature `json:"-"`
}

// rfc9068
//
// 2.2.1.  Authentication Information Claims
type JwtAccessTokenAuthenticationInformationClaims struct {

	// auth_time  OPTIONAL - as defined in Section 2 of [OpenID.Core].
	AuthTime *jwt.NumericDate `json:"auth_time,omitempty" `

	// acr  OPTIONAL - as defined in Section 2 of [OpenID.Core].
	Acr string `json:"acr,omitempty"`

	// amr  OPTIONAL - as defined in Section 2 of [OpenID.Core].
	Amr []string `json:"amr,omitempty"`
}

// rfc9068
//
// 2.2.3.  Authorization Claims
//
// If an authorization request includes a scope parameter, the
// corresponding issued JWT access token SHOULD include a "scope" claim
// as defined in Section 4.2 of [RFC8693].
//
// All the individual scope strings in the "scope" claim MUST have
// meaning for the resources indicated in the "aud" claim.  See
// Section 5 for more considerations about the relationship between
// scope strings and resources indicated by the "aud" claim.
type JwtAccessTokenAuthorizationClaims struct {

	// rfc8963 - 4.2. "scope" (Scopes) Claim
	// The value of the scope claim is a JSON string containing a space-separated list of scopes associated with the token, in the format described in Section 3.3 of [RFC6749].
	Scope string `json:"scope,omitempty"`
}

type JwtAccessTokenValidationFunc func(ctx context.Context, at *JwtAccessToken, opt *JwtAccessTokenParseOption) error

//   - The resource server MUST verify that the "typ" header value is
//     "at+jwt" or "application/at+jwt" and reject tokens carrying any
//     other value.
func JwtAccessTokenValidateHeaderType() JwtAccessTokenValidationFunc {
	return func(ctx context.Context, at *JwtAccessToken, opt *JwtAccessTokenParseOption) error {

		var algHeader jwtHeader
		err := json.Unmarshal(at.RawHeader, &algHeader)
		if err != nil {
			return fmt.Errorf("rfc9068: parse json header %w", err)
		}

		if algHeader.Type == "at+jwt" || algHeader.Type == "application/at+jwt" {
			return nil
		}

		return fmt.Errorf("rfc9068: unsupported header type '%s'", algHeader.Type)
	}
}

//   - If the JWT access token is encrypted, decrypt it using the keys
//     and algorithms that the resource server specified during
//     registration.  If encryption was negotiated with the authorization
//     server at registration time and the incoming JWT access token is
//     not encrypted, the resource server SHOULD reject it.
func (c *OAuthClient) JwtAccessTokenValidateEncrypted() JwtAccessTokenValidationFunc {
	return func(ctx context.Context, at *JwtAccessToken, opt *JwtAccessTokenParseOption) error {

		var atHeader jwtHeader
		err := json.Unmarshal(at.RawHeader, &atHeader)
		if err != nil {
			return fmt.Errorf("rfc9068: parse json header %w", err)
		}

		alg := atHeader.Alg

		if opt.RequireEncryption && c.privateKey == nil {
			return fmt.Errorf("rfc9068: encryption required but privateKey is nil")
		}

		if opt.RequireEncryption && !c.privateKey.SupportedDecryptAlg(alg) {
			return fmt.Errorf("rfc9068: encryption required but privateKey does not support alg: %s", alg)
		}

		// if no key or the key is no supported
		// just assume this is a signed jwt
		if c.privateKey == nil || !c.privateKey.SupportedDecryptAlg(alg) {
			return nil
		}

		decryptedJwt, err := c.privateKey.DecryptJWT(at.RawToken, alg)
		if err == nil {
			// update access token
			at.RawSignedToken = decryptedJwt
			return nil
		}

		if opt.RequireEncryption {
			return fmt.Errorf("rfc9068: decryption failed %w", err)
		}

		return nil
	}
}

//   - The issuer identifier for the authorization server (which is
//     typically obtained during discovery) MUST exactly match the value
//     of the "iss" claim.
func (c *OAuthClient) JwtAccessTokenValidateIssuer() JwtAccessTokenValidationFunc {
	return func(ctx context.Context, at *JwtAccessToken, opt *JwtAccessTokenParseOption) error {

		if at.Issuer == c.wk.Issuer {
			return nil
		}

		return fmt.Errorf("rfc9068: 'iss' validation error, expected '%s' got '%s'", c.wk.Issuer, at.Issuer)
	}
}

// decode jwt payload, and signature
func JwtAccessTokenValidatePayload() JwtAccessTokenValidationFunc {
	return func(ctx context.Context, at *JwtAccessToken, opt *JwtAccessTokenParseOption) error {

		payload, err := getJwtPayload(at.RawSignedToken)
		if err != nil {
			return fmt.Errorf("rfc9068: parse jwt payload %w", err)
		}

		sig, err := getJwtSig(at.RawSignedToken)
		if err != nil {
			return fmt.Errorf("rfc9068: parse jwt sig %w", err)
		}

		at.RawPayload = payload
		at.RawSig = sig

		err = json.Unmarshal(payload, at)
		if err != nil {
			return fmt.Errorf("rfc9068: parse jwt payload %w", err)
		}

		return nil
	}
}

// validate required field from payload
func JwtAccessTokenValidateRequiredFields() JwtAccessTokenValidationFunc {
	return func(ctx context.Context, at *JwtAccessToken, opt *JwtAccessTokenParseOption) error {

		validate := validator.New()
		validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
			name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]

			if name == "-" {
				return ""
			}

			return name
		})

		err := validate.Struct(at)
		if err != nil {
			return fmt.Errorf("rfc9068: required claims validation %w", err)
		}
		return nil
	}
}

//   - The current time MUST be before the time represented by the "exp"
//     claim.  Implementers MAY provide for some small leeway, usually no
//     more than a few minutes, to account for clock skew.
func JwtAccessTokenValidatExpiration() JwtAccessTokenValidationFunc {
	return func(ctx context.Context, at *JwtAccessToken, opt *JwtAccessTokenParseOption) error {

		now := time.Now()

		if at.ExpiresAt.Before(now.Add(-opt.clockSkew)) {
			return fmt.Errorf("id_token: expiration 'exp' '%s' before '%s'", at.ExpiresAt.String(), now.String())
		}

		if at.IssuedAt.After(now.Add(opt.clockSkew)) {
			return fmt.Errorf("id_token: expiration 'iat' '%s' after '%s'", at.IssuedAt.String(), now.String())
		}

		return nil
	}
}

//   - The resource server MUST validate that the "aud" claim contains a
//     resource indicator value corresponding to an identifier the
//     resource server expects for itself.  The JWT access token MUST be
//     rejected if "aud" does not contain a resource indicator of the
//     current resource server as a valid audience.
func (c *OAuthClient) JwtAccessTokenValidateAudiance() JwtAccessTokenValidationFunc {
	return func(ctx context.Context, at *JwtAccessToken, opt *JwtAccessTokenParseOption) error {

		if slices.Contains(at.Audience, c.ClientId) {
			return nil
		}

		return fmt.Errorf("rfc9068: 'aud' validation error, expected '%s' in '%s'", c.ClientId, strings.Join(at.Audience, ","))
	}
}

func (c *OAuthClient) JwtAccessTokenValidateSignature() JwtAccessTokenValidationFunc {
	return func(ctx context.Context, at *JwtAccessToken, opt *JwtAccessTokenParseOption) error {

		var supportedSigAlgs []jose.SignatureAlgorithm
		if len(opt.overrideSupportedAlg) > 0 {
			for _, alg := range opt.overrideSupportedAlg {
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

		jws, err := jose.ParseSigned(at.RawSignedToken, supportedSigAlgs)
		if err != nil {
			return fmt.Errorf("rfc9068: signature validation malformed jwt: %w", err)
		}

		// assert only one signature
		if len(jws.Signatures) != 1 {
			return fmt.Errorf("rfc9068: signature validation invalid signature nbr %d expected 1", len(jws.Signatures))
		}

		err = c.keySet.VerifySignature(ctx, jws)
		if err != nil {
			return fmt.Errorf("rfc9068: signature validation %w", err)
		}

		// set token siganture
		sig := jws.Signatures[0]
		at.Sig = sig

		return nil
	}
}

type JwtAccessTokenParseOpts func(opt *JwtAccessTokenParseOption)
type JwtAccessTokenParseOption struct {
	RequireEncryption    bool
	overrideSupportedAlg []string
	clockSkew            time.Duration
	validationFunc       []JwtAccessTokenValidationFunc
}

func WithJwtAccessTokenRequiredEncryption() JwtAccessTokenParseOpts {
	return func(opt *JwtAccessTokenParseOption) {
		opt.RequireEncryption = true
	}
}

func WithJwtAccessTokenSupportedAlg(alg []string) JwtAccessTokenParseOpts {
	return func(opt *JwtAccessTokenParseOption) {
		opt.overrideSupportedAlg = alg
	}
}

func WithJwtAccessTokenClockSkew(skew time.Duration) JwtAccessTokenParseOpts {
	return func(opt *JwtAccessTokenParseOption) {
		opt.clockSkew = skew
	}
}

func WithJwtAccessTokenCustomValidation(validations []JwtAccessTokenValidationFunc) JwtAccessTokenParseOpts {
	return func(opt *JwtAccessTokenParseOption) {
		opt.validationFunc = validations
	}
}

// NewDefaultJwtAccessTokenParseOption default rfc9368 parse option
func (c *OAuthClient) NewDefaultJwtAccessTokenParseOption() *JwtAccessTokenParseOption {
	return &JwtAccessTokenParseOption{
		RequireEncryption:    false,
		overrideSupportedAlg: []string{},
		clockSkew:            0,
		validationFunc: []JwtAccessTokenValidationFunc{

			// *  The resource server MUST verify that the "typ" header value is
			//    "at+jwt" or "application/at+jwt" and reject tokens carrying any
			//    other value.
			JwtAccessTokenValidateHeaderType(),

			// *  If the JWT access token is encrypted, decrypt it using the keys
			//    and algorithms that the resource server specified during
			//    registration.  If encryption was negotiated with the authorization
			//    server at registration time and the incoming JWT access token is
			//    not encrypted, the resource server SHOULD reject it.
			c.JwtAccessTokenValidateEncrypted(),

			JwtAccessTokenValidatePayload(),
			JwtAccessTokenValidateRequiredFields(),

			// *  The issuer identifier for the authorization server (which is
			//    typically obtained during discovery) MUST exactly match the value
			//    of the "iss" claim.
			c.JwtAccessTokenValidateIssuer(),

			// *  The resource server MUST validate that the "aud" claim contains a
			//    resource indicator value corresponding to an identifier the
			//    resource server expects for itself.  The JWT access token MUST be
			//    rejected if "aud" does not contain a resource indicator of the
			//    current resource server as a valid audience.
			c.JwtAccessTokenValidateAudiance(),

			// *  The resource server MUST validate the signature of all incoming
			//    JWT access tokens according to [RFC7515] using the algorithm
			//    specified in the JWT "alg" Header Parameter.  The resource server
			//    MUST reject any JWT in which the value of "alg" is "none".  The
			//    resource server MUST use the keys provided by the authorization
			//    server.
			c.JwtAccessTokenValidateSignature(),

			// *  The current time MUST be before the time represented by the "exp"
			//    claim.  Implementers MAY provide for some small leeway, usually no
			//    more than a few minutes, to account for clock skew.
			JwtAccessTokenValidatExpiration(),
		},
	}
}

// ParseJwtAccessToken parse and validate acess_token based on rfc9068
func (c *OAuthClient) ParseJwtAccessToken(ctx context.Context, token string, opts ...JwtAccessTokenParseOpts) (*JwtAccessToken, error) {
	rawToken := token

	options := c.NewDefaultJwtAccessTokenParseOption()
	for _, fn := range opts {
		fn(options)
	}

	header, err := getJwtHeader(token)
	if err != nil {
		return nil, fmt.Errorf("rfc9068: parse header %w", err)
	}

	accessToken := &JwtAccessToken{
		// start with both RawToken and RawSignedToken
		// with the input. The RawSignedToken may get updated
		// by Encryption validation (Nested JWT)
		RawToken:       rawToken,
		RawSignedToken: rawToken,
		RawHeader:      header,
	}

	for _, fn := range options.validationFunc {
		err = fn(ctx, accessToken, options)
		if err != nil {
			return nil, fmt.Errorf("rfc9068: validation failed %w", err)
		}
	}

	return accessToken, nil

}
