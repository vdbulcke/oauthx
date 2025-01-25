package oauthx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vdbulcke/oauthx/assert"
	"github.com/vdbulcke/oauthx/metric"
	"github.com/vdbulcke/oauthx/tracing"
)

// 2.2.  Introspection Response
type IntrospectionResponse struct {
	// active
	//    REQUIRED.  Boolean indicator of whether or not the presented token
	//    is currently active.  The specifics of a token's "active" state
	//    will vary depending on the implementation of the authorization
	//    server and the information it keeps about its tokens, but a "true"
	//    value return for the "active" property will generally indicate
	//    that a given token has been issued by this authorization server,
	//    has not been revoked by the resource owner, and is within its
	//    given time window of validity (e.g., after its issuance time and
	//    before its expiration time).  See Section 4 for information on
	//    implementation of such checks.
	Active bool `json:"active"`

	// scope
	//    OPTIONAL.  A JSON string containing a space-separated list of
	//    scopes associated with this token, in the format described in
	//    Section 3.3 of OAuth 2.0 [RFC6749].
	Scope string `json:"scope,omitempty"`

	// client_id
	//    OPTIONAL.  Client identifier for the OAuth 2.0 client that
	//    requested this token.
	ClientId string `json:"client_id,omitempty"`

	// username
	//    OPTIONAL.  Human-readable identifier for the resource owner who
	//    authorized this token.
	Username string `json:"username,omitempty"`

	// token_type
	//    OPTIONAL.  Type of the token as defined in Section 5.1 of OAuth
	//    2.0 [RFC6749].
	TokenType string `json:"token_type,omitempty"`

	// exp
	//    OPTIONAL.  Integer timestamp, measured in the number of seconds
	//    since January 1 1970 UTC, indicating when this token will expire,
	//    as defined in JWT [RFC7519].
	ExpiresAt *jwt.NumericDate `json:"exp,omitempty" `

	// iat
	//    OPTIONAL.  Integer timestamp, measured in the number of seconds
	//    since January 1 1970 UTC, indicating when this token was
	//    originally issued, as defined in JWT [RFC7519].
	IssuedAt *jwt.NumericDate `json:"iat,omitempty" `

	// nbf
	//    OPTIONAL.  Integer timestamp, measured in the number of seconds
	//    since January 1 1970 UTC, indicating when this token is not to be
	//    used before, as defined in JWT [RFC7519].
	NotBefore *jwt.NumericDate `json:"nbf,omitempty"`

	// sub
	//    OPTIONAL.  Subject of the token, as defined in JWT [RFC7519].
	//    Usually a machine-readable identifier of the resource owner who
	//    authorized this token.
	Subject string `json:"sub,omitempty"`

	// aud
	//    OPTIONAL.  Service-specific string identifier or list of string
	//    identifiers representing the intended audience for this token, as
	//    defined in JWT [RFC7519].
	Audience jwt.ClaimStrings `json:"aud,omitempty"`

	// iss
	//    OPTIONAL.  String representing the issuer of this token, as
	//    defined in JWT [RFC7519].
	Issuer string `json:"iss,omitempty"`

	// jti
	//    OPTIONAL.  String identifier for the token, as defined in JWT
	//    [RFC7519].
	Jti string `json:"jti,omitempty"`

	// raw claims
	RawPayload []byte `json:"-"`
	RawHeader  []byte `json:"-"`
	RawSig     []byte `json:"-"`

	RawToken       string `json:"-"`
	RawSignedToken string `json:"-"`

	Sig jose.Signature `json:"-"`
}

func (r *IntrospectionResponse) UnmarshallClaims(claims any) error {

	err := json.Unmarshal(r.RawPayload, claims)
	if err != nil {
		return fmt.Errorf("introspection: claims %w", err)
	}

	return nil
}

type IntrospectionStandardClaims struct {
	// active
	//    REQUIRED.  Boolean indicator of whether or not the presented token
	//    is currently active.  The specifics of a token's "active" state
	//    will vary depending on the implementation of the authorization
	//    server and the information it keeps about its tokens, but a "true"
	//    value return for the "active" property will generally indicate
	//    that a given token has been issued by this authorization server,
	//    has not been revoked by the resource owner, and is within its
	//    given time window of validity (e.g., after its issuance time and
	//    before its expiration time).  See Section 4 for information on
	//    implementation of such checks.
	Active bool `json:"active"`

	// scope
	//    OPTIONAL.  A JSON string containing a space-separated list of
	//    scopes associated with this token, in the format described in
	//    Section 3.3 of OAuth 2.0 [RFC6749].
	Scope string `json:"scope,omitempty"`

	// client_id
	//    OPTIONAL.  Client identifier for the OAuth 2.0 client that
	//    requested this token.
	ClientId string `json:"client_id,omitempty"`

	// username
	//    OPTIONAL.  Human-readable identifier for the resource owner who
	//    authorized this token.
	Username string `json:"username,omitempty"`

	// token_type
	//    OPTIONAL.  Type of the token as defined in Section 5.1 of OAuth
	//    2.0 [RFC6749].
	TokenType string `json:"token_type,omitempty"`

	// exp
	//    OPTIONAL.  Integer timestamp, measured in the number of seconds
	//    since January 1 1970 UTC, indicating when this token will expire,
	//    as defined in JWT [RFC7519].
	ExpiresAt *jwt.NumericDate `json:"exp,omitempty" `

	// iat
	//    OPTIONAL.  Integer timestamp, measured in the number of seconds
	//    since January 1 1970 UTC, indicating when this token was
	//    originally issued, as defined in JWT [RFC7519].
	IssuedAt *jwt.NumericDate `json:"iat,omitempty" `

	// nbf
	//    OPTIONAL.  Integer timestamp, measured in the number of seconds
	//    since January 1 1970 UTC, indicating when this token is not to be
	//    used before, as defined in JWT [RFC7519].
	NotBefore *jwt.NumericDate `json:"nbf,omitempty"`

	// sub
	//    OPTIONAL.  Subject of the token, as defined in JWT [RFC7519].
	//    Usually a machine-readable identifier of the resource owner who
	//    authorized this token.
	Subject string `json:"sub,omitempty"`

	// aud
	//    OPTIONAL.  Service-specific string identifier or list of string
	//    identifiers representing the intended audience for this token, as
	//    defined in JWT [RFC7519].
	Audience jwt.ClaimStrings `json:"aud,omitempty"`

	// iss
	//    OPTIONAL.  String representing the issuer of this token, as
	//    defined in JWT [RFC7519].
	Issuer string `json:"iss,omitempty"`

	// jti
	//    OPTIONAL.  String identifier for the token, as defined in JWT
	//    [RFC7519].
	Jti string `json:"jti,omitempty"`
}

type introspectResponseRequireClaims struct {
	Active bool `json:"active"`
}

type IntrospectionParseOptFunc func(opt *IntrospectionParseOption)

func WithIntrospectionParseRequiredEncryption() IntrospectionParseOptFunc {
	return func(opt *IntrospectionParseOption) {
		opt.requireEnc = true
	}
}

func WithIntrospectionParseRequiredSignature() IntrospectionParseOptFunc {
	return func(opt *IntrospectionParseOption) {
		opt.requireSign = true
	}
}

func WithIntrospectionParseDisableSignClaimValidation() IntrospectionParseOptFunc {
	return func(opt *IntrospectionParseOption) {
		opt.disableSignClaimValidation = true
	}
}

func WithIntrospectionParseIgnoreStdClaims() IntrospectionParseOptFunc {
	return func(opt *IntrospectionParseOption) {
		opt.ignoreStdClaims = true
	}
}

func WithIntrospectionParseOverrideSupportedSigAlg(alg []string) IntrospectionParseOptFunc {
	return func(opt *IntrospectionParseOption) {
		opt.overrideSupportedSigAlg = alg
	}
}

type IntrospectionParseOption struct {
	requireEnc                 bool
	ignoreStdClaims            bool
	requireSign                bool
	disableSignClaimValidation bool
	overrideSupportedSigAlg    []string
}

func newDefaultIntrospectionParseOption() *IntrospectionParseOption {
	return &IntrospectionParseOption{
		requireEnc:                 false,
		requireSign:                false,
		ignoreStdClaims:            false,
		disableSignClaimValidation: false,
		overrideSupportedSigAlg:    []string{},
	}
}

// DoIntrospectionRequest
//
// Example:
//
//	// create new introspect request
//	req := oauthx.NewIntrospectionRequest(
//	    oauthx.TokenOpt(token), // the token to introspect
//	)
//	// make introspect request with the OAuthClient client
//	// using the default opts
//	resp, err := client.DoIntrospectionRequest(ctx, req)
//	if err != nil {
//	    // handle err
//	    return err
//	}
//
// Implements rfc7662,  draft-ietf-oauth-jwt-introspection-response-03
func (c *OAuthClient) DoIntrospectionRequest(ctx context.Context, r *IntrospectionRequest, opts ...IntrospectionParseOptFunc) (*IntrospectionResponse, error) {
	assert.NotNil(ctx, assert.Panic, "oauth-client: 'ctx' cannot be nil")
	assert.NotNil(r, assert.Panic, "oauth-client: 'RevokeRequest' cannot be nil")

	params, err := c.PlumbingGenerateIntrospectionRequestParam(r)
	if err != nil {
		return nil, err
	}

	req, err := c.PlumbingNewHttpIntrospectionRequest(params)
	if err != nil {
		return nil, err
	}

	return c.PlumbingDoHttpIntrospectionRequest(ctx, req, opts...)
}

func (c *OAuthClient) PlumbingGenerateIntrospectionRequestParam(req *IntrospectionRequest) (url.Values, error) {

	params := url.Values{}
	for _, opt := range req.opts {
		opt.SetValue(params)

	}

	return params, nil
}

func (c *OAuthClient) PlumbingNewHttpIntrospectionRequest(params url.Values) (*http.Request, error) {
	assert.NotNil(c.authmethod, assert.Panic, "oauth-client: missing required 'authmethod'")
	assert.NotNil(params, assert.Panic, "oauth-client: params cannot be nil")
	assert.StrNotEmpty(c.wk.IntrospectionEndpoint, assert.Panic, "oauth-client: missing 'introspection_endpoint'")

	return c.authmethod.NewOAuthAuthenticatedRequest(IntrospectionEndpoint, c.wk.IntrospectionEndpoint, params)
}

func (c *OAuthClient) PlumbingDoHttpIntrospectionRequest(ctx context.Context, req *http.Request, opts ...IntrospectionParseOptFunc) (_ *IntrospectionResponse, err error) {
	assert.NotNil(ctx, assert.Panic, "oauth-client: 'ctx' cannot be nil")
	assert.NotNil(req, assert.Panic, "oauth-client: 'req' cannot be nil")

	endpoint := "introspection"
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		metric.OAuthDurationHist.WithLabelValues(endpoint).Observe(v)
	}))
	defer timer.ObserveDuration()
	defer metric.DeferMonitorError(endpoint, &err)

	tracing.AddHeadersFromContext(ctx, req)

	opt := newDefaultIntrospectionParseOption()
	for _, fn := range opts {
		fn(opt)
	}

	resp, err := c.http.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.http.maxSizeBytes))
	if err != nil {
		err = fmt.Errorf("rfc7662: %w", err)
		return nil, err
	}

	httpErr := &HttpErr{
		StatusCode:     resp.StatusCode,
		RespBody:       body,
		ResponseHeader: resp.Header,
	}

	if len(body) >= int(c.http.maxSizeBytes) {
		err = fmt.Errorf("http-limit: http resp body max size limit exceeded: %d bytes", c.http.maxSizeBytes)
		httpErr.Err = err
		return nil, httpErr
	}

	// NOTE: although not explicitly specified in rfc7662
	// if reasonable to expect 200 OK status code
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("rfc7662: expected status code %d but got '%d'", http.StatusOK, resp.StatusCode)
		httpErr.Err = err
		return nil, httpErr
	}

	introspection := &IntrospectionResponse{}

	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch ct {

	// draft-ietf-oauth-jwt-introspection-response-03
	// 2.  Requesting a JWT Response

	//    A resource server requests to receive a JWT introspection response by
	//    including an Accept header with content type "application/jwt" in the
	//    introspection request.
	case "application/jwt":

		payload, err := c.decryptIntrospect(introspection, body, opt)
		if err != nil {
			httpErr.Err = err
			return nil, httpErr
		}

		// Depending on the specific resource server policy the JWT is either
		// signed, or signed and encrypted.  If the JWT is signed and encrypted
		// it MUST be a Nested JWT, as defined in JWT [RFC7519].
		payload, err = c.verifyIntrospectionSignature(ctx, introspection, payload, opt)
		if err != nil {
			httpErr.Err = err
			return nil, httpErr
		}

		introspection.RawPayload = payload

	case "application/json":
		if opt.requireSign {

			err = fmt.Errorf("rfc7662: expected content-type 'application/jwt'  but got '%s'", ct)
			httpErr.Err = err
			return nil, httpErr
		}

		introspection.RawPayload = body
	default:
		err = fmt.Errorf("rfc7662: expected content-type 'application/jwt' or 'application/json'  but got '%s'", ct)
		httpErr.Err = err
		return nil, httpErr
	}

	// validate require claims
	var requiredClaim introspectResponseRequireClaims
	err = json.Unmarshal(introspection.RawPayload, &requiredClaim)
	if err != nil {
		httpErr.Err = err
		return nil, httpErr
	}

	introspection.Active = requiredClaim.Active

	var stdClaims IntrospectionStandardClaims
	err = json.Unmarshal(introspection.RawPayload, &stdClaims)
	if err != nil {
		if opt.ignoreStdClaims {
			return introspection, nil
		}

		httpErr.Err = err
		return nil, httpErr
	}

	introspection.Audience = stdClaims.Audience
	introspection.ClientId = stdClaims.ClientId
	introspection.ExpiresAt = stdClaims.ExpiresAt
	introspection.IssuedAt = stdClaims.IssuedAt
	introspection.Issuer = stdClaims.Issuer
	introspection.Jti = stdClaims.Jti
	introspection.NotBefore = stdClaims.NotBefore
	introspection.Scope = stdClaims.Scope
	introspection.Subject = stdClaims.Subject
	introspection.TokenType = stdClaims.TokenType
	introspection.Username = stdClaims.Username

	return introspection, nil
}

func (c *OAuthClient) verifyIntrospectionSignature(ctx context.Context, r *IntrospectionResponse, body []byte, opt *IntrospectionParseOption) (payload []byte, err error) {
	// check if the token was already encrypted
	encrypted := r.RawToken != ""

	token := string(body)
	header, err := getJwtHeader(token)
	if err != nil {
		// if already encrypted the body could
		// be the payload of the jwt
		// this allowed only encrytped jwt without nested jwt
		if encrypted && !opt.requireSign {
			return body, nil
		}

		return nil, fmt.Errorf("draft-ietf-oauth-jwt-introspection-response-03: parse header %w", err)
	}

	payload, err = getJwtPayload(token)
	if err != nil {
		return nil, fmt.Errorf("draft-ietf-oauth-jwt-introspection-response-03: parse jwt payload %w", err)
	}

	rawsig, err := getJwtSig(token)
	if err != nil {
		return nil, fmt.Errorf("draft-ietf-oauth-jwt-introspection-response-03: parse jwt sig %w", err)
	}

	var supportedSigAlgs []jose.SignatureAlgorithm
	if len(opt.overrideSupportedSigAlg) > 0 {
		for _, alg := range opt.overrideSupportedSigAlg {
			supportedSigAlgs = append(supportedSigAlgs, jose.SignatureAlgorithm(alg))
		}
	} else {
		// default to provider metadata supported alg
		for _, alg := range c.wk.IntrospectionEndpointAuthSigningAlgValuesSupported {
			supportedSigAlgs = append(supportedSigAlgs, jose.SignatureAlgorithm(alg))
		}
	}

	if len(supportedSigAlgs) == 0 {
		// If no algorithms were specified by both the config and discovery, default
		// to the one mandatory algorithm "RS256".
		supportedSigAlgs = []jose.SignatureAlgorithm{jose.RS256}
	}

	jws, err := jose.ParseSigned(token, supportedSigAlgs)
	if err != nil {
		return nil, fmt.Errorf("draft-ietf-oauth-jwt-introspection-response-03: signature validation malformed jwt: %w", err)
	}

	// assert only one signature
	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("draft-ietf-oauth-jwt-introspection-response-03: signature validation invalid signature nbr %d expected 1", len(jws.Signatures))
	}

	err = c.keySet.VerifySignature(ctx, jws)
	if err != nil {
		return nil, fmt.Errorf("draft-ietf-oauth-jwt-introspection-response-03: signature validation %w", err)
	}

	// Such an attack can be prevented like any other token substitution
	// attack.  The authorization server MUST include the claims "iss" and
	// "aud" in each JWT introspection response, with the "iss" value set to
	// the authorization server's issuer URL and the "aud" value set to the
	// resource server's identifier.
	if !opt.disableSignClaimValidation {
		var claims introspectionSignRequiredClaim
		if err = json.Unmarshal(payload, &claims); err != nil {
			return nil, fmt.Errorf("draft-ietf-oauth-jwt-introspection-response-03: signature validation required claims %w", err)
		}

		if claims.Issuer != c.wk.Issuer {
			return nil, fmt.Errorf("draft-ietf-oauth-jwt-introspection-response-03: invalid 'iss' expected '%s' got '%s' ", c.wk.Issuer, claims.Issuer)

		}

		if !slices.Contains(claims.Audiance, c.ClientId) {
			return nil, fmt.Errorf("draft-ietf-oauth-jwt-introspection-response-03: invalid 'aud' expected %s in [%s] ", c.ClientId, strings.Join(claims.Audiance, ","))
		}
	}

	// set token siganture
	sig := jws.Signatures[0]

	r.RawHeader = header
	r.RawPayload = payload
	r.RawSig = rawsig
	r.Sig = sig

	return payload, nil
}

func (c *OAuthClient) decryptIntrospect(r *IntrospectionResponse, body []byte, opt *IntrospectionParseOption) (payload []byte, err error) {

	token := string(body)
	header, err := getJwtHeader(token)
	if err != nil {
		return nil, fmt.Errorf("draft-ietf-oauth-jwt-introspection-response-03: parse header %w", err)
	}

	var algHeader jwtHeader
	err = json.Unmarshal(header, &algHeader)
	if err != nil {
		return nil, fmt.Errorf("draft-ietf-oauth-jwt-introspection-response-03: parse json header %w", err)
	}
	alg := algHeader.Alg

	if opt.requireEnc && c.privateKey == nil {
		return nil, errors.New("draft-ietf-oauth-jwt-introspection-response-03: encryption required but privateKey is nil")
	}

	if opt.requireEnc && !c.privateKey.SupportedDecryptAlg(alg) {
		return nil, fmt.Errorf("draft-ietf-oauth-jwt-introspection-response-03: encryption required but privateKey does not support alg: %s", alg)
	}

	if c.privateKey != nil && c.privateKey.SupportedDecryptAlg(alg) {

		decryptedJwt, err := c.privateKey.DecryptJWT(token, alg)
		if err == nil {
			r.RawHeader = header
			r.RawToken = token
			return []byte(decryptedJwt), nil
		}

		// if err != nil && requireEnc {
		// 	return decryptedJwt, err
		// }
		if err != nil {
			return nil, err
		}
	}

	// if decryption key does not support alg
	// the jwt was only signed
	// echo back the jwt
	return body, nil
}

// Such an attack can be prevented like any other token substitution
// attack.  The authorization server MUST include the claims "iss" and
// "aud" in each JWT introspection response, with the "iss" value set to
// the authorization server's issuer URL and the "aud" value set to the
// resource server's identifier.
type introspectionSignRequiredClaim struct {
	Issuer   string           `json:"iss"`
	Audiance jwt.ClaimStrings `json:"aud"`
}
