package oauthx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vdbulcke/assert"
	"github.com/vdbulcke/oauthx/metric"
	"github.com/vdbulcke/oauthx/tracing"
)

type Userinfo struct {
	//    The "sub" (subject) Claim MUST always be returned in the UserInfo
	Sub string `json:"sub,omitempty" validate:"required"`

	// raw properties
	RawPayload []byte `json:"-"`

	// if as jwt
	RawHeader []byte `json:"-"`
	RawSig    []byte `json:"-"`

	RawToken       string `json:"-"`
	RawSignedToken string `json:"-"`

	Sig jose.Signature `json:"-"`
}

func (u *Userinfo) UnmarshallClaims(claims any) error {

	err := json.Unmarshal(u.RawPayload, claims)
	if err != nil {
		return fmt.Errorf("userinfo: claims %w", err)
	}

	return nil
}

type UserinfoParseOptFunc func(opt *UserinfoParseOption)

func WithUserinfoParseRequiredEncryption() UserinfoParseOptFunc {
	return func(opt *UserinfoParseOption) {
		opt.requireEnc = true
	}
}

func WithUserinfoParseRequiredSignature() UserinfoParseOptFunc {
	return func(opt *UserinfoParseOption) {
		opt.requireSign = true
	}
}
func WithUserinfoParseDisableSignClaimValidation() UserinfoParseOptFunc {
	return func(opt *UserinfoParseOption) {
		opt.disableSignClaimValidation = true
	}
}

func WithUserinfoParseOverrideSupportedSigAlg(alg []string) UserinfoParseOptFunc {
	return func(opt *UserinfoParseOption) {
		opt.overrideSupportedSigAlg = alg
	}
}

type UserinfoParseOption struct {
	requireEnc                 bool
	requireSign                bool
	disableSignClaimValidation bool
	overrideSupportedSigAlg    []string
}

func newDefaultUserinfoParseOption() *UserinfoParseOption {
	return &UserinfoParseOption{
		requireEnc:                 false,
		requireSign:                false,
		disableSignClaimValidation: false,
		overrideSupportedSigAlg:    []string{},
	}
}

// 5.3.1.  UserInfo Request
//
//	The Client sends the UserInfo Request using either HTTP "GET" or HTTP
//	"POST".  The Access Token obtained from an OpenID Connect
//	Authentication Request MUST be sent as a Bearer Token, per Section 2
//	of OAuth 2.0 Bearer Token Usage [RFC6750].
//
//	It is RECOMMENDED that the request use the HTTP "GET" method and the
//	Access Token be sent using the "Authorization" header field.
//
// Use  'oauthx.WithUserinfoHttpMethod(http.MethodPost)' when creating OAuthClient
// to use POST instead of GET method when calling userinfo
//
// 5.3.2.  Successful UserInfo Response
//
//	The UserInfo Claims MUST be returned as the members of a JSON object
//	unless a signed or encrypted response was requested during Client
//	Registration.  The Claims defined in Section 5.1 can be returned, as
//	can additional Claims not specified there.
//
//	For privacy reasons, OpenID Providers MAY elect to not return values
//	for some requested Claims.  It is not an error condition to not
//	return a requested Claim.
//
//	If a Claim is not returned, that Claim Name SHOULD be omitted from
//	the JSON object representing the Claims; it SHOULD NOT be present
//	with a null or empty string value.
//
//	The "sub" (subject) Claim MUST always be returned in the UserInfo
//	Response.
//
//	Upon receipt of the UserInfo Request, the UserInfo Endpoint MUST
//	return the JSON Serialization of the UserInfo Response as in
//	Section 13.3 in the HTTP response body unless a different format was
//	specified during Registration [OpenID.Registration].  The UserInfo
//	Endpoint MUST return a content-type header to indicate which format
//	is being returned.  The content-type of the HTTP response MUST be
//	"application/json" if the response body is a text JSON object; the
//	response body SHOULD be encoded using UTF-8.
//
//	If the UserInfo Response is signed and/or encrypted, then the Claims
//	are returned in a JWT and the content-type MUST be "application/jwt".
//	The response MAY be encrypted without also being signed.  If both
//	signing and encryption are requested, the response MUST be signed
//	then encrypted, with the result being a Nested JWT, as defined in
//	[JWT].
//
// Use 'oauthx.WithUserinfoParseRequiredEncryption()' and/or
// 'oauthx.WithUserinfoParseRequiredSignature()' to required jwt
// encrypted and/or signed.
//
//	If signed, the UserInfo Response MUST contain the Claims "iss"
//	(issuer) and "aud" (audience) as members.  The "iss" value MUST be
//	the OP's Issuer Identifier URL.  The "aud" value MUST be or include
//	the RP's Client ID value.
//
// Use 'oauthx.WithUserinfoParseDisableSignClaimValidation()' to disbale
// 'iss' and 'aud' claims validation
func (c *OAuthClient) DoUserinfoRequest(ctx context.Context, accessToken string, opts ...UserinfoParseOptFunc) (*Userinfo, error) {

	req, err := c.PlumbingNewHttpUserinfoRequest(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	return c.PlumbingDoHttpUserinfoRequest(ctx, req, opts...)
}

func (c *OAuthClient) PlumbingNewHttpUserinfoRequest(ctx context.Context, accessToken string) (*http.Request, error) {
	assert.NotNil(c.wk, assert.Panic, "userinfo: wellknown cannot be nil")
	assert.StrNotEmpty(c.wk.UserinfoEndpoint, assert.Panic, "userinfo: 'userinfo_endpoint' cannot be empty")

	req, err := http.NewRequestWithContext(ctx, c.userinfoHttpMethod, c.wk.UserinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	return req, nil
}

func (c *OAuthClient) PlumbingDoHttpUserinfoRequest(ctx context.Context, req *http.Request, opts ...UserinfoParseOptFunc) (_ *Userinfo, err error) {
	assert.NotNil(ctx, assert.Panic, "oauth-client: 'ctx' cannot be nil")
	assert.NotNil(req, assert.Panic, "oauth-client: 'req' cannot be nil")

	endpoint := "userinfo"
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		metric.OAuthDurationHist.WithLabelValues(endpoint).Observe(v)
	}))
	defer timer.ObserveDuration()
	defer metric.DeferMonitorError(endpoint, &err)

	tracing.AddHeadersFromContext(ctx, req)

	opt := newDefaultUserinfoParseOption()
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
		err = fmt.Errorf("userinfo: %w", err)
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

	// NOTE: although not explicitly specified in openid core spec
	// if reasonable to expect 200 OK status code
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("userinfo: expected status code %d but got '%d'", http.StatusOK, resp.StatusCode)
		httpErr.Err = err
		return nil, httpErr
	}

	userinfo := &Userinfo{}

	// The UserInfo Endpoint MUST return a content-type header
	// to indicate which format is being returned.
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch ct {

	// If the UserInfo Response is signed and/or encrypted, then the Claims
	// are returned in a JWT and the content-type MUST be "application/jwt".
	case "application/jwt":

		// 5.3.4.  UserInfo Response Validation

		// 2.  If the Client has provided a "userinfo_encrypted_response_alg"
		//     parameter during Registration, decrypt the UserInfo Response
		//     using the keys specified during Registration.
		payload, err := c.decryptUserinfo(userinfo, body, opt)
		if err != nil {
			httpErr.Err = err
			return nil, httpErr
		}

		// 3.  If the response was signed, the Client SHOULD validate the
		//     signature according to JWS [JWS].
		payload, err = c.verifyUserinfoSignature(ctx, userinfo, payload, opt)
		if err != nil {
			httpErr.Err = err
			return nil, httpErr
		}

		userinfo.RawPayload = payload

	case "application/json":
		if opt.requireSign {

			err = fmt.Errorf("userinfo: expected content-type 'application/jwt'  but got '%s'", ct)
			httpErr.Err = err
			return nil, httpErr
		}

		userinfo.RawPayload = body
	default:
		err = fmt.Errorf("userinfo: expected content-type 'application/jwt' or 'application/json'  but got '%s'", ct)
		httpErr.Err = err
		return nil, httpErr
	}

	var claims userinfoRequireClaims
	err = json.Unmarshal(userinfo.RawPayload, &claims)
	if err != nil {
		return nil, fmt.Errorf("userinfo: invalid format %w", err)
	}

	userinfo.Sub = claims.Sub

	return userinfo, nil
}

func (c *OAuthClient) verifyUserinfoSignature(ctx context.Context, u *Userinfo, body []byte, opt *UserinfoParseOption) (payload []byte, err error) {
	// check if the token was already encrypted
	encrypted := u.RawToken != ""

	token := string(body)
	header, err := getJwtHeader(token)
	if err != nil {
		// if already encrypted the body could
		// be the payload of the jwt
		// this allowed only encrytped jwt without nested jwt
		if encrypted && !opt.requireSign {
			return body, nil
		}

		return nil, fmt.Errorf("userinfo: parse header %w", err)
	}

	payload, err = getJwtPayload(token)
	if err != nil {
		return nil, fmt.Errorf("userinfo: parse jwt payload %w", err)
	}

	rawsig, err := getJwtSig(token)
	if err != nil {
		return nil, fmt.Errorf("userinfo: parse jwt sig %w", err)
	}

	var supportedSigAlgs []jose.SignatureAlgorithm
	if len(opt.overrideSupportedSigAlg) > 0 {
		for _, alg := range opt.overrideSupportedSigAlg {
			supportedSigAlgs = append(supportedSigAlgs, jose.SignatureAlgorithm(alg))
		}
	} else {
		// default to provider metadata supported alg
		for _, alg := range c.wk.UserinfoSigningAlgValuesSupported {
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
		return nil, fmt.Errorf("userinfo: signature validation malformed jwt: %w", err)
	}

	// assert only one signature
	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("userinfo: signature validation invalid signature nbr %d expected 1", len(jws.Signatures))
	}

	err = c.keySet.VerifySignature(ctx, jws)
	if err != nil {
		return nil, fmt.Errorf("userinfo: signature validation %w", err)
	}

	// If signed, the UserInfo Response MUST contain the Claims "iss"
	// (issuer) and "aud" (audience) as members.  The "iss" value MUST be
	// the OP's Issuer Identifier URL.  The "aud" value MUST be or include
	// the RP's Client ID value.
	if !opt.disableSignClaimValidation {
		var claims userinfoSignRequiredClaim
		if err = json.Unmarshal(payload, &claims); err != nil {
			return nil, fmt.Errorf("userinfo: signature validation required claims %w", err)
		}

		if claims.Issuer != c.wk.Issuer {
			return nil, fmt.Errorf("userinfo: invalid 'iss' expected %s got %s ", c.wk.Issuer, claims.Issuer)

		}

		if !slices.Contains(claims.Audiance, c.ClientId) {
			return nil, fmt.Errorf("userinfo: invalid 'aud' expected %s in [%s] ", c.ClientId, strings.Join(claims.Audiance, ","))
		}
	}

	// set token siganture
	sig := jws.Signatures[0]

	u.RawHeader = header
	u.RawPayload = payload
	u.RawSig = rawsig
	u.Sig = sig

	return payload, nil
}

func (c *OAuthClient) decryptUserinfo(u *Userinfo, body []byte, opt *UserinfoParseOption) (payload []byte, err error) {

	token := string(body)
	header, err := getJwtHeader(token)
	if err != nil {
		return nil, fmt.Errorf("userinfo: parse header %w", err)
	}

	var algHeader jwtHeader
	err = json.Unmarshal(header, &algHeader)
	if err != nil {
		return nil, fmt.Errorf("userinfo: parse json header %w", err)
	}
	alg := algHeader.Alg

	if opt.requireEnc && c.privateKey == nil {
		return nil, errors.New("userinfo: encryption required but privateKey is nil")
	}

	if opt.requireEnc && !c.privateKey.SupportedDecryptAlg(alg) {
		return nil, fmt.Errorf("userinfo: encryption required but privateKey does not support alg: %s", alg)
	}

	if c.privateKey != nil && c.privateKey.SupportedDecryptAlg(alg) {

		decryptedJwt, err := c.privateKey.DecryptJWT(token, alg)
		if err == nil {
			u.RawHeader = header
			u.RawToken = token
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

type userinfoRequireClaims struct {
	Sub string `json:"sub"`
}

//	If signed, the UserInfo Response MUST contain the Claims "iss"
//
// (issuer) and "aud" (audience) as members.  The "iss" value MUST be
// the OP's Issuer Identifier URL.  The "aud" value MUST be or include
// the RP's Client ID value.
type userinfoSignRequiredClaim struct {
	Issuer   string           `json:"iss"`
	Audiance jwt.ClaimStrings `json:"aud"`
}
