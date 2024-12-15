package oauthx

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/vdbulcke/oauthx/assert"
)

const (
	TokenTypeAccessToken  = "access_token"
	TokenTypeRefreshToken = "refresh_token"
)

type OAuthContext struct {
	ClientId         string `json:"client_id"`
	Nonce            string `json:"nonce"`
	State            string `json:"state"`
	PKCECodeVerifier string `json:"code_verifier"`
	Scope            string `json:"scope"`
	AcrValues        string `json:"acr_values"`
	RedirectUri      string `json:"redirect_uri"`

	WithRFC9126Par     bool
	WithRFC9101Request bool
}

// OAuthOption a OAuth2 request
// parameter option
type OAuthOption interface {
	// SetValue set querystring paramater
	SetValue(url.Values)
	// SetClaim set RFC9101 'request' jwt claim
	SetClaim(map[string]interface{})
	// SetRequestContext save option in request context
	SetRequestContext(oauthCtx *OAuthContext)
}

type withParOtp struct{}

func (p withParOtp) SetValue(_ url.Values)             {}
func (p withParOtp) SetClaim(_ map[string]interface{}) {}
func (p withParOtp) SetRequestContext(oauthCtx *OAuthContext) {
	oauthCtx.WithRFC9126Par = true
}

type withRequestOpt struct{}

func (p withRequestOpt) SetValue(_ url.Values)             {}
func (p withRequestOpt) SetClaim(_ map[string]interface{}) {}
func (p withRequestOpt) SetRequestContext(oauthCtx *OAuthContext) {
	oauthCtx.WithRFC9101Request = true
}

type setParamAndClaim struct{ k, v string }

func (p setParamAndClaim) SetValue(m url.Values)             { m.Set(p.k, p.v) }
func (p setParamAndClaim) SetClaim(m map[string]interface{}) { m[p.k] = p.v }
func (p setParamAndClaim) SetRequestContext(oauthCtx *OAuthContext) {
	switch p.k {
	case "client_id":
		oauthCtx.ClientId = p.v
	case "redirect_uri":
		oauthCtx.RedirectUri = p.v
	case "nonce":
		oauthCtx.Nonce = p.v
	case "state":
		oauthCtx.State = p.v
	case "scope":
		oauthCtx.Scope = p.v
	case "acr_values":
		oauthCtx.AcrValues = p.v

	}
}

type setParam struct{ k, v string }

func (p setParam) SetValue(m url.Values)                    { m.Set(p.k, p.v) }
func (p setParam) SetClaim(m map[string]interface{})        {}
func (p setParam) SetRequestContext(oauthCtx *OAuthContext) {}

type setJSONParam struct {
	k string
	v interface{}
}

func (p setJSONParam) SetValue(m url.Values) {

	payload := assert.Must(json.Marshal(p.v))

	m.Set(p.k, string(payload))
}

func (p setJSONParam) SetClaim(m map[string]interface{}) {
	m[p.k] = p.v
}

func (p setJSONParam) SetRequestContext(oauthCtx *OAuthContext) {}

type setClaimsOnly struct {
	k string
	v interface{}
}

func (p setClaimsOnly) SetValue(m url.Values) {}

func (p setClaimsOnly) SetClaim(m map[string]interface{}) {
	m[p.k] = p.v
}

func (p setClaimsOnly) SetRequestContext(oauthCtx *OAuthContext) {}

// SetOAuthJSONParam when passed at parameter
// the value is json.Unmarshall as a string, but when
// parameter key is passed in request jwt it is kept as json object
func SetOAuthJSONParam(key string, value interface{}) OAuthOption {
	return setJSONParam{key, value}
}

// SetOAuthParamOnly set parameter key/value only
// as parameter (and not in the request jwt)
func SetOAuthParamOnly(key, value string) OAuthOption {
	return setParam{key, value}
}

// SetOAuthClaimOnly set parameter key/value only in
// request jwt (see [oauthx.WithGeneratedRequestJWT])
//
// ONLY for [oauthx.AuthZRequest]
func SetOAuthClaimOnly(key string, value interface{}) OAuthOption {
	return setClaimsOnly{k: key, v: value}
}

// WithPushedAuthotizationRequest rfc9126 make authorization request via
// pushed authorization endpoint, and use the 'request_uri' , 'client_id'
// for the authorization_endpoint
//
// ONLY for [oauthx.AuthZRequest]
func WithPushedAuthotizationRequest() OAuthOption {
	return withParOtp{}
}

// WithGeneratedRequestJWT rfc9101 generate the 'request'
// jwt parameter inluding the claims defined with
// the SetClaim() function from the [oauthx.OAuthOption] interface
//
// ONLY for [oauthx.AuthZRequest]
func WithGeneratedRequestJWT() OAuthOption {
	return withRequestOpt{}
}

// SetOAuthParam set key/value as both query parameter
// and claims in the request jwt (see [oauthx.WithGeneratedRequestJWT]).
//
// This also stores in the value in the [oauthx.OAuthContext] for the following key:
//   - "client_id"
//   - "redirect_uri"
//   - "nonce"
//   - "state"
//   - "scope"
//   - "acr_values"
//
// When used for [oauthx.AuthZRequest]
func SetOAuthParam(key, value string) OAuthOption {
	return setParamAndClaim{key, value}
}

// ResponseTypeCodeOpt set response_type=code in both param and request jwt
func ResponseTypeCodeOpt() OAuthOption {
	return SetOAuthParam("response_type", "code")
}

// ClientIdOpt set 'client_id=' parameter in parameter
// in request jwt as claims, and in [oauthx.OAuthContext]
func ClientIdOpt(clientId string) OAuthOption {
	return SetOAuthParam("client_id", clientId)
}

// SetStateOpt set 'state=' parameter in parameter
// in request jwt as claims, and in [oauthx.OAuthContext]
func SetStateOpt(state string) OAuthOption {
	return SetOAuthParam("state", state)
}

// StateOpt generate a new state and set 'state=' parameter in parameter
// in request jwt as claims, and in [oauthx.OAuthContext]
func StateOpt() OAuthOption {
	return SetOAuthParam("state", NewState(12))
}

// RedirectUriOpt set 'redirect_uri=' parameter in parameter
// in request jwt as claims, and in [oauthx.OAuthContext]
func RedirectUriOpt(redirectUri string) OAuthOption {
	return SetOAuthParam("redirect_uri", redirectUri)
}

// ScopeOpt format scopes as a space separated string
// set 'scope=' parameter in parameter
// in request jwt as claims, and in [oauthx.OAuthContext]
func ScopeOpt(scopes []string) OAuthOption {
	return SetOAuthParam("scope", strings.Join(scopes, " "))
}

// AcrValuesOpt format acrValues as a space separated string
// set 'acr_values=' parameter in parameter
// in request jwt as claims, and in [oauthx.OAuthContext]
func AcrValuesOpt(acrValues []string) OAuthOption {
	return SetOAuthParam("acr_values", strings.Join(acrValues, " "))
}

// UILocalesOpt format uiLocales as a space separated string
// set 'ui_locales=' parameter in parameter
// in request jwt as claims, and in [oauthx.OAuthContext]
func UILocalesOpt(uiLocales []string) OAuthOption {
	return SetOAuthParam("ui_locales", strings.Join(uiLocales, " "))
}

// SetNonceOpt set 'nonce=' parameter in parameter
// in request jwt as claims, and in [oauthx.OAuthContext]
func SetNonceOpt(nonce string) OAuthOption {
	return SetOAuthParam("nonce", nonce)
}

// NonceOpt generate and set 'nonce=' parameter in parameter
// in request jwt as claims, and in [oauthx.OAuthContext]
func NonceOpt() OAuthOption {
	return SetOAuthParam("nonce", NewNonce(12))
}

// RFC9101RequestOpt set rfc9101 'request' jwt as parameter only
//
// CANNOT be used with [oauthx.WithGeneratedRequestJWT]
func RFC9101RequestOpt(token string) OAuthOption {
	return SetOAuthParamOnly("request", token)
}

func PlumbingRequestUriOpt(requestUri string) OAuthOption {
	return setParam{k: "request_uri", v: requestUri}
}

// TODO: claims, RFC9396 authorization_details, prompt login/consent

// AuthorizationCodeGrantTypeOpt set 'grant_type=authorization_code' as
// parameter and request jwt claims
func AuthorizationCodeGrantTypeOpt() OAuthOption {
	return GrantTypeOpt("authorization_code")
}

// GrantTypeOpt set 'grant_type=' as
// parameter and request jwt claims
func GrantTypeOpt(grant string) OAuthOption {
	return SetOAuthParam("grant_type", grant)
}

// RefreshTokenGrantTypeOpt set 'grant_type=refresh_token' parameter
func RefreshTokenGrantTypeOpt() OAuthOption {
	return GrantTypeOpt("refresh_token")
}

// RefreshTokenOpt set 'refresh_token=' parameter
func RefreshTokenOpt(token string) OAuthOption {
	return SetOAuthParamOnly("refresh_token", token)
}

// CodeOpt set 'code=' parameter
func CodeOpt(code string) OAuthOption {
	return SetOAuthParam("code", code)
}

// TokenOpt set 'token=' parameter
func TokenOpt(token string) OAuthOption {
	return SetOAuthParamOnly("token", token)
}

// TokenTypeHintOpt set 'token_type_hint=' parameter
func TokenTypeHintOpt(tokenType string) OAuthOption {
	return SetOAuthParamOnly("token_type_hint", tokenType)
}

// IdTokenHintOpt set 'id_token_hint=' parameter
// for OIDC RP Initiated Logout
func IdTokenHintOpt(idToken string) OAuthOption {
	return SetOAuthParamOnly("id_token_hint", idToken)
}

// LogoutHintOpt set 'logout_hint=' parameter
func LogoutHintOpt(hint string) OAuthOption {
	return SetOAuthParamOnly("logout_hint", hint)
}

// LogoutHintOpt set 'post_logout_redirect_uri=' parameter
// for OIDC RP Initiated Logout
func PostLogoutRedirectUriOpt(uri string) OAuthOption {
	return SetOAuthParamOnly("post_logout_redirect_uri", uri)
}

// 5.5.  Requesting Claims using the "claims" Request Parameter
//
//	OpenID Connect defines the following Authorization Request parameter
//	to enable requesting individual Claims and specifying parameters that
//	apply to the requested Claims:
//
//	claims
//	   OPTIONAL.  This parameter is used to request that specific Claims
//	   be returned.  The value is a JSON object listing the requested
//	   Claims.
//
// The "claims" Authentication Request parameter requests that specific
// Claims be returned from the UserInfo Endpoint and/or in the ID Token.
// It is represented as a JSON object containing lists of Claims being
// requested from these locations.  Properties of the Claims being
// requested MAY also be specified.
//
// claim parameter is passed using [oauthx.SetOAuthJSONParam]
func ClaimsParameterOpt(claims *OpenIdRequestedClaim) OAuthOption {
	return SetOAuthJSONParam("claims", claims)
}

// 5.5.1.  Individual Claims Requests
//
// JSON Object
//
//	Used to provide additional information about the Claim being
//	requested.  This specification defines the following members:
type OpenIdRequestedClaim struct {
	//    essential
	//       OPTIONAL.  Indicates whether the Claim being requested is an
	//       Essential Claim.  If the value is "true", this indicates that
	//       the Claim is an Essential Claim.
	// The default is "false".
	Essential bool `json:"essential,omitempty"`

	// value
	//    OPTIONAL.  Requests that the Claim be returned with a
	//    particular value.
	Value string `json:"value,omitempty"`

	// values
	//    OPTIONAL.  Requests that the Claim be returned with one of a
	//    set of values, with the values appearing in order of
	//    preference.  This is processed equivalently to a "value"
	//    request, except that a choice of acceptable Claim values is
	//    provided.
	Values []string `json:"values,omitempty"`
}

func NewOpenIdRequestedClaim(essential bool, values []string) *OpenIdRequestedClaim {
	c := &OpenIdRequestedClaim{
		Essential: essential,
	}

	if len(values) == 1 {
		c.Value = values[0]
		return c
	}

	c.Values = values
	return c
}

func (c *OpenIdRequestedClaim) GetValues() []string {
	if c.Value != "" {
		return []string{c.Value}
	}

	return c.Values
}

// 5.5.  Requesting Claims using the "claims" Request Parameter
type OpendIdRequestedClaimsParam struct {

	// userinfo
	//    OPTIONAL.  Requests that the listed individual Claims be returned
	//    from the UserInfo Endpoint.  If present, the listed Claims are
	//    being requested to be added to any Claims that are being requested
	//    using "scope" values.  If not present, the Claims being requested
	//    from the UserInfo Endpoint are only those requested using "scope"
	//    values.
	//    When the "userinfo" member is used, the request MUST also use a
	//    "response_type" value that results in an Access Token being issued
	//    to the Client for use at the UserInfo Endpoint.
	Userinfo map[string]*OpenIdRequestedClaim `json:"userinfo,omitempty"`

	// id_token
	//    OPTIONAL.  Requests that the listed individual Claims be returned
	//    in the ID Token.  If present, the listed Claims are being
	//    requested to be added to the default Claims in the ID Token.  If
	//    not present, the default ID Token Claims are requested, as per the
	//    ID Token definition in Section 2 and per the additional per-flow
	//    ID Token requirements in Sections 3.1.3.6, 3.2.2.10, 3.3.2.11, and
	//    3.3.3.6.
	IDToken map[string]*OpenIdRequestedClaim `json:"id_token,omitempty"`
}