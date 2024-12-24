package oauthx

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/vdbulcke/oauthx/assert"
)

type OAuthAuthenticatedEndpoint int

const (
	PushedAuthorizationRequestEndpoint OAuthAuthenticatedEndpoint = iota
	TokenEndpoint
	IntrospectionEndpoint
	RevocationEndpoint
	// UserinfoEndpoint
	// AuthorizationEndpoint
)

func (e OAuthAuthenticatedEndpoint) String() string {
	switch e {
	case PushedAuthorizationRequestEndpoint:
		return "PushedAuthorizationRequestEndpoint"
	case TokenEndpoint:
		return "TokenEndpoint"
	case IntrospectionEndpoint:
		return "IntrospectionEndpoint"
	case RevocationEndpoint:
		return "RevocationEndpoint"

	default:
		panic("unsupported OAuthAuthenticatedEndpoint")
	}
}

type AuthMethod interface {
	// NewOAuthAuthenticatedRequest creates a new [*http.Request] for the [endpoint] of type [oauthEndpoint]
	// by adding the OAuth2 Credentials paramater for this [AuthMethod] to the OAuth2 Request [params]
	NewOAuthAuthenticatedRequest(oauthEndpoint OAuthAuthenticatedEndpoint, endpoint string, params url.Values) (*http.Request, error)
}

// None auth method from OpenID Connect Discovery 1.0
//
//	 none
//
//		The Client does not authenticate itself at the Token Endpoint,
//		either because it uses only the Implicit Flow (and so does not use
//		the Token Endpoint) or because it is a Public Client with no
//		Client Secret or other authentication mechanism.
type None struct {
	ClientId string
}

// NewAuthMethodNone creates a None auth method
//
// if clientId is not empty then always adds
// "client_id=" parameter
func NewAuthMethodNone(clientId string) *None {
	return &None{
		ClientId: clientId,
	}
}

func (a *None) NewOAuthAuthenticatedRequest(oauthEndpoint OAuthAuthenticatedEndpoint, endpoint string, params url.Values) (*http.Request, error) {
	if params == nil {
		return nil, errors.New("basic auth: params are required")
	}

	if a.ClientId != "" {
		params.Set("client_id", a.ClientId)
	}

	// encode provided params, and create request
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	// Set Content Type
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

// ClientSecretBasic OAuth client_secret_basic Authentication method
//
//	 client_secret_basic
//
//		Clients that have received a "client_secret" value from the
//		Authorization Server authenticate with the Authorization Server in
//		accordance with Section 2.3.1 of OAuth 2.0 [RFC6749] using the
//		HTTP Basic authentication scheme.
type ClientSecretBasic struct {
	ClientId     string
	ClientSecret string
}

func NewBasicAuth(clientId, secret string) *ClientSecretBasic {
	return &ClientSecretBasic{ClientId: clientId, ClientSecret: secret}
}

func (a *ClientSecretBasic) NewOAuthAuthenticatedRequest(oauthEndpoint OAuthAuthenticatedEndpoint, endpoint string, params url.Values) (*http.Request, error) {
	if params == nil {
		return nil, errors.New("basic auth: params are required")
	}

	// encode provided params, and create request
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	// set basic auth header
	req.SetBasicAuth(url.QueryEscape(a.ClientId), url.QueryEscape(a.ClientSecret))
	// Set Content Type
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

// ClientSecretPost OAuth client_secret_post Authentication method
//
//	 client_secret_post
//
//		Clients that have received a "client_secret" value from the
//		Authorization Server, authenticate with the Authorization Server
//		in accordance with Section 2.3.1 of OAuth 2.0 [RFC6749] by
//		including the Client Credentials in the request body.
type ClientSecretPost struct {
	ClientId     string
	ClientSecret string
}

func NewClientSecretPost(clientId, secret string) *ClientSecretPost {
	return &ClientSecretPost{ClientId: clientId, ClientSecret: secret}
}

func (a *ClientSecretPost) NewOAuthAuthenticatedRequest(oauthEndpoint OAuthAuthenticatedEndpoint, endpoint string, params url.Values) (*http.Request, error) {
	if params == nil {
		return nil, errors.New("params are required")
	}
	// add client_id client_secret to query params
	params.Set("client_id", a.ClientId)
	params.Set("client_secret", a.ClientSecret)

	// encode provided params, and create request
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	// Set Content Type
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

type PrivateKeyJwtOptFunc func(*PrivateKeyJwt)

// PrivateKeyJwt from  OpenID Connect Discovery 1.0
//
//	private_key_jwt
//	   Clients that have registered a public key sign a JWT using that
//	   key.  The Client authenticates in accordance with JSON Web Token
//	   (JWT) Profile for OAuth 2.0 Client Authentication and
//	   Authorization Grants [OAuth.JWT] and Assertion Framework for OAuth
//	   2.0 Client Authentication and Authorization Grants
//	   [OAuth.Assertions].  The JWT MUST contain the following REQUIRED
//	   Claim Values and MAY contain the following OPTIONAL Claim Values:
//
//	   iss
//	      REQUIRED.  Issuer.  This MUST contain the "client_id" of the
//	      OAuth Client.
//
//	   sub
//	      REQUIRED.  Subject.  This MUST contain the "client_id" of the
//	      OAuth Client.
//
//	   aud
//	      REQUIRED.  Audience.  The "aud" (audience) Claim.  Value that
//	      identifies the Authorization Server as an intended audience.
//	      The Authorization Server MUST verify that it is an intended
//	      audience for the token.  The Audience SHOULD be the URL of the
//	      Authorization Server's Token Endpoint.
//
//	   jti
//	      REQUIRED.  JWT ID.  A unique identifier for the token, which
//	      can be used to prevent reuse of the token.  These tokens MUST
//	      only be used once, unless conditions for reuse were negotiated
//	      between the parties; any such negotiation is beyond the scope
//	      of this specification.
//
//	   exp
//	      REQUIRED.  Expiration time on or after which the JWT MUST NOT
//	      be accepted for processing.
//
//	   iat
//	      OPTIONAL.  Time at which the JWT was issued.
//
//	   The JWT MAY contain other Claims.  Any Claims used that are not
//	   understood MUST be ignored.
//
//	   The authentication token MUST be sent as the value of the
//	   [OAuth.Assertions] "client_assertion" parameter.
//
//	   The value of the [OAuth.Assertions] "client_assertion_type"
//	   parameter MUST be
//	   "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", per
//	   [OAuth.JWT].
type PrivateKeyJwt struct {
	ClientId string

	alwaysIncludeClientIdParam bool
	endpointAudiance           bool

	fixedAudiance string

	pushedAuthorizationRequestEndpointAudiance string
	tokenEndpointAudiance                      string
	introspectionEndpointAudiance              string
	revocationEndpointAudiance                 string

	ttl time.Duration

	jwtSigner OAuthPrivateKey
}

// WithPrivateKeyJwtTTL used to set the "exp" claims
// default ttl is 5 minutes
func WithPrivateKeyJwtTTL(ttl time.Duration) PrivateKeyJwtOptFunc {
	return func(a *PrivateKeyJwt) {
		a.ttl = ttl
	}
}

// WithPrivateKeyJwtAlwaysIncludeClientIdParam always add the 'client_id='
// parameter along side the 'client_assertion=' and 'client_assertion_type='
func WithPrivateKeyJwtAlwaysIncludeClientIdParam() PrivateKeyJwtOptFunc {
	return func(a *PrivateKeyJwt) {
		a.alwaysIncludeClientIdParam = true
	}
}

// WithPrivateKeyJwtEndpointAsAudiance set the 'aud' claims the jwt
// assertion to the current endpoint of the request
//
// Since it cannot be used with [oauthx.WithPrivateKeyJwtFixedAudiance]
// it resets any fixed audiance previously set
func WithPrivateKeyJwtEndpointAsAudiance() PrivateKeyJwtOptFunc {
	return func(a *PrivateKeyJwt) {
		a.endpointAudiance = true
		a.fixedAudiance = ""
	}
}

// WithPrivateKeyJwtFixedAudiance set the 'aud' claims the jwt
// assertion to the aud for all endpoint
//
// typically aud should be the issuer
//
// Since it cannot be used with [oauthx.WithPrivateKeyJwtEndpointAsAudiance]
// it disables WithPrivateKeyJwtEndpointAsAudiance option
func WithPrivateKeyJwtFixedAudiance(aud string) PrivateKeyJwtOptFunc {
	return func(a *PrivateKeyJwt) {
		a.fixedAudiance = aud
		a.endpointAudiance = false
	}
}

// WithPrivateKeyJwtPushedAuthorizationRequestEndpointAudiance set the 'aud' claims the jwt
// assertion to the aud for the endpoint
func WithPrivateKeyJwtAlternativeEndpointAudiance(endpoint OAuthAuthenticatedEndpoint, aud string) PrivateKeyJwtOptFunc {
	return func(a *PrivateKeyJwt) {
		switch endpoint {
		case PushedAuthorizationRequestEndpoint:
			a.pushedAuthorizationRequestEndpointAudiance = aud
		case TokenEndpoint:
			a.tokenEndpointAudiance = aud
		case IntrospectionEndpoint:
			a.introspectionEndpointAudiance = aud
		case RevocationEndpoint:
			a.revocationEndpointAudiance = aud

		}
	}
}

// NewPrivateKeyJwt creates a new 'private_key_jwt' authmethod
func NewPrivateKeyJwt(clientId string, signer OAuthPrivateKey, opts ...PrivateKeyJwtOptFunc) *PrivateKeyJwt {
	a := &PrivateKeyJwt{
		ClientId:                   clientId,
		jwtSigner:                  signer,
		alwaysIncludeClientIdParam: false,
		endpointAudiance:           false,
		ttl:                        5 * time.Minute,
	}

	for _, fn := range opts {
		fn(a)
	}

	return a
}

func (a *PrivateKeyJwt) NewOAuthAuthenticatedRequest(oauthEndpoint OAuthAuthenticatedEndpoint, endpoint string, params url.Values) (*http.Request, error) {
	if params == nil {
		return nil, errors.New("params are required")
	}

	jwtProfile, err := a.GenerateJwtProfileAssertion(oauthEndpoint, endpoint)
	if err != nil {
		return nil, fmt.Errorf("private_key_jwt: %w", err)
	}

	// rfc7521
	// client_assertion_type
	//    REQUIRED.  The format of the assertion as defined by the
	//    authorization server.  The value will be an absolute URI.
	//
	// rfc7523
	// The value of the "client_assertion_type" is
	// "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".
	params.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")

	// rfc7521
	// client_assertion
	//    REQUIRED.  The assertion being used to authenticate the client.
	//    Specific serialization of the assertion is defined by profile
	//    documents.
	//
	// rfc7523
	// The value of the "client_assertion" parameter contains a single JWT.
	// It MUST NOT contain more than one JWT.
	params.Set("client_assertion", jwtProfile)

	// rfc7521
	// client_id
	//    OPTIONAL.  The client identifier as described in Section 2.2 of
	//    OAuth 2.0 [RFC6749].  The "client_id" is unnecessary for client
	//    assertion authentication because the client is identified by the
	//    subject of the assertion.  If present, the value of the
	//    "client_id" parameter MUST identify the same client as is
	//    identified by the client assertion.
	if a.alwaysIncludeClientIdParam {
		// add client_id client_secret to query params
		params.Set("client_id", a.ClientId)
	}

	// encode provided params, and create request
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	// Set Content Type
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

func (a *PrivateKeyJwt) GenerateJwtProfileAssertion(endpointType OAuthAuthenticatedEndpoint, endpoint string) (string, error) {
	assert.NotNil(a.jwtSigner, assert.Panic, "private_key_jwt: JwtSigner is required")

	jti := assert.Must(RandString(10))

	aud := a.getAudiance(endpointType, endpoint)

	claims := jwt.RegisteredClaims{

		// OpenID Connect Discovery 1.0
		// iss
		//    REQUIRED.  Issuer.  This MUST contain the "client_id" of the
		//    OAuth Client.
		Issuer: a.ClientId,

		// OpenID Connect Discovery 1.0
		// sub
		//    REQUIRED.  Subject.  This MUST contain the "client_id" of the
		//    OAuth Client.
		Subject: a.ClientId,

		// OpenID Connect Discovery 1.0
		// aud
		//    REQUIRED.  Audience.  The "aud" (audience) Claim.  Value that
		//    identifies the Authorization Server as an intended audience.
		//    The Authorization Server MUST verify that it is an intended
		//    audience for the token.  The Audience SHOULD be the URL of the
		//    Authorization Server's Token Endpoint.
		Audience: jwt.ClaimStrings{aud},

		// OpenID Connect Discovery 1.0
		// jti
		//    REQUIRED.  JWT ID.  A unique identifier for the token, which
		//    can be used to prevent reuse of the token.  These tokens MUST
		//    only be used once, unless conditions for reuse were negotiated
		//    between the parties; any such negotiation is beyond the scope
		//    of this specification.
		ID: jti,

		// OpenID Connect Discovery 1.0
		// exp
		//    REQUIRED.  Expiration time on or after which the JWT MUST NOT
		//    be accepted for processing.
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(a.ttl)),

		// OpenID Connect Discovery 1.0
		// iat
		//    OPTIONAL.  Time at which the JWT was issued.
		IssuedAt: jwt.NewNumericDate(time.Now()),

		// rfc7523
		// 5.   The JWT MAY contain an "nbf" (not before) claim that identifies
		//      the time before which the token MUST NOT be accepted for
		//      processing.
		NotBefore: jwt.NewNumericDate(time.Now()),
	}

	return a.jwtSigner.SignJWT(claims)
}

func (a *PrivateKeyJwt) getAudiance(endpointType OAuthAuthenticatedEndpoint, endpoint string) string {

	// if a.endpointAudiance
	aud := endpoint

	if a.fixedAudiance != "" {
		aud = a.fixedAudiance
	}

	switch endpointType {
	case PushedAuthorizationRequestEndpoint:

		if a.pushedAuthorizationRequestEndpointAudiance != "" {
			aud = a.pushedAuthorizationRequestEndpointAudiance
		}
	case TokenEndpoint:

		if a.tokenEndpointAudiance != "" {
			aud = a.tokenEndpointAudiance
		}
	case IntrospectionEndpoint:

		if a.introspectionEndpointAudiance != "" {
			aud = a.introspectionEndpointAudiance
		}
	case RevocationEndpoint:

		if a.revocationEndpointAudiance != "" {
			aud = a.revocationEndpointAudiance
		}
	}

	return aud
}

// TODO: client_secret_jwt
