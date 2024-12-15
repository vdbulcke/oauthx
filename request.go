package oauthx

import (
	"fmt"
	"net/url"

	"github.com/vdbulcke/oauthx/assert"
)

type AuthZRequest struct {
	opts   []OAuthOption
	reqCtx *OAuthContext
}

func NewAuthZRequest(opts ...OAuthOption) *AuthZRequest {
	r := &AuthZRequest{opts: opts, reqCtx: &OAuthContext{}}

	return r
}

func (r *AuthZRequest) AddOtps(opts ...OAuthOption) {
	assert.NotNil(r.opts, assert.Panic, "Request opts not initialized")

	r.opts = append(r.opts, opts...)
}

// NewBaseAuthzRequest create a new base AuthZRequest with
// resonable default:
//   - nonce
//   - state
//   - response_type=code
//   - pkce S256
func NewBaseAuthzRequest() *AuthZRequest {
	r := NewAuthZRequest(
		// response_type
		//    REQUIRED.  OAuth 2.0 Response Type value that determines the
		//    authorization processing flow to be used, including what
		//    parameters are returned from the endpoints used.  When using the
		//    Authorization Code Flow, this value is "code".
		ResponseTypeCodeOpt(),
		// state
		//    RECOMMENDED.  Opaque value used to maintain state between the
		//    request and the callback.  Typically, Cross-Site Request Forgery
		//    (CSRF, XSRF) mitigation is done by cryptographically binding the
		//    value of this parameter with a browser cookie.
		StateOpt(),
		// nonce
		//    OPTIONAL.  String value used to associate a Client session with an
		//    ID Token, and to mitigate replay attacks.  The value is passed
		//    through unmodified from the Authentication Request to the ID
		//    Token.  Sufficient entropy MUST be present in the "nonce" values
		//    used to prevent attackers from guessing values.  For
		//    implementation notes, see Section 15.5.2.
		NonceOpt(),
		// rfc7636
		// Request Context:
		// code_verifier => generated
		//    REQUIRED.  Code verifier
		//
		// Request params:
		// code_challenge => Generated
		//    REQUIRED.  Code challenge.

		// code_challenge_method => "S256"
		//    OPTIONAL, defaults to "plain" if not present in the request.  Code
		//    verifier transformation method is "S256" or "plain".
		DefaultPKCEOpt(),
	)

	return r
}

// GetAuthzRequestOptions return static otpions configured
// for this client
func (c *OAuthClient) GetAuthzRequestOptions() []OAuthOption {
	return c.staticAuthzRequestOpt
}

func (c *OAuthClient) PlumbingGenerateAuthZRequestParam(req *AuthZRequest) (url.Values, error) {

	params := url.Values{}
	claims := map[string]interface{}{}
	reqCtx := req.reqCtx
	if reqCtx == nil {
		reqCtx = &OAuthContext{}
		req.reqCtx = reqCtx
	}

	for _, opt := range req.opts {
		opt.SetValue(params)
		opt.SetClaim(claims)
		opt.SetRequestContext(reqCtx)
	}

	if reqCtx.WithRFC9101Request {
		request, err := c.PlumbingGenerateRFC9101RequestJwt(claims)
		if err != nil {
			return nil, err
		}

		// request
		//      REQUIRED unless "request_uri" is specified.  The Request Object
		//      (Section 2.1) that holds authorization request parameters stated
		//      in Section 4 of [RFC6749] (OAuth 2.0).  If this parameter is
		//      present in the authorization request, "request_uri" MUST NOT be
		//      present.
		params.Set("request", request)

		// client_id
		//    REQUIRED.  OAuth 2.0 [RFC6749] "client_id".  The value MUST match
		//    the "request" or "request_uri" Request Object's (Section 2.1)
		//    "client_id".
		// NOTE: client_id are usually added by authmethod
		params.Set("client_id", c.ClientId)

	}

	return params, nil
}

type TokenRequest struct {
	opts []OAuthOption
}

func (r *TokenRequest) AddOtps(opts ...OAuthOption) {
	r.opts = append(r.opts, opts...)
}

func NewTokenRequest(opts ...OAuthOption) *TokenRequest {
	return &TokenRequest{opts: opts}
}

func NewAuthorizationCodeGrantTokenRequest(code string, reqCtx *OAuthContext) *TokenRequest {
	assert.NotNil(reqCtx, assert.Panic)

	r := NewTokenRequest(
		AuthorizationCodeGrantTypeOpt(),
		CodeOpt(code),
	)

	if reqCtx.RedirectUri != "" {
		r.AddOtps(RedirectUriOpt(reqCtx.RedirectUri))
	}

	if reqCtx.PKCECodeVerifier != "" {
		r.AddOtps(PKCEVerifierOpt(reqCtx.PKCECodeVerifier))
	}

	return r
}

func NewRefreshTokenGrantTokenRequest(token string) *TokenRequest {
	return NewTokenRequest(
		RefreshTokenGrantTypeOpt(),
		RefreshTokenOpt(token),
	)
}

func (r *TokenRequest) Validate() error {

	// generate option
	params := url.Values{}
	for _, opt := range r.opts {
		opt.SetValue(params)

	}

	grant := params.Get("grant_type")
	if grant == "" {
		return fmt.Errorf("rfc6749: validation error missing 'grant_type'")
	}

	switch grant {
	// rfc6749
	// 4.1.3.  Access Token Request
	//    The client makes a request to the token endpoint by sending the
	//    following parameters using the "application/x-www-form-urlencoded"
	//    format per Appendix B with a character encoding of UTF-8 in the HTTP
	//    request entity-body:
	//
	//    grant_type
	//          REQUIRED.  Value MUST be set to "authorization_code".
	case "authorization_code":
		//    code
		//          REQUIRED.  The authorization code received from the
		//          authorization server.
		if params.Get("code") == "" {
			return fmt.Errorf("rfc6749: validation error missing 'code' with 'grant_type=authorization_code'")
		}
		//    redirect_uri
		//          REQUIRED, if the "redirect_uri" parameter was included in the
		//          authorization request as described in Section 4.1.1, and their
		//          values MUST be identical.
		if params.Get("redirect_uri") == "" {
			return fmt.Errorf("rfc6749: validation error missing 'redirect_uri' with 'grant_type=authorization_code'")
		}
		//    client_id
		//          REQUIRED, if the client is not authenticating with the
		//          authorization server as described in Section 3.2.1.
		// INFO: client_id is usually added by the authmethod

	// 4.3.2.  Access Token Request
	//
	//    The client makes a request to the token endpoint by adding the
	//    following parameters using the "application/x-www-form-urlencoded"
	//    format per Appendix B with a character encoding of UTF-8 in the HTTP
	//    request entity-body:
	//
	//    grant_type
	//          REQUIRED.  Value MUST be set to "password".
	case "password":

		// username
		//       REQUIRED.  The resource owner username.
		if params.Get("username") == "" {
			return fmt.Errorf("rfc6749: validation error missing 'username' with 'grant_type=password'")
		}

		// password
		//       REQUIRED.  The resource owner password.
		if params.Get("password") == "" {
			return fmt.Errorf("rfc6749: validation error missing 'password' with 'grant_type=password'")
		}

	// 4.4.2.  Access Token Request
	//    The client makes a request to the token endpoint by adding the
	//    following parameters using the "application/x-www-form-urlencoded"
	//    format per Appendix B with a character encoding of UTF-8 in the HTTP
	//    request entity-body:
	//
	//    grant_type
	//          REQUIRED.  Value MUST be set to "client_credentials".
	case "client_credentials":

		// scope
		//       OPTIONAL.  The scope of the access request as described by
		//       Section 3.3.

	// 6.  Refreshing an Access Token
	//
	//    If the authorization server issued a refresh token to the client, the
	//    client makes a refresh request to the token endpoint by adding the
	//    following parameters using the "application/x-www-form-urlencoded"
	//    format per Appendix B with a character encoding of UTF-8 in the HTTP
	//    request entity-body:
	//
	//    grant_type
	//          REQUIRED.  Value MUST be set to "refresh_token".
	//
	//    refresh_token
	//          REQUIRED.  The refresh token issued to the client.
	//
	//    scope
	//          OPTIONAL.  The scope of the access request as described by
	//          Section 3.3.  The requested scope MUST NOT include any scope
	//          not originally granted by the resource owner, and if omitted is
	//          treated as equal to the scope originally granted by the
	//          resource owner.
	//
	//    Because refresh tokens are typically long-lasting credentials used to
	//    request additional access tokens, the refresh token is bound to the
	//    client to which it was issued.  If the client type is confidential or
	//    the client was issued client credentials (or assigned other
	//    authentication requirements), the client MUST authenticate with the
	//    authorization server as described in Section 3.2.1.
	case "refresh_token":

		if params.Get("refresh_token") == "" {
			return fmt.Errorf("rfc6749: validation error missing 'refresh_token' with 'grant_type=refresh_token'")
		}

	// rfc7523
	// 2.1.  Using JWTs as Authorization Grants
	//
	//    To use a Bearer JWT as an authorization grant, the client uses an
	//    access token request as defined in Section 4 of the OAuth Assertion
	//    Framework [RFC7521] with the following specific parameter values and
	//    encodings.
	//
	//    The value of the "grant_type" is "urn:ietf:params:oauth:grant-
	//    type:jwt-bearer".
	//
	//    The value of the "assertion" parameter MUST contain a single JWT.
	//
	//    The "scope" parameter may be used, as defined in the OAuth Assertion
	//    Framework [RFC7521], to indicate the requested scope.
	//
	//    Authentication of the client is optional, as described in
	//    Section 3.2.1 of OAuth 2.0 [RFC6749] and consequently, the
	//    "client_id" is only needed when a form of client authentication that
	//    relies on the parameter is used.
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":

		if params.Get("assertion") == "" {
			return fmt.Errorf("rfc7523: validation error missing 'assertion' with 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer'")
		}

		// TODO: urn:openid:params:grant-type:ciba, urn:ietf:params:oauth:grant-type:uma-ticket,
		//       urn:ietf:params:oauth:grant-type:token-exchange, urn:ietf:params:oauth:grant-type:saml2-bearer
		//       urn:ietf:params:oauth:grant-type:device_code
	}

	return nil
}

type RevokeRequest struct {
	opts []OAuthOption
}

func (r *RevokeRequest) AddOtps(opts ...OAuthOption) {
	r.opts = append(r.opts, opts...)
}

func NewRevokeRequest(opts ...OAuthOption) *RevokeRequest {
	return &RevokeRequest{opts: opts}
}

type IntrospectionRequest struct {
	opts []OAuthOption
}

func (r *IntrospectionRequest) AddOtps(opts ...OAuthOption) {
	r.opts = append(r.opts, opts...)
}

func NewIntrospectionRequest(opts ...OAuthOption) *IntrospectionRequest {
	return &IntrospectionRequest{opts: opts}
}

type EndSessionRequest struct {
	opts []OAuthOption
}

func (r *EndSessionRequest) AddOtps(opts ...OAuthOption) {
	r.opts = append(r.opts, opts...)
}

func NewEndSessionRequest(opts ...OAuthOption) *EndSessionRequest {
	return &EndSessionRequest{opts: opts}
}
