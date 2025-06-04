package oauthx

import (
	"fmt"
	"net/url"

	"github.com/vdbulcke/assert"
)

type AuthZRequest struct {
	opts   []OAuthOption
	reqCtx *OAuthContext
}

func NewAuthZRequest(opts ...OAuthOption) *AuthZRequest {
	r := &AuthZRequest{opts: opts, reqCtx: &OAuthContext{}}

	return r
}

func (r *AuthZRequest) AddOpts(opts ...OAuthOption) {
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
		PKCEOpt(),
	)

	return r
}

// GetAuthzRequestOptions return static otpions configured
// for this client
func (c *OAuthClient) GetAuthzRequestOptions() []OAuthOption {
	return c.staticAuthzRequestOpt
}

// NewBaseAuthzRequest make new [oauthx.AuthZRequest] based on
// option passed with [oauthx.WithStaticAuthzRequestOpt] during client
// creation.
//
// Then adds the extra opt OAuthOption
func (c *OAuthClient) NewClientBaseAuthzRequest(extra ...OAuthOption) *AuthZRequest {
	r := NewAuthZRequest(c.staticAuthzRequestOpt...)
	r.AddOpts(extra...)
	return r
}

func (c *OAuthClient) PlumbingGenerateAuthZRequestParam(req *AuthZRequest) (url.Values, error) {

	params := url.Values{}
	claims := map[string]any{}
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

		jwtHeader := []*HeaderField{}

		if !reqCtx.LegacyRFC9101RequestJwtTyp {
			// rfc9101 10.8 Cross Jwt Confusion
			jwtHeader = append(jwtHeader, &HeaderField{Key: "typ", Value: "oauth-authz-req+jwt"})
		}

		request, err := c.PlumbingGenerateRFC9101RequestJwt(claims, jwtHeader...)
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

// TokenRequest a token_endpoint request
type TokenRequest struct {
	opts []OAuthOption
}

func (r *TokenRequest) AddOpts(opts ...OAuthOption) {
	r.opts = append(r.opts, opts...)
}

func NewTokenRequest(opts ...OAuthOption) *TokenRequest {
	return &TokenRequest{opts: opts}
}

// NewAuthorizationCodeGrantTokenRequest creates a token_endpoint request
// for the authorization code flow with
//   - [oauthx.AuthorizationCodeGrantTypeOpt]
//   - [oauthx.CodeOpt]
//
// and the following option if present in the [oauthx.OAuthContext]:
//   - [oauthx.RedirectUriOpt] if RedirectUri is not empty
//   - [oauthx.PKCEVerifierOpt] if PKCECodeVerifier is not empty
func NewAuthorizationCodeGrantTokenRequest(code string, reqCtx *OAuthContext) *TokenRequest {
	assert.NotNil(reqCtx, assert.Panic)

	r := NewTokenRequest(
		AuthorizationCodeGrantTypeOpt(),
		CodeOpt(code),
	)

	if reqCtx.RedirectUri != "" {
		r.AddOpts(RedirectUriOpt(reqCtx.RedirectUri))
	}

	if reqCtx.PKCECodeVerifier != "" {
		r.AddOpts(PKCEVerifierOpt(reqCtx.PKCECodeVerifier))
	}

	return r
}

// NewRefreshTokenGrantTokenRequest creates a token_endpoint request
// for the refresh token flow with:
//   - [oauthx.RefreshTokenGrantTypeOpt]
//   - [oauthx.RefreshTokenOpt]
func NewRefreshTokenGrantTokenRequest(token string) *TokenRequest {
	return NewTokenRequest(
		RefreshTokenGrantTypeOpt(),
		RefreshTokenOpt(token),
	)
}

// NewRefreshTokenGrantTokenRequest creates a token_endpoint request
// for the client_credentials flow with options:
//   - [oauthx.ClientCredentialsGrantTypeOpt]
//   - [oauthx.ScopeOpt] if scopes are provided
func NewClientCredentialsGrantTokenRequest(scopes ...string) *TokenRequest {
	req := NewTokenRequest(
		ClientCredentialsGrantTypeOpt(),
	)

	if len(scopes) > 0 {
		req.AddOpts(
			ScopeOpt(scopes...),
		)
	}

	return req
}

// Validate validate that the token request contains
// the required parameter based on the "grant_type"
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

func (r *RevokeRequest) AddOpts(opts ...OAuthOption) {
	r.opts = append(r.opts, opts...)
}

// NewRevokeRequest creates a new revocation request
//
// Example
//
//	req := oauthx.NewRevokeRequest(
//	    // token   REQUIRED.  The token that the client wants to get revoked.
//	    oauthx.TokenOpt(token),
//	    // token_type_hint  OPTIONAL.  A hint about the type of the token
//	    //         submitted for revocation.  Clients MAY pass this parameter in
//	    //         order to help the authorization server to optimize the token
//	    //         lookup.  If the server is unable to locate the token using
//	    //         the given hint, it MUST extend its search across all of its
//	    //         supported token types.  An authorization server MAY ignore
//	    //         this parameter, particularly if it is able to detect the
//	    //         token type automatically.  This specification defines two
//	    //         such values:
//	    //         * access_token: An access token as defined in [RFC6749],
//	    //           Section 1.4
//	    //         * refresh_token: A refresh token as defined in [RFC6749],
//	    //           Section 1.5
//	    oauthx.TokenTypeHintOpt(oauthx.TokenTypeRefreshToken),
//	)
//
// rfc7009
func NewRevokeRequest(opts ...OAuthOption) *RevokeRequest {
	return &RevokeRequest{opts: opts}
}

type IntrospectionRequest struct {
	opts []OAuthOption
}

func (r *IntrospectionRequest) AddOpts(opts ...OAuthOption) {
	r.opts = append(r.opts, opts...)
}

// NewIntrospectionRequest create a new introspection request with opts
//
// Example:
//
//		req := oauthx.NewIntrospectionRequest(
//	        // token
//	        //
//	        //    REQUIRED.  The string value of the token.  For access tokens, this
//	        //    is the "access_token" value returned from the token endpoint
//	        //    defined in OAuth 2.0 [RFC6749], Section 5.1.  For refresh tokens,
//	        //    this is the "refresh_token" value returned from the token endpoint
//	        //    as defined in OAuth 2.0 [RFC6749], Section 5.1.  Other token types
//	        //    are outside the scope of this specification.
//	        oauthx.TokenOpt(token),
//	        // token_type_hint
//	        //
//	        //    OPTIONAL.  A hint about the type of the token submitted for
//	        //    introspection.  The protected resource MAY pass this parameter to
//	        //    help the authorization server optimize the token lookup.  If the
//	        //    server is unable to locate the token using the given hint, it MUST
//	        //    extend its search across all of its supported token types.  An
//	        //    authorization server MAY ignore this parameter, particularly if it
//	        //    is able to detect the token type automatically.  Values for this
//	        //    field are defined in the "OAuth Token Type Hints" registry defined
//	        //    in OAuth Token Revocation [RFC7009].
//	        oauthx.TokenTypeHintOpt(oauthx.TokenTypeAccessToken),
//
//		)
//
// rfc7662: Introspect Request
func NewIntrospectionRequest(opts ...OAuthOption) *IntrospectionRequest {
	return &IntrospectionRequest{opts: opts}
}

type EndSessionRequest struct {
	opts []OAuthOption
}

func (r *EndSessionRequest) AddOpts(opts ...OAuthOption) {
	r.opts = append(r.opts, opts...)
}

// NewEndSessionRequest OpenID Connect RP-Initiated Logout Request
//
// Example
//
//	// create a OpenID Connect RP-Initiated Logout Request
//	req := oauthx.NewEndSessionRequest(
//	    // id_token_hint
//	    //    RECOMMENDED.  ID Token previously issued by the OP to the RP
//	    //    passed to the Logout Endpoint as a hint about the End-User's
//	    //    current authenticated session with the Client.  This is used as an
//	    //    indication of the identity of the End-User that the RP is
//	    //    requesting be logged out by the OP.
//	    oauthx.IdTokenHintOpt(idToken),
//	    // client_id
//	    //    OPTIONAL.  OAuth 2.0 Client Identifier valid at the Authorization
//	    //    Server.  When both "client_id" and "id_token_hint" are present,
//	    //    the OP MUST verify that the Client Identifier matches the one used
//	    //    when issuing the ID Token.  The most common use case for this
//	    //    parameter is to specify the Client Identifier when
//	    //    "post_logout_redirect_uri" is used but "id_token_hint" is not.
//	    //    Another use is for symmetrically encrypted ID Tokens used as
//	    //    "id_token_hint" values that require the Client Identifier to be
//	    //    specified by other means, so that the ID Tokens can be decrypted
//	    //    by the OP.
//	    oauthx.ClientIdOpt("my_client_id"),
//	    // post_logout_redirect_uri
//	    //    OPTIONAL.  URI to which the RP is requesting that the End-User's
//	    //    User Agent be redirected after a logout has been performed.  This
//	    //    URI SHOULD use the "https" scheme and MAY contain port, path, and
//	    //    query parameter components; however, it MAY use the "http" scheme,
//	    //    provided that the Client Type is "confidential", as defined in
//	    //    Section 2.1 of OAuth 2.0 [RFC6749], and provided the OP allows the
//	    //    use of "http" RP URIs.  The URI MAY use an alternate scheme, such
//	    //    as one that is intended to identify a callback into a native
//	    //    application.  The value MUST have been previously registered with
//	    //    the OP, either using the "post_logout_redirect_uris" Registration
//	    //    parameter or via another mechanism.  An "id_token_hint" is also
//	    //    RECOMMENDED when this parameter is included.
//	    oauthx.PostLogoutRedirectUriOpt("https://mydomain.com/post/logout"),
//	)
func NewEndSessionRequest(opts ...OAuthOption) *EndSessionRequest {
	return &EndSessionRequest{opts: opts}
}
