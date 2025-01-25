package oauthx

import (
	"bytes"
	"context"
	"net/url"
	"strings"

	"github.com/vdbulcke/oauthx/assert"
)

type AuthorizationRequest struct {
	Url     string
	ReqCtx  *OAuthContext
	PARResp *PushedAuthorizationRequestResponse
}

// DoAuthorizationRequest make authorization code flow request
//
// Example:
//
//	// NewBaseAuthzRequest create a new base AuthZRequest with
//	// resonable default:
//	//  - nonce
//	//  - state
//	//  - response_type=code
//	//  - pkce S256
//	req := oauthx.NewBaseAuthzRequest()
//	// add client specific options
//	req.AddOpts(
//		oauthx.ClientIdOpt("my_client_id"),
//		oauthx.RedirectUriOpt("https://my.domain.com/callback"),
//		oauthx.ScopeOpt("openid", "profile", "email"),
//	)
//	// let's make the authorization request via PAR.
//	// Some options are not related to specific oauth parameter
//	// but how the DoAuthorizationRequest() function should behave
//	req.AddOpts(
//		// sends authorization request options via
//		// pushed authorization endpoint and
//		// only use client_id and request_uri for
//		// redirect to the authorization_endpoint
//		oauthx.WithPushedAuthorizationRequest(),
//	)
//	// now let's make the authorzation request
//	// (if using options shuch as WithPushedAuthorizationRequest()
//	// this will make an acutual http request), then this will
//	// generate the authorization url use to redirect the user to the
//	// Authorization Server, a OAuthContext (containing relevant parameter
//	// that may be required to make the associated token request: pkce code_verifier,
//	// redirect_uri, client_id, etc).
//	authRequest, err := client.DoAuthorizationRequest(ctx, req)
//	if err != nil {
//		// handle err
//		return err
//	}
//	// authRequest.Url is the authorization request url
//
// implements rfc6749 authorization code flow, rfc9126, rfc9101
func (c *OAuthClient) DoAuthorizationRequest(ctx context.Context, authz *AuthZRequest) (*AuthorizationRequest, error) {

	originalOpts := authz.opts

	params, err := c.PlumbingGenerateAuthZRequestParam(authz)
	if err != nil {
		return nil, err
	}

	requestContext := authz.reqCtx

	if !requestContext.WithRFC9126Par {

		if requestContext.WithRFC9101Request && requestContext.WithStrictRequiredAuthorizationParams {

			for _, opt := range originalOpts {
				// seek on which oauth param the current option is
				seekParam := url.Values{}
				opt.SetValue(seekParam)
				// RCF6749 (OAuth2 ) and OIDC standard
				// requires mandatory parameter present
				// RCF6749 Section 4.1.1
				//   - response_type
				//   - client_id
				if seekParam.Has("response_type") || seekParam.Has("client_id") {
					// add it again to authorization url param
					opt.SetValue(params)
					continue
				}
				//
				// openid core spec:
				//   - scope (MUST includes 'openid')
				//   - redirect_uri
				if seekParam.Has("scope") || seekParam.Has("redirect_uri") {
					// add it again to authorization url param
					opt.SetValue(params)

				}
			}

		}
		authUrl := c.PlumbingGenerateAuthorizationUrl(params)
		resp := &AuthorizationRequest{
			Url:    authUrl,
			ReqCtx: requestContext,
		}

		return resp, nil
	}

	req, err := c.PlumbingNewHttpPARRequest(params)
	if err != nil {
		return nil, err
	}

	parResp, err := c.PlumbingDoHttpPARRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	// 4.  Authorization Request
	//    The client uses the "request_uri" value returned by the authorization
	//    server to build an authorization request as defined in [RFC9101].
	newAuthzReq := NewAuthZRequest(
		// rfc9101
		// request_uri
		//     REQUIRED unless "request" is specified.  The absolute URI, as
		//     defined by RFC 3986 [RFC3986], that is the Request Object URI
		//     (Section 2.2) referencing the authorization request parameters
		//     stated in Section 4 of [RFC6749] (OAuth 2.0).  If this parameter
		//     is present in the authorization request, "request" MUST NOT be
		//     present.

		PlumbingRequestUriOpt(parResp.RequestUri),
		// rfc9101
		// client_id
		//    REQUIRED.  OAuth 2.0 [RFC6749] "client_id".  The value MUST match
		//    the "request" or "request_uri" Request Object's (Section 2.1)
		//    "client_id".
		ClientIdOpt(c.ClientId),
	)

	newParams, err := c.PlumbingGenerateAuthZRequestParam(newAuthzReq)
	if err != nil {
		return nil, err
	}

	if requestContext.WithStrictRequiredAuthorizationParams {

		for _, opt := range originalOpts {
			// seek on which oauth param the current option is
			seekParam := url.Values{}
			opt.SetValue(seekParam)
			// RCF6749 (OAuth2 ) and OIDC standard
			// requires mandatory parameter present
			// RCF6749 Section 4.1.1
			//   - response_type
			//   - client_id
			if seekParam.Has("response_type") || seekParam.Has("client_id") {
				// add it again to authorization url param
				opt.SetValue(newParams)
				continue
			}
			//
			// openid core spec:
			//   - scope (MUST includes 'openid')
			//   - redirect_uri
			if seekParam.Has("scope") || seekParam.Has("redirect_uri") {
				// add it again to authorization url param
				opt.SetValue(newParams)
			}
		}

	}

	authUrl := c.PlumbingGenerateAuthorizationUrl(newParams)

	return &AuthorizationRequest{
		Url:     authUrl,
		PARResp: parResp,
		ReqCtx:  requestContext,
	}, nil

}

func (c *OAuthClient) PlumbingGenerateAuthorizationUrl(params url.Values) string {
	assert.StrNotEmpty(c.wk.AuthorizationEndpoint, assert.Panic, "oauth-client: missing required 'authorization_endpoint'")

	return PlumbingAddParamToEndpoint(c.wk.AuthorizationEndpoint, params)
}

func PlumbingAddParamToEndpoint(endpoint string, params url.Values) string {

	var buf bytes.Buffer
	buf.WriteString(endpoint)

	if strings.Contains(endpoint, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(params.Encode())
	return buf.String()
}
