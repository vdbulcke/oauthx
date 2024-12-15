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

func (c *OAuthClient) DoAuthorizationRequest(ctx context.Context, autz *AuthZRequest) (*AuthorizationRequest, error) {

	params, err := c.PlumbingGenerateAuthZRequestParam(autz)
	if err != nil {
		return nil, err
	}

	requestContext := autz.reqCtx

	if !requestContext.WithRFC9126Par {

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
