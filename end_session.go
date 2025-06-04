package oauthx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vdbulcke/assert"
	"github.com/vdbulcke/oauthx/metric"
	"github.com/vdbulcke/oauthx/tracing"
)

// EndSessionResponse response
// of OpenID Connect RP-Initiated Logout 1.0, 2.  RP-Initiated Logout
type EndSessionResponse struct {
	// the post_logout_redirect_uri if provided in the request
	// of empty string "" otherwise
	Redirect string
}

// DoEndSessionRequest
//
// OpenID Connect RP-Initiated Logout 1.0, 2.  RP-Initiated Logout
//
//	An RP requests that the OP log out the End-User by redirecting the
//	End-User's User Agent to the OP's Logout Endpoint.  This URL is
//	normally obtained via the "end_session_endpoint" element of the OP's
//	Discovery response or may be learned via other mechanisms.
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
//	//
//	// send endSession request
//	resp, err := client.DoEndSessionRequest(ctx,req)
//	if err != nil {
//	    return err
//	}
//	// resp.Redirect is the redirect to the post_logout_redirect_uri
func (c *OAuthClient) DoEndSessionRequest(ctx context.Context, r *EndSessionRequest) (*EndSessionResponse, error) {

	params, err := c.PlumbingGenerateEndSessionRequestParam(r)
	if err != nil {
		return nil, err
	}

	req, err := c.PlumbingNewHttpEndSessionRequest(params)
	if err != nil {
		return nil, err
	}

	return c.PlumbingDoHttpEndSessionRequest(ctx, req)

}

func (c *OAuthClient) PlumbingGenerateEndSessionRequestParam(req *EndSessionRequest) (url.Values, error) {

	params := url.Values{}
	for _, opt := range req.opts {
		opt.SetValue(params)

	}

	return params, nil
}

func (c *OAuthClient) PlumbingNewHttpEndSessionRequest(params url.Values) (*http.Request, error) {

	assert.NotNil(params, assert.Panic, "oauth-client: params cannot be nil")
	assert.StrNotEmpty(c.wk.EndSessionEndpoint, assert.Panic, "oauth-client: missing 'end_session_endpoint'")

	switch c.endSessionHttpMethod {
	case http.MethodGet:

		// add params as query string
		var buf bytes.Buffer
		buf.WriteString(c.wk.EndSessionEndpoint)

		if strings.Contains(c.wk.AuthorizationEndpoint, "?") {
			buf.WriteByte('&')
		} else {
			buf.WriteByte('?')
		}
		buf.WriteString(params.Encode())
		endpoint := buf.String()

		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}

		return req, nil
	case http.MethodPost:

		// encode provided params, and create request
		req, err := http.NewRequest(http.MethodPost, c.wk.EndSessionEndpoint, strings.NewReader(params.Encode()))
		if err != nil {
			return nil, err
		}

		// Set Content Type
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil

	default:
		return nil, fmt.Errorf("end_session: unsupported method %s", c.endSessionHttpMethod)
	}

}

func (c *OAuthClient) PlumbingDoHttpEndSessionRequest(ctx context.Context, req *http.Request) (_ *EndSessionResponse, err error) {
	assert.NotNil(ctx, assert.Panic, "oauth-client: 'ctx' cannot be nil")
	assert.NotNil(req, assert.Panic, "oauth-client: 'req' cannot be nil")

	endpoint := "end_session"
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		metric.OAuthDurationHist.WithLabelValues(endpoint).Observe(v)
	}))
	defer timer.ObserveDuration()
	defer metric.DeferMonitorError(endpoint, &err)

	tracing.AddHeadersFromContext(ctx, req)

	client := c.getHttpClientWithoutRedirect()

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	// check redirect 301/302 status
	if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound {
		return &EndSessionResponse{
			Redirect: resp.Header.Get("Location"),
		}, nil
	}

	// check 204/200 status code
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return &EndSessionResponse{}, nil
	}

	// check error
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("end_session: %w", err)
		return nil, err
	}

	httpErr := &HttpErr{
		StatusCode:     resp.StatusCode,
		RespBody:       body,
		ResponseHeader: resp.Header,
	}

	err = fmt.Errorf("end_session: expected status code 200/204 301/302 but got '%d'", resp.StatusCode)
	httpErr.Err = err
	return nil, httpErr
}

func (c *OAuthClient) getHttpClientWithoutRedirect() *http.Client {

	return &http.Client{
		// http noRedirect client GO black magic
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: c.http.client.Transport,
		Timeout:   c.http.client.Timeout,
		// Jar: c.client.Jar,
	}
}
