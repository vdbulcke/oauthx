package oauthx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vdbulcke/oauthx/assert"
	"github.com/vdbulcke/oauthx/metric"
	"github.com/vdbulcke/oauthx/tracing"
)

type PushedAuthorizationRequestResponse struct {

	// request_uri
	//    The request URI corresponding to the authorization request posted.
	//    This URI is a single-use reference to the respective request data
	//    in the subsequent authorization request.  The way the
	//    authorization process obtains the authorization request data is at
	//    the discretion of the authorization server and is out of scope of
	//    this specification.  There is no need to make the authorization
	//    request data available to other parties via this URI.
	RequestUri string `json:"request_uri"`

	// expires_in
	//    A JSON number that represents the lifetime of the request URI in
	//    seconds as a positive integer.  The request URI lifetime is at the
	//    discretion of the authorization server but will typically be
	//    relatively short (e.g., between 5 and 600 seconds).
	ExpiresIn int `json:"expires_in"`

	// raw json body
	Raw json.RawMessage

	// used to compute expiration
	receivedAt time.Time
}

func (resp *PushedAuthorizationRequestResponse) GetExpiration() time.Time {
	delta := time.Duration(resp.ExpiresIn) * time.Second
	return resp.receivedAt.Add(delta)
}

func (c *OAuthClient) PlumbingNewHttpPARRequest(params url.Values) (*http.Request, error) {
	assert.NotNil(c.authmethod, assert.Panic, "oauth-client: missing required 'authmethod'")
	assert.NotNil(params, assert.Panic, "oauth-client: params cannot be nil")
	assert.StrNotEmpty(c.wk.PushedAuthorizationRequestEndpoint, assert.Panic, "oauth-client: missing 'pushed_authorization_request_endpoint'")

	// rfc9126
	// 2.  Reject the request if the "request_uri" authorization request
	//     parameter is provided.
	if params.Has("request_uri") {
		return nil, fmt.Errorf("rfc9126: 'request_uri' cannot be included in PAR request")
	}

	return c.authmethod.NewOAuthAuthenticatedRequest(PushedAuthorizationRequestEndpoint, c.wk.PushedAuthorizationRequestEndpoint, params)
}

func (c *OAuthClient) PlumbingDoHttpPARRequest(ctx context.Context, req *http.Request) (_ *PushedAuthorizationRequestResponse, err error) {
	assert.NotNil(ctx, assert.Panic, "rfc9126: 'ctx' cannot be nil")
	assert.NotNil(req, assert.Panic, "rfc9126: 'req' cannot be nil")

	endpoint := "par"
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		metric.OAuthDurationHist.WithLabelValues(endpoint).Observe(v)
	}))
	defer timer.ObserveDuration()
	defer metric.DeferMonitorError(endpoint, &err)

	tracing.AddHeadersFromContext(ctx, req)

	resp, err := c.http.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.http.maxSizeBytes))
	if err != nil {
		err = fmt.Errorf("rfc9126: %w", err)
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

	// If the verification is successful, the server MUST generate a request
	// URI and provide it in the response with a "201" HTTP status code.
	if resp.StatusCode != http.StatusCreated {
		httpErr.Err = fmt.Errorf("rfc9126: expected status code 201 but got '%d'", resp.StatusCode)
		err = httpErr
		return nil, err
	}

	// The following parameters are included as top-level members in the
	// message body of the HTTP response using the "application/json" media
	// type as defined by [RFC8259].
	// ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))

	// if ct != "application/json"  {

	// }

	var raw json.RawMessage
	err = json.Unmarshal(body, &raw)
	if err != nil {
		return nil, fmt.Errorf("rfc9126: invalid json %w", err)
	}

	var parResp PushedAuthorizationRequestResponse
	err = json.Unmarshal(body, &parResp)
	if err != nil {
		return nil, fmt.Errorf("rfc9126: invalid json %w", err)
	}

	parResp.receivedAt = time.Now()
	parResp.Raw = raw

	return &parResp, nil
}
