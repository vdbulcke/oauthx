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
	"github.com/vdbulcke/oauthx/assert"
	"github.com/vdbulcke/oauthx/metric"
	"github.com/vdbulcke/oauthx/tracing"
)

type EndSessionResponse struct {
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

	tracing.AddTraceIDFromContext(ctx, req)

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
	return nil, err
}

func (c *OAuthClient) getHttpClientWithoutRedirect() *http.Client {

	return &http.Client{
		// http noRedirect client GO black magic
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: c.client.Transport,
		Timeout:   c.client.Timeout,
		// Jar: c.client.Jar,
	}
}
