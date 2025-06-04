package oauthx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vdbulcke/assert"
	"github.com/vdbulcke/oauthx/metric"
	"github.com/vdbulcke/oauthx/tracing"
)

// DoRevokeRequest
//
// Example:
//
//	req := oauthx.NewRevokeRequest(
//	    oauthx.TokenOpt(token),
//	    oauthx.TokenTypeHintOpt(oauthx.TokenTypeRefreshToken),
//	)
//
//	err := c.client.DoRevokeRequest(ctx, req)
//	if err != nil {
//	    // handle err
//	    return err
//	}
//
// implements rfc7009
func (c *OAuthClient) DoRevokeRequest(ctx context.Context, r *RevokeRequest) error {
	assert.NotNil(ctx, assert.Panic, "oauth-client: 'ctx' cannot be nil")
	assert.NotNil(r, assert.Panic, "oauth-client: 'RevokeRequest' cannot be nil")

	params, err := c.PlumbingGenerateRevokeRequestParam(r)
	if err != nil {
		return err
	}

	req, err := c.PlumbingNewHttpRevocationRequest(params)
	if err != nil {
		return err
	}

	return c.PlumbingDoHttpRevocationRequest(ctx, req)
}

func (c *OAuthClient) PlumbingGenerateRevokeRequestParam(req *RevokeRequest) (url.Values, error) {

	params := url.Values{}
	for _, opt := range req.opts {
		opt.SetValue(params)

	}

	return params, nil
}

func (c *OAuthClient) PlumbingNewHttpRevocationRequest(params url.Values) (*http.Request, error) {
	assert.NotNil(c.authmethod, assert.Panic, "oauth-client: missing required 'authmethod'")
	assert.NotNil(params, assert.Panic, "oauth-client: params cannot be nil")
	assert.StrNotEmpty(c.wk.RevocationEndpoint, assert.Panic, "oauth-client: missing 'revocation_endpoint'")

	return c.authmethod.NewOAuthAuthenticatedRequest(RevocationEndpoint, c.wk.RevocationEndpoint, params)
}

func (c *OAuthClient) PlumbingDoHttpRevocationRequest(ctx context.Context, req *http.Request) (err error) {
	assert.NotNil(ctx, assert.Panic, "oauth-client: 'ctx' cannot be nil")
	assert.NotNil(req, assert.Panic, "oauth-client: 'req' cannot be nil")

	endpoint := "revoke"
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		metric.OAuthDurationHist.WithLabelValues(endpoint).Observe(v)
	}))
	defer timer.ObserveDuration()
	defer metric.DeferMonitorError(endpoint, &err)

	tracing.AddHeadersFromContext(ctx, req)

	resp, err := c.http.client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// 2.2.  Revocation Response
	//
	//    The authorization server responds with HTTP status code 200 if the
	//    token has been revoked successfully or if the client submitted an
	//    invalid token.
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(io.LimitReader(resp.Body, c.http.maxSizeBytes))
		if err != nil {
			err = fmt.Errorf("rfc7009: %w", err)
			return err
		}

		httpErr := &HttpErr{
			StatusCode:     resp.StatusCode,
			RespBody:       body,
			ResponseHeader: resp.Header,
		}
		if len(body) >= int(c.http.maxSizeBytes) {
			err = fmt.Errorf("http-limit: http resp body max size limit exceeded: %d bytes", c.http.maxSizeBytes)
			httpErr.Err = err
			return httpErr
		}

		httpErr.Err = fmt.Errorf("rfc7009: expected status code 200 but got '%d'", resp.StatusCode)
		err = httpErr
		return err
	}

	// Note: invalid tokens do not cause an error response since the client
	// cannot handle such an error in a reasonable way.  Moreover, the
	// purpose of the revocation request, invalidating the particular token,
	// is already achieved.

	// The content of the response body is ignored by the client as all
	// necessary information is conveyed in the response code.

	// An invalid token type hint value is ignored by the authorization
	// server and does not influence the revocation response.
	return nil
}
