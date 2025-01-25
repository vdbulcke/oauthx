package oauthx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vdbulcke/oauthx/assert"
	"github.com/vdbulcke/oauthx/metric"
	"github.com/vdbulcke/oauthx/tracing"
)

// 5.1.  Successful Response
//
//	The authorization server issues an access token and optional refresh
//	token, and constructs the response by adding the following parameters
//	to the entity-body of the HTTP response with a 200 (OK) status code:
//
//	access_token
//	      REQUIRED.  The access token issued by the authorization server.
//
//	token_type
//	      REQUIRED.  The type of the token issued as described in
//	      Section 7.1.  Value is case insensitive.
//
//	expires_in
//	      RECOMMENDED.  The lifetime in seconds of the access token.  For
//	      example, the value "3600" denotes that the access token will
//	      expire in one hour from the time the response was generated.
//	      If omitted, the authorization server SHOULD provide the
//	      expiration time via other means or document the default value.
//
//	refresh_token
//	      OPTIONAL.  The refresh token, which can be used to obtain new
//	      access tokens using the same authorization grant as described
//	      in Section 6.
//
//	scope
//	      OPTIONAL, if identical to the scope requested by the client;
//	      otherwise, REQUIRED.  The scope of the access token as
//	      described by Section 3.3.
//
//	The parameters are included in the entity-body of the HTTP response
//	using the "application/json" media type as defined by [RFC4627].  The
//	parameters are serialized into a JavaScript Object Notation (JSON)
//	structure by adding each parameter at the highest structure level.
//	Parameter names and string values are included as JSON strings.
//	Numerical values are included as JSON numbers.  The order of
//	parameters does not matter and can vary.
//
//	The authorization server MUST include the HTTP "Cache-Control"
//	response header field [RFC2616] with a value of "no-store" in any
//	response containing tokens, credentials, or other sensitive
//	information, as well as the "Pragma" response header field [RFC2616]
//	with a value of "no-cache".
//
// OpenID Connect Core 1.0
// 3.1.3.3.  Successful Token Response
// id_token
//
//	ID Token value associated with the authenticated session.
type TokenResponse struct {
	//    access_token
	//          REQUIRED.  The access token issued by the authorization server.
	AccessToken string `json:"access_token"`
	//    token_type
	//          REQUIRED.  The type of the token issued as described in
	//          Section 7.1.  Value is case insensitive.
	TokenType string `json:"token_type"`
	//    expires_in
	//          RECOMMENDED.  The lifetime in seconds of the access token.  For
	//          example, the value "3600" denotes that the access token will
	//          expire in one hour from the time the response was generated.
	//          If omitted, the authorization server SHOULD provide the
	//          expiration time via other means or document the default value.
	//
	ExpiresIn expirationTime `json:"expires_in,omitempty"`
	//    refresh_token
	//          OPTIONAL.  The refresh token, which can be used to obtain new
	//          access tokens using the same authorization grant as described
	//          in Section 6.
	RefreshToken string `json:"refresh_token,omitempty"`
	//    scope
	//          OPTIONAL, if identical to the scope requested by the client;
	//          otherwise, REQUIRED.  The scope of the access token as
	//          described by Section 3.3.
	Scope string `json:"scope,omitempty"`

	// OpenID Connect Core 1.0
	// 3.1.3.3.  Successful Token Response
	// id_token
	//    ID Token value associated with the authenticated session.
	IDToken string `json:"id_token,omitempty"`
	// raw json body
	Raw json.RawMessage `json:"-"`

	// used to compute expiration
	receivedAt time.Time `json:"-"`
}

func (resp *TokenResponse) GetExpiration() time.Time {
	delta := time.Duration(resp.ExpiresIn) * time.Second
	return resp.receivedAt.Add(delta)
}

func (c *OAuthClient) DoTokenRequest(ctx context.Context, tr *TokenRequest) (*TokenResponse, error) {
	assert.NotNil(ctx, assert.Panic, "oauth-client: 'ctx' cannot be nil")
	assert.NotNil(tr, assert.Panic, "oauth-client: 'TokenRequest' cannot be nil")

	params, err := c.PlumbingGenerateTokenRequestParam(tr)
	if err != nil {
		return nil, err
	}

	req, err := c.PlumbingNewHttpTokenRequest(params)
	if err != nil {
		return nil, err
	}

	return c.PlumbingDoHttpTokenRequest(ctx, req)
}

func (c *OAuthClient) PlumbingGenerateTokenRequestParam(req *TokenRequest) (url.Values, error) {

	params := url.Values{}
	for _, opt := range req.opts {
		opt.SetValue(params)

	}

	return params, nil
}

func (c *OAuthClient) PlumbingNewHttpTokenRequest(params url.Values) (*http.Request, error) {
	assert.NotNil(c.authmethod, assert.Panic, "oauth-client: missing required 'authmethod'")
	assert.NotNil(params, assert.Panic, "oauth-client: params cannot be nil")
	assert.StrNotEmpty(c.wk.TokenEndpoint, assert.Panic, "oauth-client: missing 'token_endpoint'")

	return c.authmethod.NewOAuthAuthenticatedRequest(TokenEndpoint, c.wk.TokenEndpoint, params)
}

func (c *OAuthClient) PlumbingDoHttpTokenRequest(ctx context.Context, req *http.Request) (_ *TokenResponse, err error) {
	assert.NotNil(ctx, assert.Panic, "rfc6749: 'ctx' cannot be nil")
	assert.NotNil(req, assert.Panic, "rfc6749: 'req' cannot be nil")

	endpoint := "token"
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
		err = fmt.Errorf("rfc6749: %w", err)
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

	//	The authorization server issues an access token and optional refresh
	//	token, and constructs the response by adding the following parameters
	//	to the entity-body of the HTTP response with a 200 (OK) status code:
	if resp.StatusCode != http.StatusOK {
		httpErr.Err = fmt.Errorf("rfc6749: expected status code 200 but got '%d'", resp.StatusCode)
		err = httpErr
		return nil, err
	}

	//	The parameters are included in the entity-body of the HTTP response
	//	using the "application/json" media type as defined by [RFC4627].  The
	//	parameters are serialized into a JavaScript Object Notation (JSON)
	//	structure by adding each parameter at the highest structure level.
	//	Parameter names and string values are included as JSON strings.
	//	Numerical values are included as JSON numbers.  The order of
	//	parameters does not matter and can vary.
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if ct != "application/json" {
		httpErr.Err = fmt.Errorf("rfc6749: expected Content-Type 'application/json' but got '%s'", ct)
		err = httpErr
		return nil, err
	}

	var raw json.RawMessage
	err = json.Unmarshal(body, &raw)
	if err != nil {
		return nil, fmt.Errorf("rfc6749: invalid json %w", err)
	}

	var tokenResp TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return nil, fmt.Errorf("rfc6749: invalid json %w", err)
	}

	tokenResp.receivedAt = time.Now()
	tokenResp.Raw = raw

	return &tokenResp, nil
}

// from golang.org/x/oauth2
type expirationTime int32

func (e *expirationTime) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	var n json.Number
	err := json.Unmarshal(b, &n)
	if err != nil {
		return err
	}
	i, err := n.Int64()
	if err != nil {
		return err
	}
	if i > math.MaxInt32 {
		i = math.MaxInt32
	}
	*e = expirationTime(i)
	return nil
}
