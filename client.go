package oauthx

import (
	"net/http"
	"time"

	"github.com/vdbulcke/oauthx/assert"
)

type OAuthClient struct {
	ClientId string

	wk *WellKnownConfiguration

	staticAuthzRequestOpt []OAuthOption

	rfc9101JarJwtTTL time.Duration

	authmethod AuthMethod
	privateKey OAuthPrivateKey
	keySet     JWKSet

	userinfoHttpMethod   string
	endSessionHttpMethod string

	// client *http.Client
	http *httpLimitClient
}

type OAuthClientOptFunc func(*OAuthClient)

// WithAuthMethod set the [oauthx.AuthMethod] for this client
//
// default to [oauthx.None]
func WithAuthMethod(method AuthMethod) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.authmethod = method
	}
}

// WithRFC9101JarJwtTTL set the time to live for the
// 'request=' jwt parameter when using [oauthx.WithGeneratedRequestJWT]
// or [oauthx.WithStrictGeneratedRequestJWT]
func WithRFC9101JarJwtTTL(ttl time.Duration) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.rfc9101JarJwtTTL = ttl
	}
}

// WithStaticAuthzRequestOpt add static [oauthx.OAuthOption] that can be used
// to contruct a new [oauthx.AuthZRequest] with [oauthx.NewClientBaseAuthzRequest]
func WithStaticAuthzRequestOpt(opt ...OAuthOption) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.staticAuthzRequestOpt = opt
	}
}

// WithOAuthPrivateKey set the [oauthx.OAuthPrivateKey] for this client
// used to generate 'request=' jwt parameter, decrypt eventually encrytped
// userinfo, introspect, id_token jwt.
func WithOAuthPrivateKey(key OAuthPrivateKey) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.privateKey = key
	}
}

// WithKeySet override the default [oauthx.RemoteJWKSet]
// from the 'jwks_uri' endpoint of the WellKknown
func WithKeySet(ks JWKSet) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.keySet = ks
	}
}

// WithHttpClient override the default [http.DefaultClient] for
// this [oauthx.OAuthClient]
//
// use the default [oauthx.LIMIT_HTTP_RESP_BODY_MAX_SIZE_BYTES]
func WithHttpClient(client *http.Client) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.http = newHttpLimitClient(LIMIT_HTTP_RESP_BODY_MAX_SIZE_BYTES, client)
	}
}

// WithHttpClient override the default [http.DefaultClient] for
// this [oauthx.OAuthClient] and set the max reponse size limit
// for the http response body.
//
// see [oauthx.WithHttpClient] as alternative
func WithHttpClientWithLimit(client *http.Client, limit int64) OAuthClientOptFunc {
	if limit < 0 {
		panic("http limit cannot be negative")
	}
	return func(oc *OAuthClient) {
		oc.http = newHttpLimitClient(limit, client)
	}
}

// WithUserinfoHttpMethod override the default
// [http.MethodGet] for making userinfo request
func WithUserinfoHttpMethod(method string) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.userinfoHttpMethod = method
	}
}

// WithEndSessionHttpMethod override the default
// [http.MethodGet] for making endSession request
func WithEndSessionHttpMethod(method string) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.endSessionHttpMethod = method
	}
}

// NewOAuthClient create a new [oauthx.OAuthClient] with options
//
// Example:
//
//	// you should create your own *http.Client especially for
//	// production
//	httpClient := client_http.GenerateMyCustomHttpClient()
//	//
//	// create a context with trace-id header, for
//	// making the initial WellKnown http request
//	ctx := context.Background()
//	traceId := uuid.New().String()
//	ctx = tracing.ContextWithTraceID(ctx, "x-trace-id", traceId)
//	//
//	// fetch the '/.well-known/openid-configuration' metadata
//	issuer := "https://my.authorization.server.com"
//	wk, err = oauthx.NewWellKnownOpenidConfiguration(ctx, issuer, httpClient)
//	if err != nil {
//	    return nil, fmt.Errorf("oidc wellknown: %w", err)
//	}
//	//
//	// create a AuthMethod
//	clientId := "my_client_id"
//	auth := oauthx.NewClientSecretPost(clientId, "my-super-secure-secret")
//	//
//	// finally create the OAuthClient, with some options
//	client := oauthx.NewOAuthClient(clientId, wk,
//	    // settting the auth method
//	    oauthx.WithAuthMethod(auth),
//	    // setting the production http.Client
//	    oauthx.WithHttpClient(httpClient),
//	)
func NewOAuthClient(clientId string, wk *WellKnownConfiguration, opts ...OAuthClientOptFunc) *OAuthClient {
	assert.NotNil(wk, assert.Panic, "oauth-client: WellKnownConfiguration are required")
	assert.StrNotEmpty(clientId, assert.Panic, "clientId cannot be empty")

	c := &OAuthClient{
		ClientId:             clientId,
		wk:                   wk,
		authmethod:           NewAuthMethodNone(clientId), // default no auth method
		http:                 newHttpLimitClient(LIMIT_HTTP_RESP_BODY_MAX_SIZE_BYTES, http.DefaultClient),
		rfc9101JarJwtTTL:     10 * time.Minute,
		userinfoHttpMethod:   http.MethodGet,
		endSessionHttpMethod: http.MethodGet,
	}

	// aplly all options
	for _, fn := range opts {
		fn(c)
	}

	// no explicit keyset default to
	// 'jwks_uri' from metadata if defined
	if c.keySet == nil && c.wk.JwksUri != "" {
		c.keySet = NewRemoteJWKSet(wk.JwksUri, withRemoteJWKSetlimitClient(c.http))
	}

	return c
}
