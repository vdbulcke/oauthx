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

	client *http.Client
}

type OAuthClientOptFunc func(*OAuthClient)

func WithAuthMethod(method AuthMethod) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.authmethod = method
	}
}

func WithRFC9101JarJwtTTL(ttl time.Duration) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.rfc9101JarJwtTTL = ttl
	}
}

func WithStaticAuthzRequestOpt(opt ...OAuthOption) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.staticAuthzRequestOpt = opt
	}
}

func WithOAuthPrivateKey(key OAuthPrivateKey) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.privateKey = key
	}
}

func WithKeySet(ks JWKSet) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.keySet = ks
	}
}

func WithHttpClient(client *http.Client) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.client = client
	}
}

func WithUserinfoHttpMethod(method string) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.userinfoHttpMethod = method
	}
}

func WithEndSessionHttpMethod(method string) OAuthClientOptFunc {
	return func(oc *OAuthClient) {
		oc.endSessionHttpMethod = method
	}
}

func NewOAuthClient(clientId string, wk *WellKnownConfiguration, opts ...OAuthClientOptFunc) *OAuthClient {
	assert.NotNil(wk, assert.Panic, "oauth-client: WellKnownConfiguration are required")
	assert.StrNotEmpty(clientId, assert.Panic, "clientId cannot be empty")

	c := &OAuthClient{
		ClientId:             clientId,
		wk:                   wk,
		authmethod:           NewAuthMethodNone(), // default no auth method
		client:               http.DefaultClient,
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
		c.keySet = NewRemoteJWKSet(wk.JwksUri, WithRemoteJWKSetHttpClient(c.client))
	}

	return c
}
