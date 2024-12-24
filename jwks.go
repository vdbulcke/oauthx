package oauthx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/go-jose/go-jose/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vdbulcke/oauthx/assert"
	"github.com/vdbulcke/oauthx/metric"
	"github.com/vdbulcke/oauthx/tracing"
)

type JWKSet interface {
	VerifySignature(ctx context.Context, sig *jose.JSONWebSignature) error
}

func (c *OAuthClient) GetJWKSet() JWKSet {
	return c.keySet
}

type RemoteJWKSetOptFunc func(ks *RemoteJWKSet)

func WithRemoteJWKSetAlwaysSyncOnErr() RemoteJWKSetOptFunc {
	return func(ks *RemoteJWKSet) {
		ks.reSyncOnErr = true
	}
}
func WithRemoteJWKSetHttpClient(client *http.Client) RemoteJWKSetOptFunc {
	return func(ks *RemoteJWKSet) {
		ks.client = client
	}
}

// RemoteJWKSet implements the [oauthx.JWKSet] interface.
//
// It will fetch and cache the Jwks from the remote jwks_uri endpoint.
type RemoteJWKSet struct {
	JwksUri string

	reSyncOnErr bool

	client       *http.Client
	requestGroup singleflight.Group
	cache        jose.JSONWebKeySet
	mu           sync.RWMutex
}

func NewRemoteJWKSet(jwksUri string, opts ...RemoteJWKSetOptFunc) *RemoteJWKSet {

	defaultKS := &RemoteJWKSet{
		JwksUri:     jwksUri,
		reSyncOnErr: false,
		client:      http.DefaultClient,
		cache:       jose.JSONWebKeySet{},
	}

	for _, fn := range opts {
		fn(defaultKS)
	}

	return defaultKS
}

func (ks *RemoteJWKSet) VerifySignature(ctx context.Context, sig *jose.JSONWebSignature) error {
	assert.NotNil(ctx, assert.Panic, "jwks_uri: ctx cannot be nil")

	if len(sig.Signatures) == 0 {
		return fmt.Errorf("jwks_uri: jwt is not signed")
	}
	if len(sig.Signatures) > 1 {
		return fmt.Errorf("jwks_uri: jwt has multiple signature")
	}

	// from cache
	set := ks.getJwkSet()

	_, err := sig.Verify(set)
	if err == nil {
		return nil
	}

	// if signature verifcation from cached keyset failed
	// return err, unless
	// - Kid was not found in cache
	// - or the flag always resync err is enable
	if !ks.reSyncOnErr && !errors.Is(err, jose.ErrJWKSKidNotFound) {
		return fmt.Errorf("jwks_uri: signature verify %w", err)
	}

	set, err = ks.getJwkSetWithSync(ctx)
	if err != nil {
		return fmt.Errorf("jwks_uri: sync %w", err)
	}

	_, err = sig.Verify(set)
	if err != nil {
		return fmt.Errorf("jwks_uri: signature verify %w", err)
	}

	return nil
}

func (ks *RemoteJWKSet) syncRemoteJwksUri(ctx context.Context) (err error) {
	assert.StrNotEmpty(ks.JwksUri, assert.Panic, "jwks_uri endpoint is required")

	endpoint := "jwks_uri"
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		metric.OAuthDurationHist.WithLabelValues(endpoint).Observe(v)
	}))
	defer timer.ObserveDuration()
	defer metric.DeferMonitorError(endpoint, &err)

	req, err := http.NewRequest(http.MethodGet, ks.JwksUri, nil)
	if err != nil {
		return err
	}

	tracing.AddTraceIDFromContext(ctx, req)

	resp, err := ks.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		err = &HttpErr{
			RespBody:       body,
			StatusCode:     resp.StatusCode,
			ResponseHeader: resp.Header,
			Err:            fmt.Errorf("invalid status code %d expected %d", resp.StatusCode, http.StatusOK),
		}
		return err
	}

	var jwks jose.JSONWebKeySet
	err = json.Unmarshal(body, &jwks)
	if err != nil {
		err = &HttpErr{
			RespBody:       body,
			StatusCode:     resp.StatusCode,
			ResponseHeader: resp.Header,
			Err:            fmt.Errorf("jwks_uri: %w", err),
		}
		return err
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.cache = jwks

	return nil
}

func (ks *RemoteJWKSet) getJwkSet() jose.JSONWebKeySet {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.cache
}

func (ks *RemoteJWKSet) getJwkSetWithSync(ctx context.Context) (jose.JSONWebKeySet, error) {

	_, err, _ := ks.requestGroup.Do(ks.JwksUri, func() (interface{}, error) {
		err := ks.syncRemoteJwksUri(ctx)
		if err != nil {
			return false, fmt.Errorf("jwks_uri: inflight %w", err)
		}

		return true, nil
	})
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}

	return ks.getJwkSet(), nil
}
