package oauthx

import (
	"net/http"

	"github.com/vdbulcke/oauthx/assert"
)

type httpLimitClient struct {
	maxSizeBytes int64
	client       *http.Client
}

func newHttpLimitClient(n int64, c *http.Client) *httpLimitClient {
	assert.NotNil(c, assert.Panic)

	return &httpLimitClient{
		maxSizeBytes: n,
		client:       c,
	}
}
