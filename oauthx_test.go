package oauthx_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/vdbulcke/oauthx"
	"github.com/vdbulcke/oauthx/assert"
)

type validateRequest func(req *http.Request) error

type mockAS struct {
	validatePARRequest        validateRequest
	validateTokenRequest      validateRequest
	validateIntrospectRequest validateRequest
	mockServer                *httptest.Server
}

func newMockAS(validatePAR, validateToken, validateIntrospect validateRequest) *mockAS {

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	m := &mockAS{
		validatePARRequest:        validatePAR,
		validateTokenRequest:      validateToken,
		validateIntrospectRequest: validateIntrospect,
		mockServer:                srv,
	}
	mux.HandleFunc("/.well-known/openid-configuration", m.wkHanler())
	mux.HandleFunc("/par", m.parHandler())
	mux.HandleFunc("/token", m.tokenHandler())
	mux.HandleFunc("/introspect", m.introspectHandler())

	return m
}

func (ms *mockAS) getIssuer() string {
	return ms.mockServer.URL
}
func (ms *mockAS) getHttpClient() *http.Client {
	return ms.mockServer.Client()
}

func (ms *mockAS) getWellknown() *oauthx.WellKnownConfiguration {
	baseUrl := ms.mockServer.URL

	return &oauthx.WellKnownConfiguration{
		Issuer:                             baseUrl,
		PushedAuthorizationRequestEndpoint: fmt.Sprintf("%s/par", baseUrl),
		AuthorizationEndpoint:              fmt.Sprintf("%s/auth", baseUrl),
		JwksUri:                            fmt.Sprintf("%s/jwks_uri", baseUrl),
		UserinfoEndpoint:                   fmt.Sprintf("%s/userinfo", baseUrl),
		TokenEndpoint:                      fmt.Sprintf("%s/token", baseUrl),
		IntrospectionEndpoint:              fmt.Sprintf("%s/introspect", baseUrl),
		RevocationEndpoint:                 fmt.Sprintf("%s/revoke", baseUrl),
		EndSessionEndpoint:                 fmt.Sprintf("%s/endsession", baseUrl),
	}
}

func (ms *mockAS) wkHanler() http.HandlerFunc {

	wk := ms.getWellknown()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		// w.WriteHeader()
		err := json.NewEncoder(w).Encode(wk)
		assert.ErrNotNil(err, assert.Panic, "wkHandler json")
	}
}

func (ms *mockAS) parHandler() http.HandlerFunc {

	resp := &struct {
		RequestUri string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}{
		RequestUri: "urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2",
		ExpiresIn:  90,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		err := ms.validatePARRequest(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(201)
		err = json.NewEncoder(w).Encode(resp)
		assert.ErrNotNil(err, assert.Panic, "parHandler json")
	}
}

func (ms *mockAS) tokenHandler() http.HandlerFunc {

	resp := &struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    any    `json:"expires_in,omitempty"`
		RefreshToken string `json:"refresh_token,omitempty"`
	}{
		AccessToken: "2YotnFZFEjr1zCsicMWpAA",
		TokenType:   "Bearer",
		ExpiresIn:   "3600", // weird server that sends number as string
	}

	return func(w http.ResponseWriter, r *http.Request) {
		err := ms.validateTokenRequest(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		w.Header().Add("Content-Type", "application/json")
		// w.WriteHeader()
		err = json.NewEncoder(w).Encode(resp)
		assert.ErrNotNil(err, assert.Panic, "tokenHandler json")
	}
}

func (ms *mockAS) introspectHandler() http.HandlerFunc {

	resp := &struct {
		Active bool `json:"active"`
	}{
		Active: true,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		err := ms.validateIntrospectRequest(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		w.Header().Add("Content-Type", "application/json")
		// w.WriteHeader()
		err = json.NewEncoder(w).Encode(resp)
		assert.ErrNotNil(err, assert.Panic, "introspectHandler json")
	}
}

type makeAuthzRequest func() *oauthx.AuthZRequest

func TestAuthZcodeFlow(t *testing.T) {
	tbl := []struct {
		testName                 string
		valid                    bool
		PARRequiredParam         []string
		AuthorizeRequiredParam   []string
		TokenRequiredParam       []string
		IntrospectRequiredParam  []string
		authorizationRequestFunc makeAuthzRequest
	}{
		{
			testName:                "basic authz code flow ",
			valid:                   true,
			PARRequiredParam:        []string{"client_id", "scope", "response_type", "code_challenge", "code_challenge_method"},
			AuthorizeRequiredParam:  []string{"client_id", "scope", "response_type", "code_challenge", "code_challenge_method", "redirect_uri"},
			TokenRequiredParam:      []string{"client_id", "grant_type", "code", "redirect_uri", "code_verifier"},
			IntrospectRequiredParam: []string{"token"},
			authorizationRequestFunc: func() *oauthx.AuthZRequest {
				req := oauthx.NewBaseAuthzRequest()
				req.AddOpts(
					oauthx.ClientIdOpt("oauthx-test"),
					oauthx.RedirectUriOpt("http://example.com/callback"),
					oauthx.ScopeOpt([]string{"openid", "profile"}),
				)
				return req
			},
		},
		{
			testName:                "invalid: required par",
			valid:                   false,
			PARRequiredParam:        []string{"client_id", "scope", "response_type", "code_challenge", "code_challenge_method"},
			AuthorizeRequiredParam:  []string{"client_id", "request_uri"},
			TokenRequiredParam:      []string{"client_id", "grant_type", "code", "redirect_uri", "code_verifier"},
			IntrospectRequiredParam: []string{"token"},
			authorizationRequestFunc: func() *oauthx.AuthZRequest {
				req := oauthx.NewBaseAuthzRequest()
				req.AddOpts(
					oauthx.ClientIdOpt("oauthx-test"),
					oauthx.RedirectUriOpt("http://example.com/callback"),
					oauthx.ScopeOpt([]string{"openid", "profile"}),
				)
				return req
			},
		},
		{
			testName:                "valid: required par",
			valid:                   true,
			PARRequiredParam:        []string{"client_id", "scope", "response_type", "code_challenge", "code_challenge_method"},
			AuthorizeRequiredParam:  []string{"client_id", "request_uri"},
			TokenRequiredParam:      []string{"client_id", "grant_type", "code", "redirect_uri", "code_verifier"},
			IntrospectRequiredParam: []string{"token"},
			authorizationRequestFunc: func() *oauthx.AuthZRequest {
				req := oauthx.NewBaseAuthzRequest()
				req.AddOpts(
					oauthx.ClientIdOpt("oauthx-test"),
					oauthx.RedirectUriOpt("http://example.com/callback"),
					oauthx.ScopeOpt([]string{"openid", "profile"}),
					oauthx.WithPushedAuthotizationRequest(),
				)
				return req
			},
		},
		{
			testName:                "invalid: strict required param",
			valid:                   false,
			PARRequiredParam:        []string{"client_id", "request"},
			AuthorizeRequiredParam:  []string{"client_id", "request_uri", "scope", "response_type", "redirect_uri"},
			TokenRequiredParam:      []string{"client_id", "grant_type", "code", "redirect_uri", "code_verifier"},
			IntrospectRequiredParam: []string{"token"},
			authorizationRequestFunc: func() *oauthx.AuthZRequest {
				req := oauthx.NewBaseAuthzRequest()
				req.AddOpts(
					oauthx.ClientIdOpt("oauthx-test"),
					oauthx.RedirectUriOpt("http://example.com/callback"),
					oauthx.ScopeOpt([]string{"openid", "profile"}),
					oauthx.WithPushedAuthotizationRequest(),
					oauthx.WithGeneratedRequestJWTOnly(),
				)
				return req
			},
		},
		{
			testName:                "valid: strict required param",
			valid:                   true,
			PARRequiredParam:        []string{"client_id", "request"},
			AuthorizeRequiredParam:  []string{"client_id", "request_uri", "scope", "response_type", "redirect_uri"},
			TokenRequiredParam:      []string{"client_id", "grant_type", "code", "redirect_uri", "code_verifier"},
			IntrospectRequiredParam: []string{"token"},
			authorizationRequestFunc: func() *oauthx.AuthZRequest {
				req := oauthx.NewBaseAuthzRequest()
				req.AddOpts(
					oauthx.ClientIdOpt("oauthx-test"),
					oauthx.RedirectUriOpt("http://example.com/callback"),
					oauthx.ScopeOpt([]string{"openid", "profile"}),
					oauthx.WithPushedAuthotizationRequest(),
					oauthx.WithGeneratedRequestJWTOnly(),
					oauthx.WithStrictRequiredAuthorizationParams(),
				)
				return req
			},
		},
		{
			testName:                "valid: strict required param without par",
			valid:                   true,
			PARRequiredParam:        []string{"client_id", "request"},
			AuthorizeRequiredParam:  []string{"client_id", "request", "scope", "response_type", "redirect_uri"},
			TokenRequiredParam:      []string{"client_id", "grant_type", "code", "redirect_uri", "code_verifier"},
			IntrospectRequiredParam: []string{"token"},
			authorizationRequestFunc: func() *oauthx.AuthZRequest {
				req := oauthx.NewBaseAuthzRequest()
				req.AddOpts(
					oauthx.ClientIdOpt("oauthx-test"),
					oauthx.RedirectUriOpt("http://example.com/callback"),
					oauthx.ScopeOpt([]string{"openid", "profile"}),
					oauthx.WithGeneratedRequestJWTOnly(),
					oauthx.WithStrictRequiredAuthorizationParams(),
				)
				return req
			},
		},
		{
			testName:                "invalid: strict required param without par",
			valid:                   false,
			PARRequiredParam:        []string{"client_id", "request"},
			AuthorizeRequiredParam:  []string{"client_id", "request", "scope", "response_type", "redirect_uri"},
			TokenRequiredParam:      []string{"client_id", "grant_type", "code", "redirect_uri", "code_verifier"},
			IntrospectRequiredParam: []string{"token"},
			authorizationRequestFunc: func() *oauthx.AuthZRequest {
				req := oauthx.NewBaseAuthzRequest()
				req.AddOpts(
					oauthx.ClientIdOpt("oauthx-test"),
					oauthx.RedirectUriOpt("http://example.com/callback"),
					oauthx.ScopeOpt([]string{"openid", "profile"}),
					oauthx.WithGeneratedRequestJWTOnly(),
					// oauthx.WithStrictRequiredAuthorizationParams(),
				)
				return req
			},
		},
	}

	clientRS256key := assert.Must(rsa.GenerateKey(rand.Reader, 2048))
	clientOAuthKey := assert.Must(oauthx.NewOAuthPrivateKey(clientRS256key, "RS256", "client-kid"))

	for _, test := range tbl {
		t.Run(test.testName, func(t *testing.T) {
			srv := newMockAS(
				func(req *http.Request) error {

					req.ParseForm()
					requiredParam := test.PARRequiredParam

					for _, k := range requiredParam {
						if !req.Form.Has(k) {
							return fmt.Errorf("missing required key %s", k)
						}
					}
					return nil
				},
				func(req *http.Request) error {
					req.ParseForm()
					requiredParam := test.TokenRequiredParam

					for _, k := range requiredParam {
						if !req.Form.Has(k) {
							return fmt.Errorf("missing required key %s", k)
						}
					}
					return nil

				},
				func(req *http.Request) error {
					req.ParseForm()
					requiredParam := test.IntrospectRequiredParam

					for _, k := range requiredParam {
						if !req.Form.Has(k) {
							return fmt.Errorf("missing required key %s", k)
						}
					}
					return nil
				},
			)

			defer srv.mockServer.Close()

			client := oauthx.NewOAuthClient(
				"oauthx-test",
				srv.getWellknown(),
				oauthx.WithHttpClient(srv.getHttpClient()),
				oauthx.WithOAuthPrivateKey(clientOAuthKey),
			)

			// authorization request
			req := test.authorizationRequestFunc()

			ctx := context.Background()
			authz, err := client.DoAuthorizationRequest(ctx, req)
			if err != nil && test.valid {
				t.Error("invalid authorization request", err)
				var httpErr *oauthx.HttpErr
				if errors.As(err, &httpErr) {
					t.Error("http error", "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))
				}
				t.FailNow()
			}

			requiredParam := test.AuthorizeRequiredParam
			authzUrl := assert.Must(url.Parse(authz.Url))

			for _, k := range requiredParam {
				if !authzUrl.Query().Has(k) && test.valid {
					t.Error("authorization url error missing required param", k)
					t.FailNow()
				}
			}

			code := "SplxlOBeZQQYbYS6WxSbIA"

			//
			tokenReq := oauthx.NewAuthorizationCodeGrantTokenRequest(code, authz.ReqCtx)

			token, err := client.DoTokenRequest(ctx, tokenReq)
			if err != nil && test.valid {
				var httpErr *oauthx.HttpErr
				if errors.As(err, &httpErr) {
					t.Error("http error", "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))
				}
				t.Error("invalid token request", err, "req", tokenReq)
				t.FailNow()
			}

			if token.AccessToken == "" {
				t.Error("invalid token response: missing access_token", token)
				t.FailNow()
			}

			introspection := oauthx.NewIntrospectionRequest(
				oauthx.TokenOpt(token.AccessToken),
			)
			_, err = client.DoIntrospectionRequest(ctx, introspection)
			if err != nil && test.valid {
				var httpErr *oauthx.HttpErr
				if errors.As(err, &httpErr) {
					t.Error("http error", "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))
				}
				t.Error("invalid token request", err, "req", introspection)
				t.FailNow()
			}

		})
	}
}
