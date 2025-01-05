package oauthx_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/vdbulcke/oauthx"
	"github.com/vdbulcke/oauthx/assert"
)

type mockServer struct {
	// key                              crypto.PrivateKey
	// kid                              string
	// alg                              string
	key                              oauthx.OAuthPrivateKey
	IDTokenSigningAlgValuesSupported []string

	mockServer *httptest.Server
}

func newMockServer(k crypto.PrivateKey, alg, mockKid string) *mockServer {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)

	key := assert.Must(oauthx.NewOAuthPrivateKey(k, alg, mockKid))
	mock := &mockServer{
		key:        key,
		mockServer: srv,
	}

	mux.HandleFunc("/.well-known/openid-configuration", mock.wkHanler())
	mux.HandleFunc("/jwks_uri", mock.jwksHanler())

	return mock
}

func (ms *mockServer) getWellknown() *oauthx.WellKnownConfiguration {
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
		IDTokenSigningAlgValuesSupported:   ms.IDTokenSigningAlgValuesSupported,
	}
}

func (ms *mockServer) jwksHanler() http.HandlerFunc {

	key, ok := ms.key.(oauthx.JwtAdvertiser)
	if !ok {
		panic("invalid interface")
	}

	jwks := assert.Must(key.JWKS())

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		// w.WriteHeader()
		w.Write(jwks)
	}
}

func (ms *mockServer) wkHanler() http.HandlerFunc {

	wk := ms.getWellknown()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		// w.WriteHeader()
		err := json.NewEncoder(w).Encode(wk)
		assert.ErrNotNil(err, assert.Panic, "wkHandler json")
	}
}

func genIdToken(key crypto.PrivateKey, alg, kid string, claims jwt.MapClaims) string {
	k := assert.Must(oauthx.NewOAuthPrivateKey(key, alg, kid))
	return assert.Must(k.SignJWT(claims))
}

func genEncryptedIdToken(key crypto.PrivateKey, alg, kid string, claims jwt.MapClaims, clientJwkPublicKey crypto.PublicKey, jwaAlg jwa.KeyAlgorithm) string {
	k := assert.Must(oauthx.NewOAuthPrivateKey(key, alg, kid))
	signedJwt := assert.Must(k.SignJWT(claims))

	encrypted := assert.Must(jwe.Encrypt([]byte(signedJwt), jwe.WithKey(jwaAlg, clientJwkPublicKey)))
	return string(encrypted)
}

func TestIDTokenParse(t *testing.T) {

	serverkey := assert.Must(rsa.GenerateKey(rand.Reader, 2048))
	clientRS256key := assert.Must(rsa.GenerateKey(rand.Reader, 2048))
	clientES384key := assert.Must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	mockServerRS256 := newMockServer(
		serverkey,
		"RS256",
		"123456789",
	)
	defer mockServerRS256.mockServer.Close()

	clientId := "oauthx-test"
	ctx := context.Background()
	httpClient := mockServerRS256.mockServer.Client()

	wk := assert.Must(oauthx.NewWellKnownOpenidConfiguration(ctx, mockServerRS256.mockServer.URL, oauthx.WellKnownWithHttpClientDefaultLimit(httpClient)))

	clientOAuthKey := assert.Must(oauthx.NewOAuthPrivateKey(clientRS256key, "RS256", "client-kid"))

	client := oauthx.NewOAuthClient(clientId, wk,
		oauthx.WithHttpClient(httpClient),
		oauthx.WithOAuthPrivateKey(clientOAuthKey),
	)

	past := time.Now().Add(-10 * time.Hour)

	tbl := []struct {
		testName string
		mock     *mockServer
		client   *oauthx.OAuthClient
		idToken  string
		valid    bool
	}{
		{
			testName: "valid token",
			valid:    true,
			client:   client,
			mock:     mockServerRS256,
			idToken: genIdToken(
				serverkey,
				"RS256",
				"123456789",
				jwt.MapClaims{
					"iss": mockServerRS256.getWellknown().Issuer,
					"aud": clientId,
					"exp": jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
					"iat": jwt.NewNumericDate(time.Now()),
					"nbf": jwt.NewNumericDate(time.Now()),
					"sub": "alice",
				},
			),
		},
		{
			testName: "valid encrypted token",
			valid:    true,
			client:   client,
			mock:     mockServerRS256,
			idToken: genEncryptedIdToken(
				serverkey,
				"RS256",
				"123456789",
				jwt.MapClaims{
					"iss": mockServerRS256.getWellknown().Issuer,
					"aud": clientId,
					"exp": jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
					"iat": jwt.NewNumericDate(time.Now()),
					"nbf": jwt.NewNumericDate(time.Now()),
					"sub": "alice",
				},
				clientRS256key,
				jwa.RSA_OAEP,
			),
		},
		{
			testName: "invalid encrypted token",
			valid:    false,
			client:   client,
			mock:     mockServerRS256,
			idToken: genEncryptedIdToken(
				serverkey,
				"RS256",
				"123456789",
				jwt.MapClaims{
					"iss": mockServerRS256.getWellknown().Issuer,
					"aud": clientId,
					"exp": jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
					"iat": jwt.NewNumericDate(time.Now()),
					"nbf": jwt.NewNumericDate(time.Now()),
					"sub": "alice",
				},
				clientES384key,
				jwa.ECDH_ES_A128KW, // use unsupported encryption alg got client
			),
		},
		{
			testName: "valid token: multiple audiance",
			valid:    true,
			client:   client,
			mock:     mockServerRS256,
			idToken: genIdToken(
				serverkey,
				"RS256",
				"123456789",
				jwt.MapClaims{
					"iss": mockServerRS256.getWellknown().Issuer,
					"aud": jwt.ClaimStrings{"foo", "bar", clientId},
					"exp": jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
					"iat": jwt.NewNumericDate(time.Now()),
					"nbf": jwt.NewNumericDate(time.Now()),
					"sub": "alice",
				},
			),
		},
		{
			testName: "unvalid token: kid",
			valid:    false,
			client:   client,
			mock:     mockServerRS256,
			idToken: genIdToken(
				serverkey,
				"RS256",
				"wrong-kid",
				jwt.MapClaims{
					"iss": mockServerRS256.getWellknown().Issuer,
					"aud": clientId,
					"exp": jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
					"iat": jwt.NewNumericDate(time.Now()),
					"nbf": jwt.NewNumericDate(time.Now()),
					"sub": "alice",
				},
			),
		},
		{
			testName: "unvalid token: wrong issuer",
			valid:    false,
			client:   client,
			mock:     mockServerRS256,
			idToken: genIdToken(
				serverkey,
				"RS256",
				"123456789",
				jwt.MapClaims{
					"iss": "https://wrong.issuer.com",
					"aud": clientId,
					"exp": jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
					"iat": jwt.NewNumericDate(time.Now()),
					"nbf": jwt.NewNumericDate(time.Now()),
					"sub": "alice",
				},
			),
		},
		{
			testName: "unvalid token:  expired",
			valid:    false,
			client:   client,
			mock:     mockServerRS256,
			idToken: genIdToken(
				serverkey,
				"RS256",
				"123456789",
				jwt.MapClaims{
					"iss": mockServerRS256.getWellknown().Issuer,
					"aud": clientId,
					"exp": jwt.NewNumericDate(past.Add(15 * time.Minute)),
					"iat": jwt.NewNumericDate(past),
					"nbf": jwt.NewNumericDate(past),
					"sub": "alice",
				},
			),
		},
		{
			testName: "unvalid token: missing required claim",
			valid:    false,
			client:   client,
			mock:     mockServerRS256,
			idToken: genIdToken(
				serverkey,
				"RS256",
				"123456789",
				jwt.MapClaims{
					"iss": mockServerRS256.getWellknown().Issuer,
					// "aud": clientId,
					"exp": jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
					"iat": jwt.NewNumericDate(time.Now()),
					"nbf": jwt.NewNumericDate(time.Now()),
					"sub": "alice",
				},
			),
		},
		{
			testName: "unvalid token: wrong signature ",
			valid:    false,
			client:   client,
			mock:     mockServerRS256,
			idToken: genIdToken(
				assert.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)),
				"ES256",
				"123456789",
				jwt.MapClaims{
					"iss": mockServerRS256.getWellknown().Issuer,
					"aud": clientId,
					"exp": jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
					"iat": jwt.NewNumericDate(time.Now()),
					"nbf": jwt.NewNumericDate(time.Now()),
					"sub": "alice",
				},
			),
		},
	}

	for _, test := range tbl {
		t.Run(test.testName, func(t *testing.T) {
			assert.NotNil(test.client, assert.Panic, "a *oauthx.OAuthClient must be defined for each test")

			_, err := test.client.ParseIDToken(ctx, test.idToken)
			if test.valid && err != nil {
				t.Log("expected valid but got error", err)
				t.Fail()
			} else if !test.valid && err == nil {

				t.Log("expected  invalid but got no error")
				t.Fail()
			}
		})
	}

}
