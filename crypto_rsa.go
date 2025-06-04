package oauthx

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
)

var (
	_ JwtAdvertiser   = (*RSAJWTSigner)(nil)
	_ OAuthPrivateKey = (*RSAJWTSigner)(nil)
)

// RSAJWTSigner an implementation of
// [oauthx.OAuthPrivateKey] and [oauthx.JwtAdvertiser] for
// [rsa.PrivateKey]
type RSAJWTSigner struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string

	alg           string
	signingMethod jwt.SigningMethod
}

// NewRSAJWTSigner create a [oauthx.ECJWTSigner] from
// [rsa.PrivateKey], with alg (MUST one of RS256,RS384, RS512).
//
// if staticKid is empty generate a kid based on the bytes of
// the [rsa.PublicKey]
func NewRSAJWTSigner(k *rsa.PrivateKey, alg, staticKid string) (*RSAJWTSigner, error) {
	var method jwt.SigningMethod
	switch alg {
	case "RS256":
		method = jwt.SigningMethodRS256
	case "RS384":
		method = jwt.SigningMethodRS384
	case "RS512":
		method = jwt.SigningMethodRS512

	default:
		return nil, fmt.Errorf("unsuported signing alg %s for RSA private key ", alg)

	}
	rsaKid := staticKid
	if rsaKid == "" {
		var err error
		rsaKid, err = kid(&k.PublicKey)
		if err != nil {
			return nil, err
		}
	}
	return &RSAJWTSigner{
		PrivateKey:    k,
		PublicKey:     &k.PublicKey,
		Kid:           rsaKid,
		alg:           alg,
		signingMethod: method,
	}, nil

}

func (k *RSAJWTSigner) GetKid() string {
	return k.Kid
}

// JWKS is the JSON JWKS representation of the rsa.PublicKey
func (k *RSAJWTSigner) JWKS() ([]byte, error) {

	sig := jose.JSONWebKey{
		Use: "sig",
		// Algorithm:                 k.alg,
		Key:   k.PublicKey,
		KeyID: k.Kid,
		// Certificates:              []*x509.Certificate{cert},
		// CertificateThumbprintSHA1: fingerprint[:],
	}

	enc := jose.JSONWebKey{
		Use: "enc",

		Key:   k.PublicKey,
		KeyID: k.Kid,
		// Certificates:              []*x509.Certificate{cert},
		// CertificateThumbprintSHA1: fingerprint[:],
	}
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{sig, enc},
	}

	return json.Marshal(jwks)
}

// SignJWT signs jwt.Claims with the Keypair and returns a token string
func (k *RSAJWTSigner) SignJWT(claims jwt.Claims, extraHeaderFields ...*HeaderField) (string, error) {
	token := jwt.NewWithClaims(k.signingMethod, claims)

	token.Header["kid"] = k.Kid

	for _, hf := range extraHeaderFields {
		if hf == nil {
			continue
		}

		token.Header[hf.Key] = hf.Value
	}

	return token.SignedString(k.PrivateKey)
}

func (k *RSAJWTSigner) SupportedDecryptAlg(alg string) bool {
	switch alg {
	case "RSA-OAEP-256":
		return true

	case "RSA-OAEP":
		return true
	default:
		return false
	}
}

// DecryptJWT decrypt jwt
func (k *RSAJWTSigner) DecryptJWT(encryptedJwt, alg string) (string, error) {
	var method jwa.KeyAlgorithm

	switch alg {
	case "RSA-OAEP-256":
		method = jwa.RSA_OAEP_256

	case "RSA-OAEP":
		method = jwa.RSA_OAEP
	default:
		return "", fmt.Errorf("unsupported encryption alg %s", alg)
	}

	decrypted, err := jwe.Decrypt([]byte(encryptedJwt), jwe.WithKey(method, k.PrivateKey))
	if err != nil {
		return "", err
	}

	return string(decrypted), nil

}
