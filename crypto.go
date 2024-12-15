package oauthx

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

// OAuthPrivateKey interface for signing jwt
type OAuthPrivateKey interface {
	SignJWT(claims jwt.Claims) (string, error)           // signs jwt claims
	SupportedDecryptAlg(alg string) bool                 // return true if alg is suppported for decryption
	DecryptJWT(encryptedJwt, alg string) (string, error) // decrypt jwt
}

type JwtAdvertiser interface {
	GetKid() string        // return active kid
	JWKS() ([]byte, error) // marshal of JWKS
}

// NewJwtSigner create a JwtSigned for the correspond key type
//
// supported key tupes are [rsa.PrivateKey] and [ecdsa.PrivateKey]
//
// Set [staticKid] to "" (empty string) to generate kid based on public key
func NewOAuthPrivateKey(key crypto.PrivateKey, alg, staticKid string) (OAuthPrivateKey, error) {

	// case key to derive hc vault key type
	switch priv := key.(type) {
	case *rsa.PrivateKey:

		return NewRSAJWTSigner(priv, alg, staticKid)

	case *ecdsa.PrivateKey:

		return NewECJWTSigner(priv, alg, staticKid)
	default:
		return nil, errors.New("unsupported key type. Must be one of RSA or EC")
	}

}

// kid generates a kid by sha256 sum public key
func kid(k crypto.PublicKey) (string, error) {

	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return "", err
	}

	hasher := crypto.SHA256.New()
	if _, err := hasher.Write(publicKeyDERBytes); err != nil {
		return "", err
	}
	publicKeyDERHash := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(publicKeyDERHash), nil
}

func (c *OAuthClient) GetOAuthPrivateKey() OAuthPrivateKey {
	return c.privateKey
}
