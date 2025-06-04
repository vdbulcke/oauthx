package oauthx

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/vdbulcke/assert"
)

func (c *OAuthClient) PlumbingGenerateRFC9101RequestJwt(claims map[string]interface{}) (string, error) {
	assert.NotNil(c.privateKey, assert.Panic, "rfc9101: private key required for generating 'request' JAR")

	jwtClaims := jwt.MapClaims{}

	jwtClaims["exp"] = jwt.NewNumericDate(time.Now().Add(c.rfc9101JarJwtTTL))
	jwtClaims["iat"] = jwt.NewNumericDate(time.Now())
	jwtClaims["nbf"] = jwt.NewNumericDate(time.Now())

	// rfc9101
	// The value of "aud" should be the value of
	// the authorization server (AS) "issuer", as defined in RFC 8414
	// [RFC8414].
	jwtClaims["aud"] = c.wk.Issuer
	jwtClaims["iss"] = c.ClientId

	// add extra claims
	for k, v := range claims {
		jwtClaims[k] = v
	}

	signedJwt, err := c.privateKey.SignJWT(jwtClaims)
	if err != nil {
		return "", fmt.Errorf("rfc9101: %w", err)
	}

	return signedJwt, nil
}
