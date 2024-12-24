package oauthx

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
)

// Constants defined in the RFC7636
// https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
const (
	charSet         = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	charSetLength   = byte(len(charSet))
	minSize         = 43
	maxSize         = 128
	PKCEMethodPlain = "plain"
	PKCEMethodS256  = "S256"
)

// GenerateVerifier generates a PKCE code verifier with 32 octets of randomness.
// This follows recommendations in RFC 7636.
func GenerateVerifier() string {

	data, err := genCryptoSecureRandomBytes(50)
	if err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(data)
}

// VerifierOption returns a PKCE code verifier AuthCodeOption
func PKCEVerifierOpt(verifier string) OAuthOption {
	return setParam{k: "code_verifier", v: verifier}
}

// PKCES256ChallengeFromVerifier returns a PKCE code challenge derived from verifier with method S256.
//
// Prefer to use S256ChallengeOption where possible.
func PKCES256ChallengeFromVerifier(verifier string) string {
	sha := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sha[:])
}

// PKCES256ChallengeOpt derives a PKCE code challenge derived from verifier with
// method S256.
func PKCES256ChallengeOpt(verifier string) OAuthOption {
	return challengeOption{
		challenge_method: "S256",
		challenge:        PKCES256ChallengeFromVerifier(verifier),
		verifier:         verifier,
	}
}

// PKCEOpt generates a new verifier and adds pkce option with method S256.
func PKCEOpt() OAuthOption {
	verifier := GenerateVerifier()
	return challengeOption{
		challenge_method: "S256",
		challenge:        PKCES256ChallengeFromVerifier(verifier),
		verifier:         verifier,
	}
}

type challengeOption struct{ challenge_method, challenge, verifier string }

func (p challengeOption) SetValue(m url.Values) {
	m.Set("code_challenge_method", p.challenge_method)
	m.Set("code_challenge", p.challenge)
}

func (p challengeOption) SetClaim(m map[string]interface{}) {
	m["code_challenge_method"] = p.challenge_method
	m["code_challenge"] = p.challenge
}

func (p challengeOption) SetRequestContext(oauthCtx *OAuthContext) {
	oauthCtx.PKCECodeVerifier = p.verifier
}
