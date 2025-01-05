package oauthx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vdbulcke/oauthx/assert"
	"github.com/vdbulcke/oauthx/metric"
	"github.com/vdbulcke/oauthx/tracing"
)

// WellKnownConfiguration rfc8414 and openid
// Well known configuration metadata
type WellKnownConfiguration struct {

	// REQUIRED.  The authorization server's issuer identifier, which is
	// a URL that uses the "https" scheme and has no query or fragment
	// components.  Authorization server metadata is published at a
	// location that is ".well-known" according to RFC 5785 [RFC5785]
	// derived from this issuer identifier, as described in Section 3.
	// The issuer identifier is used to prevent authorization server mix-
	// up attacks, as described in "OAuth 2.0 Mix-Up Mitigation"
	// [MIX-UP].
	Issuer string `json:"issuer,omitempty"  validate:"required"`

	// URL of the authorization server's authorization endpoint
	// [RFC6749].  This is REQUIRED unless no grant types are supported
	// that use the authorization endpoint.
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"  `

	// OPTIONAL.  URL of the authorization server's JWK Set [JWK]
	// document.  The referenced document contains the signing key(s) the
	// client uses to validate signatures from the authorization server.
	// This URL MUST use the "https" scheme.  The JWK Set MAY also
	// contain the server's encryption key or keys, which are used by
	// clients to encrypt requests to the server.  When both signing and
	// encryption keys are made available, a "use" (public key use)
	// parameter value is REQUIRED for all keys in the referenced JWK Set
	// to indicate each key's intended usage.
	JwksUri string `json:"jwks_uri,omitempty"  `

	// RECOMMENDED.  URL of the OP's UserInfo Endpoint [OpenID.Core].
	// This URL MUST use the "https" scheme and MAY contain port, path,
	// and query parameter components.
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"  `

	// OPTIONAL.  URL of the authorization server's OAuth 2.0 Dynamic
	// Client Registration endpoint [RFC7591].
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"  `

	// RECOMMENDED.  JSON array containing a list of the OAuth 2.0
	// [RFC6749] "scope" values that this authorization server supports.
	// Servers MAY choose not to advertise some supported scope values
	// even when this parameter is used.
	ScopesSupported []string `json:"scopes_supported,omitempty"  `

	// REQUIRED.  JSON array containing a list of the OAuth 2.0
	// "response_type" values that this authorization server supports.
	// The array values used are the same as those used with the
	// "response_types" parameter defined by "OAuth 2.0 Dynamic Client
	// Registration Protocol" [RFC7591].
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"  `

	// OPTIONAL.  JSON array containing a list of the OAuth 2.0
	// "response_mode" values that this authorization server supports, as
	// specified in "OAuth 2.0 Multiple Response Type Encoding Practices"
	// [OAuth.Responses].  If omitted, the default is "["query",
	// "fragment"]".  The response mode value "form_post" is also defined
	// in "OAuth 2.0 Form Post Response Mode" [OAuth.Post].
	ResponseModeSupported []string `json:"response_modes_supported,omitempty"  `

	// OPTIONAL.  JSON array containing a list of the OAuth 2.0 grant
	// type values that this authorization server supports.  The array
	// values used are the same as those used with the "grant_types"
	// parameter defined by "OAuth 2.0 Dynamic Client Registration
	// Protocol" [RFC7591].  If omitted, the default value is
	// "["authorization_code", "implicit"]".
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"  `

	// OPTIONAL.  JSON array containing a list of Proof Key for Code
	// Exchange (PKCE) [RFC7636] code challenge methods supported by this
	// authorization server.  Code challenge method values are used in
	// the "code_challenge_method" parameter defined in Section 4.3 of
	// [RFC7636].  The valid code challenge method values are those
	// registered in the IANA "PKCE Code Challenge Methods" registry
	// [IANA.OAuth.Parameters].  If omitted, the authorization server
	// does not support PKCE.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`

	// OPTIONAL.  JSON array containing a list of the Authentication
	// Context Class References that this OP supports.
	AcrValuesSupported []string `json:"acr_values_supported,omitempty"  `

	// REQUIRED.  JSON array containing a list of the Subject Identifier
	// types that this OP supports.  Valid types include "pairwise" and
	// "public".
	SubjectTypesSupported []string `json:"subject_types_supported,omitempty"  `

	// REQUIRED.  JSON array containing a list of the JWS signing
	// algorithms ("alg" values) supported by the OP for the ID Token to
	// encode the Claims in a JWT [JWT].  The algorithm "RS256" MUST be
	// included.  The value "none" MAY be supported but MUST NOT be used
	// unless the Response Type used returns no ID Token from the
	// Authorization Endpoint (such as when using the Authorization Code
	// Flow).
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"  `

	// OPTIONAL.  JSON array containing a list of the JWE encryption
	// algorithms ("enc" values) supported by the OP for the ID Token to
	// encode the Claims in a JWT [JWT].
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"  `

	// OPTIONAL.  JSON array containing a list of the JWE encryption
	// algorithms ("enc" values) supported by the OP for the ID Token to
	// encode the Claims in a JWT [JWT].
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported,omitempty"  `

	// OPTIONAL.  JSON array containing a list of the JWS [JWS] signing
	// algorithms ("alg" values) [JWA] supported by the UserInfo Endpoint
	// to encode the Claims in a JWT [JWT].  The value "none" MAY be
	// included.
	UserinfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported,omitempty"  `

	// OPTIONAL.  JSON array containing a list of the JWE [JWE]
	// encryption algorithms ("alg" values) [JWA] supported by the
	// UserInfo Endpoint to encode the Claims in a JWT [JWT].
	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"  `

	// OPTIONAL.  JSON array containing a list of the JWE encryption
	// algorithms ("enc" values) [JWA] supported by the UserInfo Endpoint
	// to encode the Claims in a JWT [JWT].
	UserinfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"  `

	// OPTIONAL.  JSON array containing a list of the JWS signing
	// algorithms ("alg" values) supported by the OP for Request Objects,
	// which are described in Section 6.1 of OpenID Connect Core 1.0
	// [OpenID.Core].  These algorithms are used both when the Request
	// Object is passed by value (using the "request" parameter) and when
	// it is passed by reference (using the "request_uri" parameter).
	// Servers SHOULD support "none" and "RS256".
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"  `

	// OPTIONAL.  JSON array containing a list of the JWE encryption
	// algorithms ("alg" values) supported by the OP for Request Objects.
	// These algorithms are used both when the Request Object is passed
	// by value and when it is passed by reference.
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"  `

	// OPTIONAL.  JSON array containing a list of the JWE encryption
	// algorithms ("enc" values) supported by the OP for Request Objects.
	// These algorithms are used both when the Request Object is passed
	// by value and when it is passed by reference.
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"  `

	// OPTIONAL.  JSON array containing a list of the "display" parameter
	// values that the OpenID Provider supports.  These values are
	// described in Section 3.1.2.1 of OpenID Connect Core 1.0
	// [OpenID.Core].
	DisplayValuesSupported []string `json:"display_values_supported,omitempty"  `

	// OPTIONAL.  JSON array containing a list of the Claim Types that
	// the OpenID Provider supports.  These Claim Types are described in
	// Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core].  Values
	// defined by this specification are "normal", "aggregated", and
	// "distributed".  If omitted, the implementation supports only
	// "normal" Claims.
	ClaimTypesSupported []string `json:"claim_types_supported,omitempty"  `

	// RECOMMENDED.  JSON array containing a list of the Claim Names of
	// the Claims that the OpenID Provider MAY be able to supply values
	// for.  Note that for privacy or other reasons, this might not be an
	// exhaustive list.
	ClaimsSupported []string `json:"claims_supported,omitempty"  `

	// OPTIONAL.  Languages and scripts supported for values in Claims
	// being returned, represented as a JSON array of BCP47 [RFC5646]
	// language tag values.  Not all languages and scripts are
	// necessarily supported for all Claim values.
	ClaimsLocalesSupported []string `json:"claims_locales_supported,omitempty"  `

	// OPTIONAL.  Languages and scripts supported for the user interface,
	// represented as a JSON array of language tag values from BCP 47
	// [RFC5646].  If omitted, the set of supported languages and scripts
	// is unspecified.
	UILocalesSupported []string `json:"ui_locales_supported,omitempty"  `

	// OPTIONAL.  Boolean value specifying whether the OP supports use of
	// the "claims" parameter, with "true" indicating support.  If
	// omitted, the default value is "false".
	ClaimsParameterSupported bool `json:"claims_parameter_supported,omitempty"  `

	// OPTIONAL.  Boolean value specifying whether the OP supports use of
	// the "request" parameter, with "true" indicating support.  If
	// omitted, the default value is "false".
	RequestParameterSupported bool `json:"request_parameter_supported,omitempty"  `

	// OPTIONAL.  Boolean value specifying whether the OP supports use of
	// the "request_uri" parameter, with "true" indicating support.  If
	// omitted, the default value is "true".
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported,omitempty"  `

	// OPTIONAL.  Boolean value specifying whether the OP requires any
	// "request_uri" values used to be pre-registered using the
	// "request_uris" registration parameter.  Pre-registration is
	// REQUIRED when the value is "true".  If omitted, the default value
	// is "false".
	RequireRequestUriRegistration bool `json:"require_request_uri_registration,omitempty"  `

	// The URL of the pushed authorization request endpoint at which a
	// client can post an authorization request to exchange for a
	// "request_uri" value usable at the authorization server.
	// https://www.rfc-editor.org/rfc/rfc9126.html#name-authorization-server-metada
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"  `

	// Boolean parameter indicating whether the authorization server
	// accepts authorization request data only via PAR.  If omitted, the
	// default value is "false".
	RequirePushedAuthorizationRequests bool `json:"require_pushed_authorization_requests,omitempty"  `

	// URL of the authorization server's token endpoint [RFC6749].  This
	// is REQUIRED unless only the implicit grant type is supported.
	TokenEndpoint string `json:"token_endpoint,omitempty"  `

	// OPTIONAL.  JSON array containing a list of client authentication
	// methods supported by this token endpoint.  Client authentication
	// method values are used in the "token_endpoint_auth_method"
	// parameter defined in Section 2 of [RFC7591].  If omitted, the
	// default is "client_secret_basic" -- the HTTP Basic Authentication
	// Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"  `

	// OPTIONAL.  JSON array containing a list of the JWS signing
	// algorithms ("alg" values) supported by the token endpoint for the
	// signature on the JWT [JWT] used to authenticate the client at the
	// token endpoint for the "private_key_jwt" and "client_secret_jwt"
	// authentication methods.  This metadata entry MUST be present if
	// either of these authentication methods are specified in the
	// "token_endpoint_auth_methods_supported" entry.  No default
	// algorithms are implied if this entry is omitted.  Servers SHOULD
	// support "RS256".  The value "none" MUST NOT be used.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"  `

	// OPTIONAL.  URL of the authorization server's OAuth 2.0
	// introspection endpoint [RFC7662].
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// OPTIONAL.  JSON array containing a list of client authentication
	// methods supported by this introspection endpoint.  The valid
	// client authentication method values are those registered in the
	// IANA "OAuth Token Endpoint Authentication Methods" registry
	// [IANA.OAuth.Parameters] or those registered in the IANA "OAuth
	// Access Token Types" registry [IANA.OAuth.Parameters].  (These
	// values are and will remain distinct, due to Section 7.2.)  If
	// omitted, the set of supported authentication methods MUST be
	// determined by other means.
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`

	// OPTIONAL.  JSON array containing a list of the JWS signing
	// algorithms ("alg" values) supported by the introspection endpoint
	// for the signature on the JWT [JWT] used to authenticate the client
	// at the introspection endpoint for the "private_key_jwt" and
	// "client_secret_jwt" authentication methods.  This metadata entry
	// MUST be present if either of these authentication methods are
	// specified in the "introspection_endpoint_auth_methods_supported"
	// entry.  No default algorithms are implied if this entry is
	// omitted.  The value "none" MUST NOT be used.
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`

	// OPTIONAL.  URL of the authorization server's OAuth 2.0 revocation
	// endpoint [RFC7009].
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// OPTIONAL.  JSON array containing a list of client authentication
	// methods supported by this revocation endpoint.  The valid client
	// authentication method values are those registered in the IANA
	// "OAuth Token Endpoint Authentication Methods" registry
	// [IANA.OAuth.Parameters].  If omitted, the default is
	// "client_secret_basic" -- the HTTP Basic Authentication Scheme
	// specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`

	// OPTIONAL.  JSON array containing a list of the JWS signing
	// algorithms ("alg" values) supported by the revocation endpoint for
	// the signature on the JWT [JWT] used to authenticate the client at
	// the revocation endpoint for the "private_key_jwt" and
	// "client_secret_jwt" authentication methods.  This metadata entry
	// MUST be present if either of these authentication methods are
	// specified in the "revocation_endpoint_auth_methods_supported"
	// entry.  No default algorithms are implied if this entry is
	// omitted.  The value "none" MUST NOT be used.
	RevocationEndpointAuthSigningAlgValuesSupported []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`

	// OPTIONAL.  URL that the authorization server provides to the
	// person registering the client to read about the authorization
	// server's requirements on how the client can use the data provided
	// by the authorization server.  The registration process SHOULD
	// display this URL to the person registering the client if it is
	// given.  As described in Section 5, despite the identifier
	// "op_policy_uri" appearing to be OpenID-specific, its usage in this
	// specification is actually referring to a general OAuth 2.0 feature
	// that is not specific to OpenID Connect.
	OpPolicyUri string `json:"op_policy_uri,omitempty"  `

	// OPTIONAL.  URL that the authorization server provides to the
	// person registering the client to read about the authorization
	// server's terms of service.  The registration process SHOULD
	// display this URL to the person registering the client if it is
	// given.  As described in Section 5, despite the identifier
	// "op_tos_uri", appearing to be OpenID-specific, its usage in this
	// specification is actually referring to a general OAuth 2.0 feature
	// that is not specific to OpenID Connect.
	OpTosUri string `json:"op_tos_uri,omitempty"  `

	// OPTIONAL.  URL of a page containing human-readable information
	// that developers might want or need to know when using the
	// authorization server.  In particular, if the authorization server
	ServiceDocumentation string `json:"service_documentation,omitempty" `

	// end_session_endpoint
	//    REQUIRED.  URL at the OP to which an RP can perform a redirect to
	//    request that the End-User be logged out at the OP.  This URL MUST
	//    use the "https" scheme and MAY contain port, path, and query
	//    parameter components.
	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"`

	// check_session_endpoint  URL of an OP endpoint that provides a page to
	//    support cross-origin communications for session state information
	//    with the RP client, using the HTML5 postMessage API.  The page is
	//    loaded from an invisible iframe embedded in an RP page so that it
	//    can run in the OP's security context.  It accepts postMessage
	//    requests from the relevant RP iframe and postMessage back the
	//    login status of the user at the OP.
	CheckSessionEndpoint string `json:"check_session_endpoint,omitempty"`

	WellKnownRaw []byte
}

type WellKnownOtpFunc func(*WellKnownOptions)

// WellKnownOptions options for making the
// call to the metadata endpoint
type WellKnownOptions struct {
	http *httpLimitClient
}

// WellKnownWithHttpClient set a [http.Client] and a limit for the http response
// for the metadata endpoint call.
//
// # The limit is expressed as max number of bytes read from the response body
//
// See [oauthx.WellKnownWithHttpClientDefaultLimit] as alternative options
func WellKnownWithHttpClient(client *http.Client, limit int64) WellKnownOtpFunc {
	return func(wko *WellKnownOptions) {
		if client == nil {
			client = http.DefaultClient
		}

		if limit < 0 {
			panic("http client limit cannot be negative")
		}

		wko.http = newHttpLimitClient(limit, client)
	}
}

// WellKnownWithHttpClientDefaultLimit set a [http.Client] and a limit for the http response
// for the metadata endpoint call.
//
// The limit is expressed as max number of bytes read from the response body
// and is set to [oauthx.LIMIT_HTTP_RESP_BODY_MAX_SIZE_BYTES]
//
// See [oauthx.WellKnownWithHttpClient] as alternative options
func WellKnownWithHttpClientDefaultLimit(client *http.Client) WellKnownOtpFunc {
	return func(wko *WellKnownOptions) {
		if client == nil {
			client = http.DefaultClient
		}

		wko.http = newHttpLimitClient(LIMIT_HTTP_RESP_BODY_MAX_SIZE_BYTES, client)
	}
}

// NewWellKnownOpenidConfiguration fetch "/.well-known/openid-configuration"
// based on [issuer] according to OpenID Connect Discovery 1.0
//
// Use [oauthx.WellKnownWithHttpClient] or [oauthx.WellKnownWithHttpClientDefaultLimit] as options.
// By Default, uses  [http.DefaultClient] and [oauthx.LIMIT_HTTP_RESP_BODY_MAX_SIZE_BYTES] as limit
func NewWellKnownOpenidConfiguration(ctx context.Context, issuer string, opts ...WellKnownOtpFunc) (_ *WellKnownConfiguration, err error) {
	assert.StrNotEmpty(issuer, assert.Panic, "oidc-wellknown: issuer cannot be empty")
	// OpenID Connect Discovery 1.0
	//  OpenID Providers supporting Discovery MUST make a JSON document
	//  available at the path formed by concatenating the string
	//  "/.well-known/openid-configuration" to the Issuer.
	wkEndpoint := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	wk, err := fetchWellKnown(ctx, wkEndpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}

	// OpenID Connect Discovery 1.0
	//   The "issuer" value returned MUST be identical to the Issuer URL that
	//   was used as the prefix to "/.well-known/openid-configuration" to
	//   retrieve the configuration information.
	if wk.Issuer != issuer {
		return nil, fmt.Errorf("oidc: well-known issuer not matching. expected %s got %s ", issuer, wk.Issuer)
	}

	return wk, nil
}

// NewWellKnownOAuthAuthorizationServer fetch "/.well-known/oauth-authorization-server"
// based on [issuer] according to rfc8414: OAuth 2.0 Authorization Server Metadata
//
// Use [oauthx.WellKnownWithHttpClient] or [oauthx.WellKnownWithHttpClientDefaultLimit] as options.
// By Default, uses  [http.DefaultClient] and [oauthx.LIMIT_HTTP_RESP_BODY_MAX_SIZE_BYTES] as limit
func NewWellKnownOAuthAuthorizationServer(ctx context.Context, issuer string, opts ...WellKnownOtpFunc) (_ *WellKnownConfiguration, err error) {
	assert.StrNotEmpty(issuer, assert.Panic, "rfc8414: issuer cannot be empty")

	// rfc8414: OAuth 2.0 Authorization Server Metadata
	//   Authorization servers supporting metadata MUST make a JSON document
	//   containing metadata as specified in Section 2 available at a path
	//   formed by inserting a well-known URI string into the authorization
	//   server's issuer identifier between the host component and the path
	//   component, if any.  By default, the well-known URI string used is
	//   "/.well-known/oauth-authorization-server".  This path MUST use the
	//   "https" scheme.

	wkEndpoint := strings.TrimSuffix(issuer, "/") + "/.well-known/oauth-authorization-server"

	wk, err := fetchWellKnown(ctx, wkEndpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("rfc8414: %w", err)
	}

	// rfc8414: OAuth 2.0 Authorization Server Metadata
	//   The "issuer" value returned MUST be identical to the authorization
	//   server's issuer identifier value into which the well-known URI string
	//   was inserted to create the URL used to retrieve the metadata.  If
	//   these values are not identical, the data contained in the response
	//   MUST NOT be used.
	if wk.Issuer != issuer {
		return nil, fmt.Errorf("rfc8414: well-known issuer not matching. expected %s got %s ", issuer, wk.Issuer)
	}

	return wk, nil
}

// NewInsecureWellKnownEndpoint fetch metadata from [wkEndpoint]
// without any validation
//
// Use [oauthx.WellKnownWithHttpClient] or [oauthx.WellKnownWithHttpClientDefaultLimit] as options.
// By Default, uses  [http.DefaultClient] and [oauthx.LIMIT_HTTP_RESP_BODY_MAX_SIZE_BYTES] as limit
func NewInsecureWellKnownEndpoint(ctx context.Context, wkEndpoint string, opts ...WellKnownOtpFunc) (_ *WellKnownConfiguration, err error) {
	return fetchWellKnown(ctx, wkEndpoint, opts...)
}

func fetchWellKnown(ctx context.Context, wkEndpoint string, opts ...WellKnownOtpFunc) (_ *WellKnownConfiguration, err error) {
	assert.StrNotEmpty(wkEndpoint, assert.Panic, "well-known endpoint is required")

	endpoint := "well-known"
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		metric.OAuthDurationHist.WithLabelValues(endpoint).Observe(v)
	}))
	defer timer.ObserveDuration()
	defer metric.DeferMonitorError(endpoint, &err)

	opt := &WellKnownOptions{
		http: newHttpLimitClient(LIMIT_HTTP_RESP_BODY_MAX_SIZE_BYTES, http.DefaultClient),
	}

	for _, fn := range opts {
		fn(opt)
	}

	req, err := http.NewRequest(http.MethodGet, wkEndpoint, nil)
	if err != nil {
		return nil, err
	}
	tracing.AddHeadersFromContext(ctx, req)

	resp, err := opt.http.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, opt.http.maxSizeBytes))
	if err != nil {
		return nil, err
	}

	if len(body) >= int(opt.http.maxSizeBytes) {
		return nil, fmt.Errorf("well-known: http resp body max size limit exceeded: %d bytes", opt.http.maxSizeBytes)
	}

	if resp.StatusCode != http.StatusOK {
		err = &HttpErr{
			RespBody:       body,
			StatusCode:     resp.StatusCode,
			ResponseHeader: resp.Header,
			Err:            fmt.Errorf("invalid status code %d expected %d", resp.StatusCode, http.StatusOK),
		}

		return nil, err
	}

	var wk WellKnownConfiguration

	err = json.Unmarshal(body, &wk)
	if err != nil {
		err = &HttpErr{
			RespBody:       body,
			StatusCode:     resp.StatusCode,
			ResponseHeader: resp.Header,
			Err:            err,
		}
		return nil, err
	}

	return &wk, nil
}

func (c *OAuthClient) GetWellknown() *WellKnownConfiguration {
	return c.wk
}
