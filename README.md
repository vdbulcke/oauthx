# `oauthx` a complete oauth2/oidc client library

> WARNING: 🚧 still under construction 🚧 

implements the following standards:

- rfc6749/openid-connect-core: OAuth2/OIDC Authorization code flow 
- rfc7636: PKCE and `none` auth method
- rfc6772: OAuth2 Token Introspection
- draft-ietf-oauth-jwt-introspection-response-03: JWT Response for OAuth Token Introspection
- rfc7009: OAuth2 Token Revocation
- rfc8414: OAuth 2.0 Authorization Server Metadata 
- rfc6749: OAuth2 RefreshToken
- rfc6749: `client_secret_basic`, `client_secret_post` auth method
- rfc7523: OAuth2 `private_key_jwt` 
- rfc9101: JAR (`request=` jwt parameter)
- rfc9126: Pushed Authorization Request (`request_uri` parameter)
- rfc9396: RAR (`authorization_details`)
- rfc9068: JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens (JWT AccessToken)
- openid-connect-core: 3.1.3.7.  ID Token Validation
- openid-connect-core: 3.1.3.8.  Access Token Validation
- openid-connect-core: 5.5.   Requesting Claims using the "claims" Request Parameter`claims=`
- openid-connect-core: 5.3.   UserInfo Endpoint
- openid-connect-core: 5.1.   Standard Claims
- openid-connect-discovery: `/.well-known/openid-configuration`
- openid-connect-rpinitiated: RP initiated logout (endSession)

## Documentation

See [godoc](https://pkg.go.dev/github.com/vdbulcke/oauthx) or [doc](doc/) dir.

### Feature Examples

#### Creating a OAuthClient with builtin AuthMethod

Builtin AuthMethod:

- `none` (**default**)
- `client_secret_basic`
- `client_secret_post`
- `private_key_jwt`

See [Getting Started](doc/README.md) example for more info

You can also create your own auth method by implementing a simple interface, see [Custom Auth Method](doc/custom_auth_method.md) for
an example implementation of Bearer Token Auth Method for token introspection. 

#### Openid Connect Authorization Code Flow example

See [Authorization Code Flow](doc/authorization_code_flow.md) example for a sample
implementation of the authorization code flow using with go standard http handler, id_token validation, userinfo call.

#### Other flows

- [Client Credentials Grant Flow](doc/client_credentials.md)
- [Refresh Token Grant Flow](doc/refresh_token.md)
- [Token Introspection](doc/introspection.md)

#### PAR (rfc9126)/JAR (rfc9101)/RAR (rfc9396) example

This library provides ergonomic api for adding support for Pushed Authorization Request, Jwt-secured Authorization Request (`request=` jwt),
Rich Authotization Request (`authorization_details`) in your authorization request by adding extra options to your `oauthx.AuthZRequest`.  

See [PAR RAR JAR](doc/par_rar_jar.md) example for more info.

#### Http: client, tracing, custom header, custom error, response limit

This library has first class support for adding tracing header (and arbitrary headers) to http requests via `context.Context`.

It is encouraged to provide your own instance `*http.Client` with options.

Http and unmarshalling errors are returned using a custom `error` (`*oauthx.HttpErr`) that includes http response code, http response header, and
http response body. It also as a builtin support for OAuth2 rfc6749 standard error. 

Inspired by [tigerbeetle's Tiger Style](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md) this library has http response size
limits (default `oauthx.LIMIT_HTTP_RESP_BODY_MAX_SIZE_BYTES`) that you can override by using `oauthx.WellKnownWithHttpClient()` and `oauthx.WithHttpClientWithLimit`
options for fetching the wellknown metadata, and the oauth client respectively.


See [http tunning](doc/http.md) for more info.

### Tiger Style

This library is inspired by [tigerbeetle's Tiger Style](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md) and implements some
of the features, such as assertions and limits (on http responses).

The library has several assertion on input parameters, and will print as stacktrace on `stderr` then panic if one assertion fails (for example
passing `nil` pointer as input).

### Plumbing and Porcelain

Inspired by [git](https://git-scm.com/book/en/v2/Git-Internals-Plumbing-and-Porcelain), this library provides ergonomic "porcelain" api (it is
recommended to only use the "procelain" function), but it also exposes its internal "plumbing" functions.

All the "plumbing" function are prefixed with `Plumbing` (for example [PlumbingDoHttpPARRequest](https://pkg.go.dev/github.com/vdbulcke/oauthx#OAuthClient.PlumbingDoHttpPARRequest)).
Plumbing functions can be used if you want to make your own http request, and parsing the http response.

### other features

- Supports ID Token encryption (Nested JWT), and/or signed
- Builtin support for Remote Jwks Uri (with caching)
- Support Userinfo encryption and/or signed (jwt) or JSON
- Support Introspection encryption and/or signed (jwt) or JSON

## Inspired by 

- https://github.com/ory/fosite
- https://github.com/coreos/go-oidc
- https://godoc.org/golang.org/x/oauth2
