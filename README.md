# `oauthx` a complete oauth2/oidc client library

implements: 

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
- openid-connect-core: 3.1.3.7.  ID Token Validation
- openid-connect-core: 3.1.3.8.  Access Token Validation
- openid-connect-core: 5.5.   Requesting Claims using the "claims" Request Parameter`claims=`
- openid-connect-core: 5.3.   UserInfo Endpoint
- openid-connect-core: 5.1.   Standard Claims
- openid-connect-discovery: `/.well-known/openid-configuration`
- openid-connect-rpinitiated: RP initiated logout (endSession)

## Inpired by 

- https://github.com/ory/fosite
- https://github.com/coreos/go-oidc
- https://godoc.org/golang.org/x/oauth2
