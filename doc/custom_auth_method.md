# Custom Auth Method

## Example: implementing Introspection Bearer rfc7662

From rfc7662:
 > To prevent token scanning attacks, the endpoint MUST also require
 > some form of authorization to access this endpoint, such as client
 > authentication as described in OAuth 2.0 [RFC6749] or a separate
 > OAuth 2.0 access token such as the bearer token described in OAuth
 > 2.0 Bearer Token Usage [RFC6750].  The methods of managing and
 > validating these authentication credentials are out of scope of this
 > specification.

In this example we will implement the bearer token auth method for token introspection endpoint.
We assume that the bearer token is an access token obtain with client_credentials grant with a
special scope `allow:introspection`.

### Implementing the `oauthx.AuthMethod` interface

See the [oauthx.AuthMethod](https://pkg.go.dev/github.com/vdbulcke/oauthx#AuthMethod) interface:


```go
// IntrospectionBearerAuth our custom type
// representing the bearer introspection
// auth method
type IntrospectionBearerAuth struct {
	// let's use a instance of a oauthx.OAuthClient to
	// do the client_credentials grant
	clientCredentialClient *oauthx.OAuthClient
}

// NewOAuthAuthenticatedRequest implements the oauthx.AuthMethod interface
//   - endpoint => the url for the current request
//   - oauthEndpoint => used to indicate for which endpoint type (see the enum oauthx.OAuthAuthenticatedEndpoint for more info)
//   - params => the parameters of the current request
func (a *IntrospectionBearerAuth) NewOAuthAuthenticatedRequest(oauthEndpoint oauthx.OAuthAuthenticatedEndpoint, endpoint string, params url.Values) (*http.Request, error) {

	switch oauthEndpoint {
	case oauthx.IntrospectionEndpoint:
		// NOTE: you could implement caching of the access token to avoid
		// making a new client_credentials grant flow for each introspect request

		// get an access token with client_credentials flow
		ctx := context.Background()
		req := oauthx.NewClientCredentialsGrantTokenRequest("allow:introspection")
		token, err := a.clientCredentialClient.DoTokenRequest(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("introspect-bearer-auth: client_credentials error %w", err)
		}

		// generate the http.Request
		httpReq, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(params.Encode()))
		if err != nil {
			return nil, err
		}
		// Set Content Type
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// set the Authorization Bearer header with the access token
		httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

		return httpReq, nil

	default:
		// this auth mehod is only used for token introspection
		return nil, fmt.Errorf("unsupported endpoint %s for this auth method", oauthEndpoint.String())
	}

}

// validate the oauthx.AuthMethod interface is implemented
var _ oauthx.AuthMethod = (*IntrospectionBearerAuth)(nil)

```
