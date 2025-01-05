# Controlling http request/response


## Using a custom `*http.Client`

```go

// create your own *http.client other than http.DefaultClient
httpClient := makeCustomHttpClient()


// using custom client for fetching wellknown
wk, err = oauthx.NewWellKnownOpenidConfiguration(ctx, c.Issuer, oauthx.WellKnownWithHttpClientDefaultLimit(httpClient))
// or use oauthx.WellKnownWithHttpClient(httpClient, 100_000) where 10_000 is the response size limit in bytes
// the default limit is oauthx.LIMIT_HTTP_RESP_BODY_MAX_SIZE_BYTES
if err != nil {
  panic(err)
}

// using the custom *http.Client for the oauthx.OAuthCient
client := oauthx.NewOAuthClient(clientId, wk,
  oauthx.WithHttpClient(httpClient), // using the default oauthx.LIMIT_HTTP_RESP_BODY_MAX_SIZE_BYTES limit
  // oauthx.WithHttpClientWithLimit(httpClient, 100_000), // OR set a custom limit of 100_000 bytes for all http responses
)


```

## Tracing and extra headers

You can pass trace-id or arbitrary extra headers to http requests by adding extra value to the context.Context:

```go

ctx := context.Background()
traceId := uuid.New().String()
// this add the "x-trace-id" header to http request
ctx = tracing.ContextWithTraceID(ctx, "x-trace-id", traceId)

// for example when doing client_credentials grant
req := oauthx.NewClientCredentialsGrantTokenRequest("read", "write")
tokenResp, err := client.DoTokenRequest(ctx, req)
if err != nil {
  panic(err)
}


// and you can also add extra header
// for example if you use header for feature flags or
// for doing blue/green deployment routing
extraHeaders := map[string]string{
  "x-blue-green-region": "green",
  "x-ff-jwt-introspect": "true",
}
ctx = tracing.ContextWithExtraHeader(ctx, extraHeaders)

// for example when doing client_credentials grant
introspection := oauthx.NewIntrospectionRequest(
  oauthx.TokenOpt(tokenResp.AccessToken),
)

introspectionResp, err := client.DoIntrospectionRequest(ctx, req)
if err != nil {
  panic(err)
}


```

## Getting http response body/status code/headers on error

```go


req := oauthx.NewClientCredentialsGrantTokenRequest("read", "write")
tokenResp, err := client.DoTokenRequest(ctx, req)
if err != nil {

  var httpErr *oauthx.HttpErr
  if errors.As(err, &httpErr) {
    logger.Error("http error", "response_code", httpErr.StatusCode, "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))

    // or try to see if the reponse is a standard rfc6749 oauth2 error
    rfc6749Err, err := httpErr.AsRFC6749Error()
    if err == nil { // return err if the http response body cannot be unmarshall into expected json
      logger.Error("rfc6749 err", "error", rfc6749Err.Error, "error_description", rfc6749Err.ErrorDescription, "error_uri", rfc6749Err.ErrorUri)
    }
  }
}


```
