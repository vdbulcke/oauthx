# Token Introspection

```go
ctx := context.Background()


// get an initial access token
req := oauthx.NewClientCredentialsGrantTokenRequest(
  "read", 
  "write",
)

tokenResp, err := client.DoTokenRequest(ctx, req)
if err != nil {
  panic(err)
}

accessToken := tokenResp.AccessToken


// create access token introspection request
introspectionReq := oauthx.NewIntrospectionRequest(
  oauthx.TokenOpt(accessToken),
  oauthx.TokenTypeHintOpt(oauthx.TokenTypeAccessToken),
)

// do the introspection request
introspectionResp, err := client.DoIntrospectionRequest(ctx, introspectionReq)
if err != nil {
  panic(err)
}

// check introspection 'active' 
if !introspectionResp.Active {
  panic("token not active")
}

// check standard claims
if !slices.Contains(strings.Split(introspectionResp.Scope, " "), "read") {
  panic("scope 'read' is required")
}


// custom claims
var customClaims struct {
  Foo string `json:"foo"`
  Bar map[string]interface{} `json:"bar"`
}

// unmarshall your custom claims 
err = introspectionResp.UnmarshallClaims(&customClaims)
if err != nil {
  panic(err)
}


```
