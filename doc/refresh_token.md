# Refresh Token

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
refreshToken := tokenResp.RefreshToken


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

// if access token is no longer active
// refresh it
if !introspectionResp.Active {

  
  // create refresh token request
  refreshTokenReq := oauthx.NewTokenRequest(
    oauthx.RefreshTokenGrantTypeOpt(),
    oauthx.RefreshTokenOpt(refreshToken),
  )


  // do refresh token grant 
  tokenResp, err = client.DoTokenRequest(ctx, req)
  if err != nil {
    panic(err)
  }

  
  accessToken = tokenResp.AccessToken
  refreshToken = tokenResp.RefreshToken

}

```
