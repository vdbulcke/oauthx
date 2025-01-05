# Client Credentials Grant

```go

// make client credentials request with scopes
req := oauthx.NewClientCredentialsGrantTokenRequest(
  "read", 
  "write",
)

tokenResp, err := c.client.DoTokenRequest(ctx, req)
if err != nil {
  panic(err)
}

accessToken := tokenResp.AccessToken


```
