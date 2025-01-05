# Getting Started

## Create a new OAuthClient

### Public client

```go

issuer := "https://as.example.com"
clientId := "my_client_id"

ctx := context.Background()

// fetch '/.well-known/openid-configuration'
wk, err := oauthx.NewWellKnownOpenidConfiguration(ctx, issuer)
if err != nil {
  panic(err)
}

// create OAuthClient with default option (auth method 'none')
client := oauthx.NewOAuthClient(clientId, wk)

```

### ClientSecretPost

```go

issuer := "https://as.example.com"
clientId := "my_client_id"
clientSecret := "my_secret"

auth := oauthx.NewClientSecretPost(clientId, clientSecret)

ctx := context.Background()


// fetch '/.well-known/openid-configuration'
wk, err := oauthx.NewWellKnownOpenidConfiguration(ctx, issuer)
if err != nil {
  panic(err)
}

// create OAuthClient 
client := oauthx.NewOAuthClient(clientId, wk,
	oauthx.WithAuthMethod(auth),
)

```

### PrivateKeyJwt

```go

issuer := "https://as.example.com"
clientId := "my_client_id"

// crypto.PrivateKey
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
  panic(err)
}

// leave the staticKid empty to generate the kid based on 
// a hash of the public key
oauthkey, err = oauthx.NewOAuthPrivateKey(privateKey, "RS256", "")
if err != nil {
  panic(err)
}

// create priavate_key_jwt with default options
auth := oauthx.NewPrivateKeyJwt(clientId, oauthkey)

ctx := context.Background()


// fetch '/.well-known/openid-configuration'
wk, err := oauthx.NewWellKnownOpenidConfiguration(ctx, issuer)
if err != nil {
  panic(err)
}

// create OAuthClient 
client := oauthx.NewOAuthClient(clientId, wk,
	oauthx.WithAuthMethod(auth),
)

```
