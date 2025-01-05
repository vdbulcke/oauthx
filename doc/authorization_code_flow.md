# Authorization Code Flow

```go
// see README.md for info on how to 
// create a OAuthClient
var client *oauthx.OAuthClient
// create cache of mapping state to associated oauth context
cache := make(map[string]*oauthx.OAuthContext)


// handler for login. Initiates authorization code flow 
func HandleLogin(w http.ResponseWriter, r *http.Request) {

  // base request includes
  //  - nonce
  //  - state
  //  - response_type=code
  //  - pkce S256
  req := oauthx.NewBaseAuthzRequest()
  // add client specific options
  req.AddOpts(
  	oauthx.ClientIdOpt(client.ClientId),
  	oauthx.RedirectUriOpt("https://my.domain.com/callback"),
  	oauthx.ScopeOpt([]string{"openid", "profile", "email"}),
  )

  // make the authorization request
  ctx := context.Background() // or use r.Context()
  authorization, err := c.client.DoAuthorizationRequest(ctx, req)
  if err != nil {
    panic(err)
  }

  // DoAuthorizationRequest() also persist relevant 
  // parameter in the OAuthContext (ReqCtx) that 
  // can be used to make the associated token endpoint
  // request later
  oauthCtx := authorization.ReqCtx
  // NOTE: create your own caching logic (e.g. using redis)
  cache[oauthCtx.State] = oauthCtx


  //  you should set the 'state' as a csrf cookie
  ttl := 15 * time.Minute
	cookie := &http.Cookie{
  	Name:     "oauthx_csrf",
  	Value:    oauthCtx.State,
  	MaxAge:   int(ttl.Seconds()),
  	Secure:   true,
  	HttpOnly: true,
  }
  http.SetCookie(w, cookie)
  
  // authorization.Url is the authorization_endpoint from the WellKnown
  // configuration with the oauth parameter from the request (req)
  http.Redirect(w, r, authorization.Url, http.StatusFound)
  
}

// handler for redirect_uri callback from the Authorization Server
func HandleOAuthCallback(w http.ResponseWriter, r *http.Request) {

  // get state from redirect_uri callback
  state := r.URL.Query().Get("state")
  if state == "" {
    panic("missing required 'state' parameter")
  }

  stateCookie, err := r.Cookie("state")
  if err != nil {
    panic(err)
  }

  // csrf check
  if state != stateCookie.Value {
    panic("invalid 'state' parameter")
  }


  oauthCtx, found := cache[state]
  if !found {
    panic("could not find context from cache")
  }

  // remove context from cache 
  delete(cache, state)

  code := r.URL.Query().Get("code")
  if code == "" {
    panic("missing required 'code' parameter")
  }

  
  // generate the token endpoint request based on the authorization code
  // and the oauth context
  tokenRequest := oauthx.NewAuthorizationCodeGrantTokenRequest(code, oauthCtx)

  ctx := context.Background() // or use r.Context()
  resp, err := c.client.DoTokenRequest(ctx, tokenRequest)
  if err != nil {
    panic(err)
  }

  accessToken := resp.AccessToken
  idTokenRaw := resp.IDToken

  // parse and validate IDToken string with default validation opts
  idToken, err := client.ParseIDToken(ctx, idTokenRaw)
  if err != nil {
    panic(err)
  }


  sub := idToken.Subject

  userinfo, err := client.DoUserinfoRequest(ctx, accessToken)
  if err != nil {
    panic(err)
  }

  if sub != userinfo.Sub {
    panic("openid requires 'sub' from id_token and userinfo to be the same")
  }

  // try to parse userinfo payload to extract
  // openid standard claims set
  var stdClaims oauthx.OpendIdStandardClaims
  err := userinfo.UnmarshallClaims(&stdClaims)
  if err != nil {
    panic(err)
  }

}

```
