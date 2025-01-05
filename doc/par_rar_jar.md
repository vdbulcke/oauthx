# Pushed Authorization Request/JWT-Secured Authorization Request/Rich Authorization Requests


## Pushed Authorization Request (PAR)


```go
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
  // sends authorization request options via
  // pushed authorization endpoint and
  // only use client_id and request_uri for
  // redirect to the authorization_endpoint
  oauthx.WithPushedAuthorizationRequest(), // <-- add this options to make the authorization request via PAR
)

// ... same example as for authorization code flow
// c.client.DoAuthorizationRequest(ctx, req) will detect the 
// oauthx.WithPushedAuthorizationRequest() option

```

## JWT-Secured Authorization Request (JAR/request jwt)

> WARNING: the OAuthClient MUST have the `oauthx.WithOAuthPrivateKey(privateKey)` option


```go
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
  // generate the 'request' jwt paramater by
  // adding authorization options as jwt claims
  // only keeping the 'request=' 'client_id=' and 
  // the parameters set by the AuthMethod
  oauthx.WithGeneratedRequestJWTOnly(),
  // NOTE: you can also combine it with PAR 
  // oauthx.WithPushedAuthorizationRequest(),
)

// ... same example as for authorization code flow.
// c.client.DoAuthorizationRequest(ctx, req) will detect the 
// oauthx.WithGeneratedRequestJWTOnly() option 

```

## Strict OAuth2/OIDC required parameters

Some implementation requires to have the `scope`, `response_type`, `redirect_uri` to still be passed as query string parameter on the authorization url
even when using PAR and/or JAR. 


```go

// ... 
req.AddOpts(
  // ...
  
  // generate the 'request' jwt paramater by
  // adding authorization options as jwt claims
  // only keeping the 'request=' 'client_id=' and 
  // the parameters set by the AuthMethod
  oauthx.WithGeneratedRequestJWTOnly(),
  // NOTE: you can also combine it with PAR 
  oauthx.WithPushedAuthorizationRequest(),
  // RFC9101
  //
  // The client MAY send the parameters included in the Request Object
  // duplicated in the query parameters as well for backward
  // compatibility, etc.  However, the authorization server supporting
  // this specification MUST only use the parameters included in the
  // Request Object.

  // openid-connect-core
  //
  // So that the request is a valid OAuth 2.0 Authorization Request,
  // values for the "response_type" and "client_id" parameters MUST be
  // included using the OAuth 2.0 request syntax, since they are REQUIRED
  // by OAuth 2.0.  The values for these parameters MUST match those in
  // the Request Object, if present.

  // Even if a "scope" parameter is present in the Request Object value, a
  // "scope" parameter MUST always be passed using the OAuth 2.0 request
  // syntax containing the "openid" scope value to indicate to the
  // underlying OAuth 2.0 logic that this is an OpenID Connect request.
  oauthx.WithStrictRequiredAuthorizationParams(), // <- add this option to duplicate the required param when generating the authorization url
)

```

## Rich Authorization Requests (RAR/authorization_details)

* Create you custom type for representing a specific authorization detail type:

```go

// create a custom type from the example 
// of rfc9396
type PaymentInitiation struct {
  Type                              string            `json:"type"`
  Actions                           []string          `json:"actions"`
  Locations                         []string          `json:"locations"`
  InstructedAmount                  *InstructedAmount `json:"instructedAmount"`
  CredictorName                     string            `json:"creditorName"`
  CreditorAccount                   *CreditorAccount  `json:"creditorAccount"`
  RemittanceInformationUnstructured string            `json:"remittanceInformationUnstructured"`
}

type InstructedAmount struct {
  Currency string `json:"currency"`
  Amount   string `json:"amount"`
}

type CreditorAccount struct {
  Iban string `json:"iban"`
}




// MUST implement the oauthx.AuthorizationDetailI interface
func (p *PaymentInitiation) GetRegisteredType() string {
  // set a unique collision free registered type
  return "payment_initiation"
}

func (p *PaymentInitiation) Factory() oauthx.AuthorizationDetailI {
  // return a pointer to your custom type
  return &PaymentInitiation{}
}

func (p *PaymentInitiation) Validate() error {
  // this is where you can validate required field 
  // for your custom type
  if p.InstructedAmount.Currency != "EUR" {
    return fmt.Errorf("invalid curenty %s", p.InstructedAmount.Currency)
  }
  return nil
}

// assert that interface is completed
var _ oauthx.AuthorizationDetailI = (*PaymentInitiation)(nil)


// for unmarshalling your custom authorization_details
// you MUST first register your type with the lib
oauthx.RegisterAuthorizationDetail(&PaymentInitiation{})
  
```


* Use your custom authorization_details type in  AuthZRequest:

```go

// create a oauthx.AuthorizationDetails with a 
// single authorization detail PaymentInitiation
authDetails := oauthx.AuthorizationDetails{
  &PaymentInitiation{
  	Type: "payment_initiation",
  	Actions: []string{
  		"initiate",
  		"status",
  		"cancel",
  	},
  	Locations: []string{
  		"https://example.com/payments",
  	},
  	InstructedAmount: &InstructedAmount{
  		Currency: "EUR",
  		Amount:   "123.50",
  	},
  	CredictorName: "Merchant A",
  	CreditorAccount: &CreditorAccount{
  		Iban: "DE02100100109307118603",
  	},
  	RemittanceInformationUnstructured: "Ref Number Merchant",
  },
}


// ... 
req.AddOpts(
  // ...

  // add 'authorization_details=' parameter OR
  // add the 'authorization_details' claims in the 
  // RAR request jwt  
  oauthx.AuthorizationDetailsParamaterOpt(authDetails),
)
  
```

* Parsing authorization_details from token/introspection response

```go
// ...

tokenResp, err := c.client.DoTokenRequest(ctx, req)
if err != nil {
  panic(err)
}


// Parsing Token response looking like this:
//   HTTP/1.1 200 OK
//   Content-Type: application/json
//   Cache-Control: no-store
//
//   {
//      "access_token": "2YotnFZFEjr1zCsicMWpAA",
//      "token_type": "example",
//      "expires_in": 3600,
//      "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
//      "authorization_details": [
//         {
//            "type": "payment_initiation",
//            "actions": [
//               "initiate",
//               "status",
//               "cancel"
//            ],
//            "locations": [
//               "https://example.com/payments"
//            ],
//            "instructedAmount": {
//               "currency": "EUR",
//               "amount": "123.50"
//            },
//            "creditorName": "Merchant A",
//            "creditorAccount": {
//               "iban": "DE02100100109307118603"
//            },
//            "remittanceInformationUnstructured": "Ref Number Merchant"
//         }
//      ]
//   }

// NOTE: you MUST have registered your custom type first with lib
var authZDetails oauthx.AuthorizationDetails

err = json.Unmarshal(tokenResp.Raw, &authZDetails)
if err != nil {
  panic("unmarshalling error")
}

for _, ad := range authZDetails {
  // look for your custom type
  if ad.GetRegisteredType() == "payment_initiation" {

    err = ad.Validate()
    if err != nil {
      panic(err)
    }

    if payment, ok := ad.(*PaymentInitiation); ok {
      logger.Info("payment",
        "type", payment.Type,
        "action", payment.Actions,
        "location", payment.Locations,
        "instructedAmount", payment.InstructedAmount,
        "creditorName", payment.CredictorName,
        "creditorAccount", payment.CreditorAccount,
        "remittanceInformationUnstructured", payment.RemittanceInformationUnstructured,
      )
    }
       
  }
}



```

