package oauthx_test

import (
	"encoding/json"
	"os"
	"testing"

	"log/slog"

	"github.com/vdbulcke/oauthx"
)

func TestClaimsParam(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	slog.SetDefault(logger)

	claims := oauthx.OpendIdRequestedClaimsParam{
		IDToken: map[string]*oauthx.OpenIdRequestedClaim{
			"foo": nil,
			"bar": oauthx.NewOpenIdRequestedClaim(true, []string{}),
			"acr": oauthx.NewOpenIdRequestedClaim(true, []string{
				"urn:mace:incommon:iap:silver",
				"urn:mace:incommon:iap:bronze",
			}),
		},
		Userinfo: map[string]*oauthx.OpenIdRequestedClaim{
			"hello": oauthx.NewOpenIdRequestedClaim(false, []string{"world"}),
		},
	}

	data, err := json.Marshal(claims)
	if err != nil {
		slog.Error("json", "err", err)
		t.Fail()
	}

	slog.Info("ok", "payload", string(data))
}
func TestParsClaimsParam(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	example := []byte(`
		{
		  "userinfo": {
		    "given_name": {
		      "essential": true
		    },
		    "nickname": null,
		    "email": {
		      "essential": true
		    },
		    "email_verified": {
		      "essential": true
		    },
		    "picture": null,
		    "http://example.info/claims/groups": null
		  },
		  "id_token": {
		    "auth_time": {
		      "essential": true
		    },
		    "acr": {
		      "values": [
		        "urn:mace:incommon:iap:silver"
		      ]
		    }
		  }
		}	
	`)

	var claims oauthx.OpendIdRequestedClaimsParam
	err := json.Unmarshal(example, &claims)
	if err != nil {
		slog.Error("json", "err", err)
		t.Fail()
	}

	slog.Info("parsed", "claims", claims)

}
