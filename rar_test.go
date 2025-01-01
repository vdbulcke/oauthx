package oauthx_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/vdbulcke/oauthx"
)

func TestRAR(t *testing.T) {

	payload := []byte(`
      [
        {
          "type": "credential",
          "documentDigests": [
            {
              "hash": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
              "label": "Example Contract"
            },
            {
              "hash": "HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=",
              "label": "Example Terms of Service"
            }
          ],
          "signatureQualifier": "eu_eidas_qes",
          "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
        },
        
      {
         "type": "payment_initiation",
         "actions": [
            "initiate",
            "status",
            "cancel"
         ],
         "locations": [
            "https://example.com/payments"
         ],
         "instructedAmount": {
            "currency": "EUR",
            "amount": "123.50"
         },
         "creditorName": "Merchant A",
         "creditorAccount": {
            "iban": "DE02100100109307118603"
         },
         "remittanceInformationUnstructured": "Ref Number Merchant"
      }
      ]`)

	oauthx.RegisterAuthorizationDetail(&PaymentIniation{})

	var ads oauthx.AuthorizationDetails
	err := json.Unmarshal(payload, &ads)
	if err != nil {
		t.Error("json", "err", err)
		t.Fail()
	}

	for _, ad := range ads {
		err = ad.Validate()
		if err != nil {
			t.Error("validation", "err", err)
			t.Fail()

		}
	}

}

type PaymentIniation struct {
	Type            string            `json:"type"`
	Actions         []string          `json:"actions"`
	Locations       []string          `json:"locations"`
	IntructedAmount *InstructedAmount `json:"instructedAmount"`
	CredictorName   string            `json:"creditorName"`
}

type InstructedAmount struct {
	Currenty string `json:"currency"`
	Amount   string `json:"amount"`
}

func (p *PaymentIniation) GetRegisteredType() string {
	return "payment_initiation"
}

func (p *PaymentIniation) Factory() oauthx.AuthorizationDetailI {
	return &PaymentIniation{}
}

func (p *PaymentIniation) Validate() error {
	if p.IntructedAmount.Currenty != "EUR" {
		return fmt.Errorf("invalid curenty %s", p.IntructedAmount.Currenty)
	}
	return nil
}
