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

	oauthx.RegisterAuthorizationDetail(&PaymentInitiation{})

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

		if ad.GetRegisteredType() == "payment_initiation" {
			if payment, ok := ad.(*PaymentInitiation); ok {
				t.Log("payment",
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

	_ = oauthx.NewAuthZRequest(
		oauthx.AuthorizationDetailsParamaterOpt(authDetails),
	)

}

var _ oauthx.AuthorizationDetailI = (*PaymentInitiation)(nil)

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

func (p *PaymentInitiation) GetRegisteredType() string {
	return "payment_initiation"
}

func (p *PaymentInitiation) Factory() oauthx.AuthorizationDetailI {
	return &PaymentInitiation{}
}

func (p *PaymentInitiation) Validate() error {
	if p.InstructedAmount.Currency != "EUR" {
		return fmt.Errorf("invalid curenty %s", p.InstructedAmount.Currency)
	}
	return nil
}
