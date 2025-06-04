package oauthx

import (
	"encoding/json"
	"errors"
	"fmt"
)

type AuthorizationDetailI interface {

	// type:
	//    An identifier for the authorization details type as a string.
	//    The value of the type field determines the allowable contents of
	//    the object that contains it.  The value is unique for the
	//    described API in the context of the AS.  This field is REQUIRED.
	GetRegisteredType() string

	// Factory returns a pointer to
	// the concrete struct implementing the
	// [oauthx.AuthorizationDetailI] interface
	Factory() AuthorizationDetailI

	// Validate validates the authorization
	// This is where you can enforce required field
	// for your custom authorization_details schema.
	Validate() error
}

// AuthorizationDetails rfc9396 'authorization_details'.
//
//	 The request parameter authorization_details contains, in JSON
//	 notation, an array of objects.  Each JSON object contains the data to
//	 specify the authorization requirements for a certain type of
//	 resource.  The type of resource or access requirement is determined
//	 by the type field, which is defined as follows:
//
//	 type:
//
//		An identifier for the authorization details type as a string.
//		The value of the type field determines the allowable contents of
//		the object that contains it.  The value is unique for the
//		described API in the context of the AS.  This field is REQUIRED.
//
//	 An authorization_details array MAY contain multiple entries of the
//	 same type.
type AuthorizationDetails []AuthorizationDetailI

// AuthorizationDetailsAllowUnregisteredType (default true)
//
// if true, if a 'type' from authoriation_details is not
// one of the registered type, the json object will unmarshaled
// into [oauthx.AuthorizationDetailI].
//
// if false, the UnmarshalJSON() function will return a
// [oauthx.ErrRFC9396UnsupportedType] sentinel error
var AuthorizationDetailsAllowUnregisteredType = true

// UnmarshalJSON implements [json.Unmarshaler] interface
//
// This will validate each json object within the json array have the
// required "type" (string) field.
//
// For each "type" value, it will look for [oauthx.RegisterAuthorizationDetail] registered type
//   - if registered type is found to the "type" value, it will try to [json.Unmarshall] the
//     the current json object into the Factory()
//   - if the "type" is not one of the registered type it will [json.Unmashall] into
//     the [oauthx.UnregisteredAuthorizationDetail] (a wrapper of [json.RawMessage])
func (ads *AuthorizationDetails) UnmarshalJSON(b []byte) error {
	// check valid json
	var raw []json.RawMessage
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	// Allocate an array of Interface
	*ads = make(AuthorizationDetails, len(raw))

	// for each json object in the list
	for i, rawOject := range raw {
		var required requiredType
		// get required type
		err := json.Unmarshal(rawOject, &required)
		if err != nil {
			return err
		}

		// "type" is required
		if required.Type == "" {
			return ErrRFC9396MissingRequiredType
		}

		// check supported type
		factory, ok := lookup[required.Type]
		if !ok {
			if AuthorizationDetailsAllowUnregisteredType {
				// if not supported match unsupported
				factory = UnregisteredAuthorizationDetail{}
			} else {
				return fmt.Errorf("%w for type: '%s'", ErrRFC9396UnsupportedType, required.Type)
			}

		}

		// get concrete struct from matched factory
		concreteType := factory.Factory()

		err = json.Unmarshal(rawOject, concreteType)
		if err != nil {
			return err
		}

		// assign concrete type to index
		(*ads)[i] = concreteType

	}

	return nil
}

// registered authorization_details implementation by type
var lookup = make(map[string]AuthorizationDetailI)

// RegisterAuthorizationDetail registers a struct implementing
// the [oauthx.AuthorizationDetailI] interface
func RegisterAuthorizationDetail(iface AuthorizationDetailI) {
	lookup[iface.GetRegisteredType()] = iface
}

// assert interface is implemented
var _ AuthorizationDetailI = (*UnregisteredAuthorizationDetail)(nil)

// UnregisteredAuthorizationDetail a [json.RawMessage] wrapper
// that implements the [oauthx.AuthorizationDetailI] interface
type UnregisteredAuthorizationDetail struct {
	json.RawMessage
}

func (ad UnregisteredAuthorizationDetail) GetRegisteredType() string {
	return "urn:rfc9396:oauthx:unregistered:authorization_details"
}

func (ad UnregisteredAuthorizationDetail) Factory() AuthorizationDetailI {
	return &UnregisteredAuthorizationDetail{}
}

func (ad UnregisteredAuthorizationDetail) Validate() error {

	var required requiredType
	return json.Unmarshal(ad.RawMessage, &required)
}

type requiredType struct {
	Type string `json:"type"`
}

var (
	ErrRFC9396MissingRequiredType = errors.New("RFC9396  missing required 'type' in 'authorization_details' ")
	ErrRFC9396UnsupportedType     = errors.New("RFC9396 unsuported 'type' in 'authorization_details' ")
)
