package oauthx

import (
	"encoding/json"
	"net/http"
)

// HttpErr error resulting from http call.
//
// useful to have access to response header/response body
// in case of error for troubleshooting.
//
// Use AsRFC6749Error() to try unmarshalling the response body
// into standard rfc6749 OAuth2 Error
type HttpErr struct {
	RespBody       []byte      `json:"resp_body"`
	StatusCode     int         `json:"status_code"`
	ResponseHeader http.Header `json:"res_headers"`
	Err            error       `json:"err"`
}

func (e *HttpErr) Error() string {
	return e.Err.Error()
}

func (e HttpErr) AsRFC6749Error() (*RFC6749Error, error) {
	var rfc6749Err RFC6749Error
	err := json.Unmarshal(e.RespBody, &rfc6749Err)
	if err != nil {
		return nil, err
	}

	return &rfc6749Err, nil
}

// 5.2.  Error Response
//
//	 The authorization server responds with an HTTP 400 (Bad Request)
//	 status code (unless specified otherwise) and includes the following
//	 parameters with the response:
//	 error
//	       REQUIRED.  A single ASCII [USASCII] error code from the
//	       following:
//
//	       invalid_request
//	             The request is missing a required parameter, includes an
//	             unsupported parameter value (other than grant type),
//	             repeats a parameter, includes multiple credentials,
//	             utilizes more than one mechanism for authenticating the
//	             client, or is otherwise malformed.
//
//	       invalid_client
//	             Client authentication failed (e.g., unknown client, no
//	             client authentication included, or unsupported
//	             authentication method).  The authorization server MAY
//	             return an HTTP 401 (Unauthorized) status code to indicate
//	             which HTTP authentication schemes are supported.  If the
//	             client attempted to authenticate via the "Authorization"
//	             request header field, the authorization server MUST
//	             respond with an HTTP 401 (Unauthorized) status code and
//	             include the "WWW-Authenticate" response header field
//	             matching the authentication scheme used by the client.
//
//	       invalid_grant
//	             The provided authorization grant (e.g., authorization
//	             code, resource owner credentials) or refresh token is
//	             invalid, expired, revoked, does not match the redirection
//	             URI used in the authorization request, or was issued to
//	             another client.
//
//	       unauthorized_client
//	             The authenticated client is not authorized to use this
//	             authorization grant type.
//
//	       unsupported_grant_type
//	             The authorization grant type is not supported by the
//	             authorization server.
//
//
//	      invalid_scope
//	            The requested scope is invalid, unknown, malformed, or
//	            exceeds the scope granted by the resource owner.
//
//	      Values for the "error" parameter MUST NOT include characters
//	      outside the set %x20-21 / %x23-5B / %x5D-7E.
//
//	error_description
//	      OPTIONAL.  Human-readable ASCII [USASCII] text providing
//	      additional information, used to assist the client developer in
//	      understanding the error that occurred.
//	      Values for the "error_description" parameter MUST NOT include
//	      characters outside the set %x20-21 / %x23-5B / %x5D-7E.
//
//	error_uri
//	      OPTIONAL.  A URI identifying a human-readable web page with
//	      information about the error, used to provide the client
//	      developer with additional information about the error.
//	      Values for the "error_uri" parameter MUST conform to the
//	      URI-reference syntax and thus MUST NOT include characters
//	      outside the set %x21 / %x23-5B / %x5D-7E.
//
//	The parameters are included in the entity-body of the HTTP response
//	using the "application/json" media type as defined by [RFC4627].  The
//	parameters are serialized into a JSON structure by adding each
//	parameter at the highest structure level.  Parameter names and string
//	values are included as JSON strings.  Numerical values are included
//	as JSON numbers.  The order of parameters does not matter and can
//	vary.
type RFC6749Error struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorUri         string `json:"error_uri,omitempty"`
}
