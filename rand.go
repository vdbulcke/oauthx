package oauthx

import (
	"crypto/rand"
	"encoding/base64"
	"io"
)

// genCryptoSecureRandomBytes generates an unbiased,
// crypto random sequence of bytes of length l
func genCryptoSecureRandomBytes(l int) ([]byte, error) {

	// the random sequence generated from the charSet
	randSequence := make([]byte, 0, l)

	// read length
	// NOTE: Arbitrary set to twice as long
	//       under the assumption that is more expensive to rand.Read()
	//       than to have some extra byte in memory
	randLength := l * 2

	// continue until the randSequence is full
	for {

		// Read a random byte buffer fo size randLength
		// https://pkg.go.dev/crypto/rand#example-Read
		b := make([]byte, randLength)
		_, err := rand.Read(b)
		if err != nil {
			return nil, err
		}

		// for each random byte
		for _, randByte := range b {

			// to avoid modulo bias towards certain character
			// only keep random byte that are valid index of the charset
			if randByte < charSetLength {

				// add the corresponding random index to sequence
				randSequence = append(randSequence, charSet[randByte])

				// return sequence when full
				if len(randSequence) == l {
					return randSequence, nil
				}

			}

		}

	}

}

// NewNonce generates a new base64-urlencoded nonce
func NewNonce(size int) string {
	n, err := RandString(size)
	if err != nil {
		panic(err)
	}

	return n
}

// NewState generates a new base64-urlencoded state
func NewState(size int) string {
	n, err := RandString(size)
	if err != nil {
		panic(err)
	}

	return n
}

// RandString generates a base64-urlencoded string
// from nByte random data
func RandString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
