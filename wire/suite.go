package wire

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrOpen reports an AEAD authentication failure. Under suite 0x01 it means
// bytes the author really signed that still will not decrypt — the signature is
// over the sealed body, so a tampered ciphertext fails the signature check
// first, and reaching this error means something else went wrong.
var ErrOpen = errors.New("wire: sealed body failed to open")

// SealBody applies suite 0x01 to a plaintext body.
//
// The suite is a body wrapper and nothing else: no offset moves, no field is
// added. The literal header is the associated data, so the suite, the epoch and
// the nonce are all bound with no second binding to keep in step — change any
// header byte and the body no longer opens.
//
// header must be the marshalled 158 bytes, with Nonce already set to the value
// the sealing will use. The returned body is TagLen longer than plaintext.
func SealBody(header []byte, contentKey [32]byte, plaintext []byte) ([]byte, error) {
	if len(header) != HeaderLen {
		return nil, fmt.Errorf("wire: header must be %d bytes, got %d", HeaderLen, len(header))
	}
	aead, err := chacha20poly1305.NewX(contentKey[:])
	if err != nil {
		return nil, err
	}
	nonce := header[offNonce : offNonce+chacha20poly1305.NonceSizeX]
	return aead.Seal(nil, nonce, plaintext, header), nil
}

// OpenBody reverses SealBody. header must be the envelope's own 158 header bytes.
func OpenBody(header []byte, contentKey [32]byte, body []byte) ([]byte, error) {
	if len(header) != HeaderLen {
		return nil, fmt.Errorf("wire: header must be %d bytes, got %d", HeaderLen, len(header))
	}
	aead, err := chacha20poly1305.NewX(contentKey[:])
	if err != nil {
		return nil, err
	}
	nonce := header[offNonce : offNonce+chacha20poly1305.NonceSizeX]
	out, err := aead.Open(nil, nonce, body, header)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOpen, err)
	}
	return out, nil
}
