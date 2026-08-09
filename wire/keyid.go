package wire

import "crypto/sha256"

// KeyIDLen is the width of a derived key id.
const KeyIDLen = 8

// KeyID derives a key's id: the first 8 bytes of its SHA-256.
//
// A key id indexes into a device's keys. It is always derived, never taken from
// a caller's claim — letting a client choose one would let one key occupy
// another's slot. A claim that arrives on the wire is cross-checked against this
// and then discarded.
func KeyID(publicKey []byte) [KeyIDLen]byte {
	sum := sha256.Sum256(publicKey)
	var id [KeyIDLen]byte
	copy(id[:], sum[:KeyIDLen])
	return id
}
