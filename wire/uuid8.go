package wire

import "crypto/sha256"

// UUID8 derives a Workspace id from a frozen namespace and a Root public key.
//
//	d  = SHA-256( namespace 16B ‖ root_pk 32B )
//	id = d[0..16], then
//	       octet 6  ←  0x80 | (octet 6 & 0x0F)      version 8
//	       octet 8  ←  0x80 | (octet 8 & 0x3F)      variant, RFC 9562
//
// RFC 9562 leaves version 8 to the application precisely so that it can be
// this. Version 5 is the obvious answer and it is SHA-1 — and a Workspace id is
// signed into every certificate and every envelope header the Workspace will
// ever carry, in a log that is never rewritten, so a deprecated primitive there
// is permanent by construction.
//
// The name is the 32 raw bytes of the key, never a base64 or hex spelling of
// them. A textual identifier has spellings — case, padding, whitespace,
// normalisation — and two peers that spell it differently derive different
// Workspaces and never converge, each side internally consistent and nothing
// reporting the divergence. A public key has no spelling.
//
// Both operands are fixed width, so the concatenation is injective without a
// length prefix and the framing rule is not being evaded: there is no second
// way to read these 48 bytes.
func UUID8(namespace [16]byte, rootPK [32]byte) [16]byte {
	h := sha256.New()
	h.Write(namespace[:])
	h.Write(rootPK[:])
	sum := h.Sum(nil)

	var id [16]byte
	copy(id[:], sum[:16])
	id[6] = 0x80 | (id[6] & 0x0F)
	id[8] = 0x80 | (id[8] & 0x3F)
	return id
}
