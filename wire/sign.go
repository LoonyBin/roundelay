package wire

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
)

// OpDomain returns the signing domain for an op of the given class.
//
// Every class below 0xC0 signs under "<ns>/op/v1". An extension class signs
// under "<ns>/ext/<name>/v1" instead, so extName must be the NAME the class is
// enabled under and is ignored otherwise.
//
// The split protects readers: a client built against one extension cannot verify
// an op written under another. It does not protect the server, which verifies no
// envelope signature at all — that is what the mandatory NAME on an ext_binding
// is for.
func (ns Namespace) OpDomain(class byte, extName string) string {
	if IsExtension(class) {
		return ns.ExtDomain(extName)
	}
	return ns.V1(DocOp)
}

// OpSigningInput is the preimage an envelope signature covers:
// framed(domain, header || body).
//
// The signature is over the sealed bytes under suite 0x01 — the body as it
// appears on the wire, not the plaintext.
func OpSigningInput(domain string, header, body []byte) []byte {
	return Framed(domain, header, body)
}

// SignOp signs an envelope and returns it complete. header must be the
// marshalled 158 bytes and body the on-wire body.
func SignOp(priv ed25519.PrivateKey, domain string, header, body []byte) ([]byte, error) {
	if len(header) != HeaderLen {
		return nil, fmt.Errorf("wire: header must be %d bytes, got %d", HeaderLen, len(header))
	}
	sig := ed25519.Sign(priv, OpSigningInput(domain, header, body))
	out := make([]byte, 0, len(header)+len(body)+SigLen)
	out = append(out, header...)
	out = append(out, body...)
	out = append(out, sig...)
	return out, nil
}

// VerifyOp checks an envelope signature. It is a client obligation: the server
// MUST NOT verify envelope signatures, because it does not know which keys a
// reader has decided to trust, and a server that "helpfully" verified would
// reject ops every conforming server accepts.
func VerifyOp(pub ed25519.PublicKey, domain string, e Envelope) bool {
	return ed25519.Verify(pub, OpSigningInput(domain, e.Header.Marshal(), e.Body), e.Sig[:])
}

// CertSigningInput is the preimage a certificate signature covers:
// framed("<ns>/<document>/v1", the literal certificate bytes).
//
// The certificate is signed bytes, never re-serialised JSON. A verifier that
// re-encodes what it parsed is verifying a document nobody signed.
func (ns Namespace) CertSigningInput(document string, cert []byte) []byte {
	return Framed(ns.V1(document), cert)
}

// AuthChallengeInput is the preimage the device login signature covers:
// framed("<ns>/auth-challenge/v1", member_id || nonce).
//
// member_id is the 16 raw bytes of the id, never a textual spelling: a text
// identifier has spellings — case, dashes, braces — and two peers that spell it
// differently sign different bytes and never learn why.
//
// Including the member id binds the signature to this device's challenge slot,
// so a captured signature cannot be replayed into another device's pending
// challenge.
func (ns Namespace) AuthChallengeInput(memberID [16]byte, nonce []byte) []byte {
	return Framed(ns.V1(DocAuthChallenge), memberID[:], nonce)
}

// VaultInput is the preimage a vault record's Root signature covers:
// framed("<ns>/vault/v1", locator || version || blob).
//
// The locator is inside the signed bytes, so a record signed for one slot can
// never be replayed into another. version is a u64, big-endian, at fixed width —
// the convention every framed construction here holds to, so that no
// construction depends on a default two libraries might disagree about.
func (ns Namespace) VaultInput(locator [32]byte, version uint64, blob []byte) []byte {
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], version)
	return Framed(ns.V1(DocVault), locator[:], v[:], blob)
}
