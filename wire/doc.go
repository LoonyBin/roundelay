// Package wire implements the Roundelay v1 wire format: the envelope, the body
// framing and padding ladder, domain-separated signing inputs, and the key-plane
// constructions (member wraps, escrow wraps, the wrap-set digest).
//
// It carries the rules the specification tags [W] — the ones that bind both the
// server and every client, and that two implementations must agree on byte for
// byte. It deliberately carries nothing tagged [S] or [C]: no refusal codes, no
// served-set membership, no policy. A caller decides what is legal here; this
// package decides what the bytes are.
//
// Every construction in this package is exercised by a frozen vector in
// ../vectors, which is the cross-implementation contract. A change to any output
// of this package that does not also change those files is a change nobody else
// will make.
package wire
