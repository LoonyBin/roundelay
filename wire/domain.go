package wire

import (
	"errors"
	"fmt"
	"regexp"
)

// The fifteen core documents. Keys §2 fixes this table: a core domain is
// "<namespace>/<document>/v<n>" and these are the whole of that set.
//
// The domain space itself is not closed — an envelope of an extension class is
// signed under ExtDomain instead, one domain per enabled NAME.
const (
	DocOp               = "op"
	DocMemberRegister   = "member-register"
	DocWorkspaceGenesis = "workspace-genesis"
	DocMemberAmend      = "member-amend"
	DocGrant            = "grant"
	DocRevoke           = "revoke"
	DocRoleTable        = "role-table"
	DocDelegate         = "delegate"
	DocRevokeDelegation = "revoke-delegation"
	DocRootHandover     = "root-handover"
	DocAuthChallenge    = "auth-challenge"
	DocVault            = "vault"
	DocKeywrap          = "keywrap"
	DocEpochKeyEscrow   = "epoch-key-escrow"
	DocKeywrapDigest    = "keywrap-digest"
)

// CoreDocuments is the closed set above, in the order Keys §2 tables them.
var CoreDocuments = []string{
	DocOp, DocMemberRegister, DocWorkspaceGenesis, DocMemberAmend,
	DocGrant, DocRevoke, DocRoleTable, DocDelegate, DocRevokeDelegation,
	DocRootHandover, DocAuthChallenge, DocVault, DocKeywrap,
	DocEpochKeyEscrow, DocKeywrapDigest,
}

// tokenPattern is the shape shared by the namespace, extension NAMEs, role
// tokens and member_kind tokens: kebab-case, 1-32 bytes, no leading or trailing
// hyphen.
var tokenPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// ValidToken reports whether s matches the protocol's kebab-case token shape.
func ValidToken(s string) bool {
	return len(s) >= 1 && len(s) <= 32 && tokenPattern.MatchString(s)
}

// Namespace is PROTOCOL_NAMESPACE, row 1 of the profile obligations. It is the
// first component of every domain, deployment-frozen, and globally unique — not
// merely locally unique, because these signing keys are shared with unrelated
// protocols.
//
// The type exists so that the length invariant Framed relies on is established
// once, at boot, rather than assumed at every call site.
type Namespace string

// ErrBadNamespace is returned by NewNamespace for a value outside the token shape.
var ErrBadNamespace = errors.New("wire: namespace must match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$, 1-32 bytes")

// NewNamespace validates and returns a Namespace. A server refuses to start
// without one; there is no default, because a guessed namespace would let two
// unrelated deployments' signatures verify against each other.
func NewNamespace(s string) (Namespace, error) {
	if !ValidToken(s) {
		return "", fmt.Errorf("%w: %q", ErrBadNamespace, s)
	}
	return Namespace(s), nil
}

// Domain builds a core domain, "<namespace>/<document>/v<n>".
//
// The domain string is the version: no signed document carries a version field,
// so a field addition or a semantic change ships under a new v<n> and a
// downgrade attempt is a signature failure rather than a parsing ambiguity.
func (ns Namespace) Domain(document string, version int) string {
	return fmt.Sprintf("%s/%s/v%d", ns, document, version)
}

// V1 is Domain(document, 1), which is every core domain this specification defines.
func (ns Namespace) V1(document string) string {
	return ns.Domain(document, 1)
}

// ExtDomain builds the signing domain for an extension class, "<namespace>/ext/<name>/v1".
//
// Ops of an extension class are not signed under DocOp. The domain moves with
// the NAME so that a client built against one extension cannot verify an op
// written under another — which only holds if the two never share a domain.
func (ns Namespace) ExtDomain(name string) string {
	return fmt.Sprintf("%s/ext/%s/v1", ns, name)
}

// Framed implements the framing rule of Keys §2:
//
//	framed(domain, rest) = [1 byte: length of domain] [domain] [rest]
//
// The length prefix is what makes the construction injective. Plain
// concatenation is not: with a varying namespace, "acme" + "/op/v1" and
// "acme/op" + "/v1" are the same bytes, and several inputs here begin with
// attacker-influenceable material — the vault preimage starts with a raw
// locator, any byte of which may be an ASCII digit.
//
// Framed panics if the domain is empty or 256 bytes or longer. Both are
// unreachable through Namespace, whose validator bounds it at 32 bytes, and the
// longest document name adds 20; the check is here so that a domain assembled
// some other way fails loudly rather than silently truncating its own length
// prefix.
func Framed(domain string, parts ...[]byte) []byte {
	if len(domain) == 0 || len(domain) > 255 {
		panic(fmt.Sprintf("wire: domain must be 1-255 bytes, got %d", len(domain)))
	}
	n := 1 + len(domain)
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	out = append(out, byte(len(domain)))
	out = append(out, domain...)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
