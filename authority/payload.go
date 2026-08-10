// Package authority carries the rules the specification tags to the Authority
// layer: who may write what, recorded in the log rather than decided by the
// server.
//
// This half of it is store-independent — the shape of a control payload, the
// nine certificate documents, the five core role rules, and the control chain's
// link rules. Everything here is settled from a document's own literals, which is
// exactly the set of checks §5 permits above a signature: they refuse malformed
// documents and choose a key, they decide no authority and record nothing.
//
// The positional half — resolving root authority at a position, judging grants
// and delegations, applying effects — needs the log, and lands with the store.
package authority

import (
	"net/http"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/strictjson"
	"github.com/loonybin/roundelay/wire"
)

const unproc = http.StatusUnprocessableEntity

func refuse(status int, code codes.Code, fields map[string]any) *oplog.Refusal {
	return &oplog.Refusal{Status: status, Code: code, Fields: fields}
}

func malformedPayload() *oplog.Refusal {
	return refuse(unproc, codes.MalformedControlPayload, nil)
}

// Principal is a grant's or a revoke's named authority: `root`, or the uuid of a
// device holding the authority role.
//
// Only those two types name their authority in the payload, because only they
// have a choice of one. Everywhere else the verification key follows from the
// type, and no field is needed to find it.
type Principal struct {
	// Root is true for the literal "root", which resolves to root authority —
	// the Workspace's current Root, then each delegation live at that op's
	// position. It names an authority, not a particular key.
	Root bool
	// Member is the device, when Root is false.
	Member [16]byte
}

// ControlPayload is a decoded 0x80 body.
//
// Every type carries `type` and `prev_control_hash`, and every key set is
// closed: a missing key, or one belonging to another type, is
// malformed_control_payload.
type ControlPayload struct {
	Type            string
	PrevControlHash [32]byte

	// Every type but rotate.
	CertBytes []byte
	CertSig   [64]byte

	// grant and revoke.
	Granter Principal

	// rotate, the one type with no certificate. It carries its Workspace in the
	// payload because it has no certificate to carry one — same check, same
	// code, one document fewer.
	WorkspaceID   [16]byte
	FromEpoch     uint32
	ToEpoch       uint32
	KeywrapDigest [32]byte
}

// ZeroLink is the only legal link on a genesis, and illegal on everything else.
var ZeroLink [32]byte

// ParseControlPayload reads a 0x80 body under the shape rules of step 1.
//
// `type` is mandatory in every payload, for ever, because a chain link points at
// bare bytes with no surrounding context: a payload that has to be inferred from
// which fields are present is one two implementations will infer differently the
// first time a field becomes optional.
func ParseControlPayload(body []byte) (*ControlPayload, *oplog.Refusal) {
	doc, err := strictjson.Parse(body)
	if err != nil {
		return nil, malformedPayload()
	}
	o := doc.Root()

	typ, ok := o.PeekString("type")
	if !ok {
		return nil, malformedPayload()
	}
	if !ServesControlType(typ) {
		return nil, refuse(unproc, codes.UnsupportedControlType, nil)
	}
	o.String("type")

	p := &ControlPayload{Type: typ}
	copy(p.PrevControlHash[:], o.Hex("prev_control_hash", 32))

	switch typ {
	case wire.CtlRotate:
		p.WorkspaceID = o.UUID("workspace_id")
		p.FromEpoch = uint32(o.In("from_epoch", strictjson.EpochRange))
		p.ToEpoch = uint32(o.In("to_epoch", strictjson.EpochRange))
		copy(p.KeywrapDigest[:], o.Bytes("keywrap_digest_b64", 32))
	default:
		if typ == wire.CtlGrant {
			id, isRoot := o.Authority("granter")
			p.Granter = Principal{Root: isRoot, Member: id}
		}
		if typ == wire.CtlRevoke {
			id, isRoot := o.Authority("revoker")
			p.Granter = Principal{Root: isRoot, Member: id}
		}
		p.CertBytes = o.BytesAny("cert_b64")
		copy(p.CertSig[:], o.Bytes("cert_sig_b64", 64))
	}
	if doc.Err() != nil {
		return nil, malformedPayload()
	}

	// A rotation that skips an epoch is malformed_control_payload, not a
	// conflict: it is arithmetic over the document's own literals. A jump would
	// leave a gap no wrap set is ever minted for.
	if typ == wire.CtlRotate && p.ToEpoch != p.FromEpoch+1 {
		return nil, malformedPayload()
	}
	return p, nil
}

// ServesControlType reports whether a type is in v1's served set.
//
// An advisory type — one whose name begins note_ — is refused at a server's door
// like any other type it does not serve. v1 defines none: the reservation is a
// place kept, not a member.
func ServesControlType(t string) bool {
	for _, s := range wire.ControlTypes {
		if s == t {
			return true
		}
	}
	return false
}

// CertificateDocument maps a control type to the signing domain of the document
// it carries.
//
// The certificate a payload carries MUST be the document its type names.
// Nothing cryptographic rests on that — a mis-carried certificate dies at the
// signature whichever way it fell, because the domains differ. What it buys is
// code honesty: without it a client that built its payload around the wrong
// document meets bad_root_signature, which this specification reserves for
// "these bytes are forged" and which has no remedy.
func CertificateDocument(controlType string) (string, bool) {
	switch controlType {
	case wire.CtlWorkspaceGenesis:
		return wire.DocWorkspaceGenesis, true
	case wire.CtlMemberRegister:
		return wire.DocMemberRegister, true
	case wire.CtlMemberAmend:
		return wire.DocMemberAmend, true
	case wire.CtlGrant:
		return wire.DocGrant, true
	case wire.CtlRevoke:
		return wire.DocRevoke, true
	case wire.CtlRoleTable:
		return wire.DocRoleTable, true
	case wire.CtlDelegate:
		return wire.DocDelegate, true
	case wire.CtlRevokeDelegation:
		return wire.DocRevokeDelegation, true
	case wire.CtlRootHandover:
		return wire.DocRootHandover, true
	}
	return "", false // rotate carries none
}

// Delegable reports whether a live delegate's signature is as good as Root's for
// this type.
//
// Four documents are withheld. The role table is the authority vocabulary rather
// than an exercise of authority — a delegate that could rewrite it could hand
// itself every class Root never authorised. Handover is the remedy for
// compromise, and a delegate that could hand over turns a warm-key compromise
// into an unrecoverable one. Genesis happens once, so there is nothing routine to
// relieve. And a delegate cannot mint delegates, or the tree grows branches Root
// never authorised and could only prune by handing over.
func Delegable(controlType string) bool {
	switch controlType {
	case wire.CtlMemberRegister, wire.CtlMemberAmend, wire.CtlGrant, wire.CtlRevoke:
		return true
	}
	return false
}
