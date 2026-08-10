package identity

import (
	"context"
	"crypto/ed25519"
	"net/http"

	"github.com/loonybin/roundelay/authority"
	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/wire"
)

const unproc = http.StatusUnprocessableEntity

func refuse(status int, code codes.Code, fields map[string]any) *oplog.Refusal {
	return &oplog.Refusal{Status: status, Code: code, Fields: fields}
}

// Registration is the decoded POST /v1/members body.
type Registration struct {
	MemberID  [16]byte
	ControlPK [32]byte
	ContentPK [32]byte
	KexPK     [32]byte
	// ClaimedIDs is the optional key_ids object. Optional as a whole, never
	// member by member: a client's claim is cross-checked and then discarded,
	// because letting a client choose a key id would let one key occupy
	// another's slot.
	ClaimedIDs *ClaimedKeyIDs
	Cert       []byte
	CertSig    [64]byte
	RootPK     [32]byte
}

// ClaimedKeyIDs is the request's own copy of the three derivations.
type ClaimedKeyIDs struct{ Control, Content, Kex [8]byte }

// WorkspaceLookup is what the joining branch needs from the log: whether a
// Workspace exists, what its current Root is, and which delegations are live as
// this route evaluates.
//
// The route occupies no position in any log — it runs before the op exists, and
// often before the Workspace has heard of the device at all — so it asks live
// now, and the append path re-asks live there.
type WorkspaceLookup interface {
	CurrentRoot(ctx context.Context, workspace [16]byte) ([32]byte, bool, error)
	LiveDelegations(ctx context.Context, workspace [16]byte) ([][32]byte, error)
}

// Admitter decides whether a caller may bring a new identity into being.
//
// How it decides is the implementation's own business; the core defines no
// mechanism and no format. What the core defines is the carrier — an opaque
// string in the Roundelay-Admission header, which the server parses and nothing
// else does.
type Admitter interface {
	Admit(ctx context.Context, credential string) bool
}

// AdmitAll is the `open` declaration: a self-hosted deployment serving one
// person has no abuse boundary worth defending, and saying so explicitly beats a
// policy nobody enforces.
type AdmitAll struct{}

func (AdmitAll) Admit(context.Context, string) bool { return true }

// Registrar serves POST /v1/members.
type Registrar struct {
	Profile   *profile.Profile
	Store     Store
	Lookup    WorkspaceLookup
	Admission Admitter
}

// Result is what the route answers with.
type Result struct {
	Device  Device
	Created bool
	// Chained reports an accepted registration in the log anywhere.
	Chained bool
}

// Register runs the six checks in order.
//
// Steps 1 and 2 are shape and step 5 is values, which is why the certificate's
// own claims wait below the signature: whether this document names your device
// is a question about what it says, and asking it of bytes that have not
// verified decides something on a forgery's word.
func (r *Registrar) Register(ctx context.Context, req *Registration, admissionCredential string) (*Result, *oplog.Refusal) {
	// ── 1. the request's own shape ──────────────────────────────────────────
	//
	// Every key id is derived by the server; a claim is cross-checked, never
	// stored.
	if ids := req.ClaimedIDs; ids != nil {
		if wire.KeyID(req.ControlPK[:]) != ids.Control ||
			wire.KeyID(req.ContentPK[:]) != ids.Content ||
			wire.KeyID(req.KexPK[:]) != ids.Kex {
			return nil, refuse(unproc, codes.KeyIdNotDerivedFromSignPk, nil)
		}
	}

	// ── 2. the certificate parses, with the closed key set for its type ─────
	//
	// Certificates carry no type field of their own, so the closed key set is
	// how the server tells which of the two this door accepts it is holding.
	genesis, greg := authority.ParseGenesis(req.Cert)
	var reg *authority.Registration
	if greg != nil {
		var rr *oplog.Refusal
		reg, rr = authority.ParseRegistration(req.Cert)
		if rr != nil {
			return nil, refuse(unproc, codes.MalformedControlPayload, nil)
		}
	}
	founding := greg == nil

	// ── 3. creation, on the founding branch only ────────────────────────────
	//
	// A workspace_genesis certificate takes the founding branch whether or not
	// the Workspace already exists. The server does not look, which is what keeps
	// this branch from needing a Workspace lookup on the path that runs before
	// any Workspace exists.
	if founding {
		if !r.creatable(genesis.RootPK, genesis.WorkspaceID) {
			return nil, refuse(http.StatusForbidden, codes.WorkspaceNotReachable, nil)
		}
	}

	// ── 4. the signature verifies under root authority ──────────────────────
	//
	// A genesis is never delegable, so the founding branch tries the carried
	// root_pk and nothing else. A member_register is, so the joining branch
	// tries the carried root_pk first, then each delegation live in the
	// Workspace the certificate names.
	doc := wire.DocWorkspaceGenesis
	candidates := [][32]byte{req.RootPK}
	if !founding {
		doc = wire.DocMemberRegister
		dels, err := r.Lookup.LiveDelegations(ctx, reg.WorkspaceID)
		if err != nil {
			return nil, storeDown()
		}
		candidates = append(candidates, dels...)
	}
	if !r.verify(candidates, doc, req.Cert, req.CertSig) {
		return nil, refuse(unproc, codes.BadRootSignature, nil)
	}

	// ── 5. the certificate's contents ───────────────────────────────────────
	cert := reg
	if founding {
		cert = &genesis.Founder
	}
	if cert.MemberID != req.MemberID {
		return nil, refuse(unproc, codes.CertMemberMismatch, nil)
	}
	if cert.Control.PK != req.ControlPK || cert.Content.PK != req.ContentPK || cert.Kex.PK != req.KexPK {
		return nil, refuse(unproc, codes.CertKeyMismatch, nil)
	}
	if !r.knownKind(cert.MemberKind) {
		return nil, refuse(unproc, codes.UnknownMemberKind, nil)
	}

	// ── 6. the branch's own gate ────────────────────────────────────────────
	if founding {
		// Registering an identity's founding device is the only admitted
		// operation, and it is consulted once per identity however many
		// Workspaces that identity founds.
		if r.Profile.Admission != profile.AdmissionOpen && r.Admission != nil {
			if !r.Admission.Admit(ctx, admissionCredential) {
				return nil, refuse(http.StatusForbidden, codes.AdmissionRefused, nil)
			}
		}
	} else {
		root, exists, err := r.Lookup.CurrentRoot(ctx, reg.WorkspaceID)
		if err != nil {
			return nil, storeDown()
		}
		if !exists {
			return nil, refuse(http.StatusConflict, codes.WorkspaceNotCreated, nil)
		}
		// Which keeps a skewed device recoverable: it verified at step 4 under
		// the key it carried, and is told to re-read the log and rebuild against
		// the Root it reports — rather than bad_root_signature, whose ordinary
		// meaning is forged, and no remedy.
		if root != req.RootPK {
			return nil, refuse(unproc, codes.CertRootPkMismatch, nil)
		}
	}

	return r.store(ctx, req)
}

// store creates the record, or answers an identical repeat.
//
// This confers no authority whatsoever: the record is a shell until the same
// registration is accepted into the log as a control op. The certificate proves
// this Workspace's root authority asked for this key; only the log makes it true.
func (r *Registrar) store(ctx context.Context, req *Registration) (*Result, *oplog.Refusal) {
	want := Device{MemberID: req.MemberID, ControlPK: req.ControlPK, ContentPK: req.ContentPK, KexPK: req.KexPK}

	existing, found, err := r.Store.Device(ctx, req.MemberID)
	if err != nil {
		return nil, storeDown()
	}
	created := !found
	if found {
		// The id is a client-chosen UUID, so this is an existence oracle over a
		// namespace the caller already controls. Two identities that pick the
		// same UUID collide, and the second is told so rather than silently
		// taking over the first one's record.
		if *existing != want {
			return nil, refuse(http.StatusConflict, codes.MemberIdAlreadyRegistered, nil)
		}
	} else if err := r.Store.PutDevice(ctx, want); err != nil {
		return nil, storeDown()
	}

	chained, err := r.Store.ChainedAnywhere(ctx, req.MemberID)
	if err != nil {
		return nil, storeDown()
	}
	return &Result{Device: want, Created: created, Chained: chained}, nil
}

func (r *Registrar) creatable(rootPK [32]byte, workspace [16]byte) bool {
	if r.Profile.Creatable != nil {
		return r.Profile.Creatable(rootPK, workspace)
	}
	return true
}

func (r *Registrar) knownKind(kind string) bool {
	for _, k := range r.Profile.MemberKinds {
		if k == kind {
			return true
		}
	}
	return false
}

func (r *Registrar) verify(keys [][32]byte, doc string, cert []byte, sig [64]byte) bool {
	input := r.Profile.Namespace.CertSigningInput(doc, cert)
	for _, k := range keys {
		if ed25519.Verify(ed25519.PublicKey(k[:]), input, sig[:]) {
			return true
		}
	}
	return false
}

func storeDown() *oplog.Refusal {
	return refuse(http.StatusServiceUnavailable, codes.StoreUnavailable, nil)
}
