// Package oplog is the append pipeline and the payload rules The Log owns.
//
// It carries stages 0, 1, 3 and 5 of the six-stage walk. Stages 2 and 4 belong
// to Authority and reach this package through the Authority interface, which is
// how a layer that decides permissions stays out of a layer that decides bytes.
package oplog

import (
	"context"

	"github.com/loonybin/roundelay/codes"
)

// Refusal is one verdict: a status, a code from the closed vocabulary, and the
// per-code extra fields.
type Refusal struct {
	Status int
	Code   codes.Code
	Fields map[string]any
}

// At returns a copy carrying the zero-based batch index. Every per-op code
// carries one; the two stage-0 refusals do not, because no single op is at fault.
func (r *Refusal) At(index int) *Refusal {
	if r == nil {
		return nil
	}
	f := map[string]any{"index": index}
	for k, v := range r.Fields {
		f[k] = v
	}
	return &Refusal{Status: r.Status, Code: r.Code, Fields: f}
}

func refuse(status int, code codes.Code, fields map[string]any) *Refusal {
	return &Refusal{Status: status, Code: code, Fields: fields}
}

// SigningClass distinguishes a device's two signing keys. A device holds one for
// server-read classes and the auth challenge, and another for opaque classes.
type SigningClass uint8

const (
	// ControlSigning covers every class with bit 7 set, and the auth challenge.
	ControlSigning SigningClass = iota
	// ContentSigning covers every class with bit 7 clear.
	ContentSigning
)

// SigningClassFor reports which of a device's two signing keys a class is
// authored under.
func SigningClassFor(class byte) SigningClass {
	if class&0x80 != 0 {
		return ControlSigning
	}
	return ContentSigning
}

// Other is the class an author_key_class_mismatch is judged against.
func (c SigningClass) Other() SigningClass {
	if c == ControlSigning {
		return ContentSigning
	}
	return ControlSigning
}

// StoredOp is one row of the per-op retained state: the envelope bytes plus the
// ten facts that survive them.
//
// A hard_prune drops Envelope and keeps everything else. That enumeration and
// the tombstone of The Log §7 are one list, and a field added to either belongs
// in both.
type StoredOp struct {
	Seq          int64
	Workspace    [16]byte
	Class        byte
	KeyEpoch     uint32
	OpID         [16]byte
	Author       [16]byte
	AuthorKeyID  [8]byte
	AuthorSeq    uint64
	ReprisedBy   int64 // the position of the op that marked it; 0 when not marked
	EnvelopeHash [32]byte
	Envelope     []byte // nil once a hard_prune has dropped the bytes
}

// Reprised reports whether some marking type has hidden this op from the default
// read. Nothing distinguishes a mark a prune_ext set from one a prune set.
func (o *StoredOp) Reprised() bool { return o.ReprisedBy != 0 }

// Dropped reports whether a hard_prune has destroyed the envelope bytes. The row
// is still found: the tombstone is judged, and prune_target_not_found is the
// wrong answer for it.
func (o *StoredOp) Dropped() bool { return o.Envelope == nil }

// Store hands out append transactions.
type Store interface {
	// BeginAppend opens a transaction over one Workspace.
	//
	// Positions must be allocated under the same serialisation as the commit, or
	// a read can return position S while a lower position is still uncommitted —
	// which loses ops permanently and silently, because `since` is exclusive and
	// no server-side cursor exists.
	BeginAppend(ctx context.Context, workspace [16]byte) (Tx, error)
}

// Tx is one append transaction. The whole batch commits, or none of it does.
//
// A batch's walk must see one consistent snapshot: what a later op is judged
// against is what earlier ops in the same batch established, plus what was
// committed when the batch began.
type Tx interface {
	// WorkspaceExists reports an accepted genesis. A Workspace does not exist
	// because someone named it.
	WorkspaceExists() (bool, error)

	// Registered reports an accepted registration for this device here.
	// Registration is per Workspace: a device registered in one is a stranger to
	// every other, including Workspaces founded by the same Root.
	Registered(member [16]byte) (bool, error)

	// KeyIDsHeldForClass returns every key id this device has held in this
	// Workspace for a signing class — its registration's, and every
	// member_amend's since. Every id, never only the pair the registration
	// named, so an amend never turns an honest stale client into a class
	// mismatch.
	KeyIDsHeldForClass(member [16]byte, class SigningClass) ([][8]byte, error)

	// OpByOpID answers the idempotency lookup, keyed by (workspace, author,
	// op_id).
	OpByOpID(author, opID [16]byte) (*StoredOp, bool, error)

	// OpAt returns what is held at a transport position, tombstone included.
	OpAt(seq int64) (*StoredOp, bool, error)

	// AuthorHead is this author's highest author_seq here, 0 when it has written
	// nothing.
	AuthorHead(member [16]byte) (uint64, error)

	// ExtBindingAt resolves the NAME in force for a member and an extension
	// class at a position — the interval whose span contains it.
	ExtBindingAt(member [16]byte, class byte, seq int64) (string, bool, error)

	// LiveExtBinding resolves the member's currently open interval for a class.
	LiveExtBinding(member [16]byte, class byte) (string, bool, error)

	// Append stores an op verbatim and returns the position it now occupies.
	Append(op StoredOp) (int64, error)

	// MarkReprised records that the op at seq is reprised by the op at byPos.
	MarkReprised(seq, byPos int64) error

	// DropEnvelope destroys the bytes at seq, keeping the tombstone.
	DropEnvelope(seq int64) error

	// OpenExtBinding and CloseExtBinding move a member's binding intervals.
	OpenExtBinding(member [16]byte, class byte, name string, at int64) error
	CloseExtBinding(member [16]byte, class byte, at int64) error

	Commit() error
	Rollback() error
}

// Authority is the seam where the pipeline consults the Authority layer.
//
// The pipeline calls it and never reimplements it: permission lives in the log,
// and a server that decided any of this on its own authority would be the one
// thing this design says it cannot be.
type Authority interface {
	// Stage2 judges every class but control: the Workspace exists, a live grant
	// permits this class at this position, and a sealed op's epoch is current
	// enough.
	Stage2(ctx context.Context, tx Tx, op Op) *Refusal

	// Stage4 judges a control op, applies its effect, and reports its payload
	// type.
	Stage4(ctx context.Context, tx Tx, op Op, at int64) (controlType string, r *Refusal)

	// PermitsPruneType is stage 3 step 3: the author's role confers 0x81, but
	// does it confer this payload type? An entry naming bare 0x81 confers
	// `prune` and refuses the other two.
	PermitsPruneType(ctx context.Context, tx Tx, author [16]byte, pruneType string) *Refusal

	// EstablishesAccess reports whether this op is the one that establishes its
	// own author's access: a workspace_genesis, or a member_register naming the
	// author.
	//
	// It answers the access gate's deferred half. Whether the batch's first op
	// *is* that op is a fact about its class, its payload type and its
	// certificate, none of which stage 0 has read.
	EstablishesAccess(op Op) bool
}
