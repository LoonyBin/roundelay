// Package oplog is the append pipeline and the payload rules The Log owns.
//
// It carries stages 0, 1, 3 and 5 of the six-stage walk. Stages 2 and 4 belong
// to Authority and reach this package through the Authority interface, which is
// how a layer that decides permissions stays out of a layer that decides bytes.
package oplog

import (
	"context"

	"github.com/loonybin/roundelay/profile"

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

	// BeginRead opens a read-only view. It must not observe a partially
	// committed batch, and must not return position S while any position below S
	// is still uncommitted.
	BeginRead(ctx context.Context, workspace [16]byte) (ReadTx, error)
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

	// NextSeq is the position the next op will occupy. An op under judgement is
	// judged as though it landed there, which is what granted_seq < S means for
	// an op that is about to be stored.
	NextSeq() (int64, error)

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

	AuthorityTx
	KeyplaneTx

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

// ── Authority's rows ────────────────────────────────────────────────────────
//
// The Log does not read any of these. They live on the same transaction because
// there is one store and one retained-state table, and a batch's walk must see
// one consistent snapshot across all of it.

// MemberRecord is a registration accepted into this Workspace's log.
type MemberRecord struct {
	MemberID     [16]byte
	Kind         string
	HolderRef    [32]byte
	ControlPK    [32]byte
	ContentPK    [32]byte
	KexPK        [32]byte
	RegisteredAt int64
}

// Grant is one permission, with the positional window it is live over.
//
// Authorised iff granted_seq < S and (revoked_by_seq is null or S <
// revoked_by_seq). Anchored on log position and not on the certificate's clock:
// clock anchoring would let a revoked device backdate ops to slip under the
// boundary, because it controls its own clock but not where the server puts its
// op.
type Grant struct {
	GrantID       [16]byte
	Member        [16]byte
	Role          string
	Granter       [16]byte
	GranterIsRoot bool
	Start         int64
	End           int64 // 0 while live; write-once
}

// LiveAt applies the positional verdict.
func (g Grant) LiveAt(seq int64) bool {
	return g.Start < seq && (g.End == 0 || seq < g.End)
}

// Delegation is a key holding root authority over a span of positions.
type Delegation struct {
	DelegationID [16]byte
	PK           [32]byte
	Start        int64
	End          int64 // 0 while live; write-once
}

// LiveAt applies the same positional verdict a grant has.
func (d Delegation) LiveAt(seq int64) bool {
	return d.Start < seq && (d.End == 0 || seq < d.End)
}

// KeyChange is one key an amendment moves.
type KeyChange struct {
	PK    [32]byte
	KeyID [8]byte
}

// AuthorityTx is the half of a transaction the Authority layer reads and writes.
type AuthorityTx interface {
	// CurrentRoot is the key every certificate is checked against first. It is
	// the founding Root until a handover moves it.
	CurrentRoot() ([32]byte, bool, error)
	SetRoot(pk [32]byte) error
	MarkGenesis(at int64) error

	MemberRecord(member [16]byte) (*MemberRecord, bool, error)
	PutRegistration(rec MemberRecord) error

	// ControlKeyAt is the control signing key in force for a device at a
	// position — its registration's, until a member_amend installs another.
	ControlKeyAt(member [16]byte, at int64) ([32]byte, bool, error)

	GrantByID(id [16]byte) (*Grant, bool, error)
	LiveGrantsAt(member [16]byte, at int64) ([]Grant, error)
	HasAnyGrant(member [16]byte) (bool, error)
	PutGrant(g Grant) error
	CloseGrant(id [16]byte, at int64) error

	DelegationByID(id [16]byte) (*Delegation, bool, error)
	LiveDelegationsAt(at int64) ([]Delegation, error)
	IsRegisteredSigningKey(pk [32]byte) (bool, error)
	PutDelegation(d Delegation) error
	CloseDelegation(id [16]byte, at int64) error

	// RoleTableAt is the table carried by the latest role_table op below a
	// position. False means none has landed, and the profile's initial table
	// stands.
	RoleTableAt(at int64) (profile.RoleTable, bool, error)
	PutRoleTable(t profile.RoleTable, at int64) error

	AmendIDUsed(id [16]byte) (bool, error)
	PutAmend(member, amendID [16]byte, control, content, kex *KeyChange, at int64) error

	CurrentEpoch() (uint32, error)
	PutRotate(from, to uint32, digest [32]byte, at int64) error

	// LastControlOpBefore is what the control tip is computed from. Derived, not
	// stored: a stored tip is a cache of a function of the log, free to drift
	// from it.
	LastControlOpBefore(seq int64) (*StoredOp, bool, error)

	// EndDeviceSessions runs the cascade a lost last grant and a control amend
	// both trigger: every refresh token scoped to that device is revoked, and
	// every live signal socket it holds here closes with 4403.
	EndDeviceSessions(member [16]byte) error
}

// ── reading ─────────────────────────────────────────────────────────────────

// Page is one page of ops, with the exact has_more the route promises.
type Page struct {
	Ops     []StoredOp
	HasMore bool
}

// MemberPage is one page of the member list.
type MemberPage struct {
	Members []MemberRecord
	HasMore bool
}

// ReadTx is a read-only view of one Workspace.
//
// Reads take their own transaction because they are bar-1 routes that write
// nothing, and because a read must not observe a partially committed batch.
type ReadTx interface {
	// WorkspaceExists reports an accepted genesis. Reading a Workspace that does
	// not exist yet returns an empty page rather than an error — which is how a
	// device discovers it needs to create one, while holding a token and no
	// permissions at all.
	WorkspaceExists() (bool, error)

	Registered(member [16]byte) (bool, error)
	HasAnyGrant(member [16]byte) (bool, error)
	LiveGrantsAt(member [16]byte, at int64) ([]Grant, error)
	NextSeq() (int64, error)

	// ReadOps serves ops ascending by position, `since` exclusive.
	//
	// includeReprised drops the default filter and serves the history view. It
	// never returns a hard-pruned op: the position is absent from the page, and
	// the hard_prune that removed it is in the log.
	ReadOps(since int64, limit int, includeReprised bool) (Page, error)

	// ReadMembers serves the member list ordered by raw member id bytes
	// ascending, `after` exclusive.
	ReadMembers(after *[16]byte, limit int) (MemberPage, error)

	KeyplaneReadTx

	Close() error
}

// ── the key plane ───────────────────────────────────────────────────────────

// EpochRecord is what a Workspace retains per epoch: the committed digest, the
// escrow wrap, and the rotate position — absent at epoch 0, which no rotate
// creates.
type EpochRecord struct {
	Epoch  uint32
	Digest [32]byte
	// EscrowWrap is nil until the set is uploaded. An epoch in that window is
	// omitted from GET /epoch-keys: serving an empty blob would look like a wrap
	// that fails to open — an alarm — instead of one that has not arrived.
	EscrowWrap []byte
	RotateAt   int64
	// Published reports whether a wrap set has landed for this epoch. A published
	// set is final.
	Published bool
}

// MemberWrap is one device's sealed copy of an epoch key.
type MemberWrap struct {
	Epoch    uint32
	Member   [16]byte
	KexKeyID [8]byte
	Wrap     []byte
}

// KeyplaneTx is the half of a transaction the key plane writes.
type KeyplaneTx interface {
	// EpochRecord reads what is retained for one epoch.
	EpochRecord(epoch uint32) (*EpochRecord, bool, error)

	// KexKeyIDInForce is the id derived from this device's sealing key in force
	// in this Workspace — its registration's, until a member_amend installs
	// another. Never a claim: a wrap sealed to some other key would be
	// undeliverable, and the device would look orphaned for a reason nothing in
	// the log explained.
	KexKeyIDInForce(member [16]byte) ([8]byte, bool, error)

	// MemberWrapsAt returns the set published for one epoch, for comparing a
	// replay against what is stored.
	MemberWrapsAt(epoch uint32) ([]MemberWrap, error)

	// PublishWraps stores an epoch's whole set. Never incremental: the digest
	// commits to the whole set, so a partial upload could not be checked against
	// it, and accepting one would restore exactly the curation power the digest
	// exists to remove.
	PublishWraps(epoch uint32, digest [32]byte, escrow []byte, wraps []MemberWrap) error
}

// WrapPage is one page of a device's own wraps.
type WrapPage struct {
	Wraps   []MemberWrap
	HasMore bool
}

// EpochPage is one page of escrow wraps.
type EpochPage struct {
	Epochs  []EpochRecord
	HasMore bool
}

// KeyplaneReadTx is the half of a read the key plane serves.
type KeyplaneReadTx interface {
	// ReadMemberWraps serves one device's own wraps, ordered by epoch ascending.
	// Every epoch, kept for ever: reprised ops are retained, so content sealed at
	// any past epoch may still need opening.
	ReadMemberWraps(member [16]byte, afterEpoch *uint32, limit int) (WrapPage, error)

	// ReadEpochKeys serves the escrow wraps, ordered by epoch ascending.
	//
	// Omission and paging compose without interacting: an epoch whose escrow wrap
	// has not arrived is absent from every page, never a short page and never a
	// gap between two, and has_more counts servable entries only.
	ReadEpochKeys(afterEpoch *uint32, limit int) (EpochPage, error)
}
