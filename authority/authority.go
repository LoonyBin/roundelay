package authority

import (
	"context"
	"crypto/ed25519"
	"net/http"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/wire"
)

// Authority derives permission from the log.
//
// Its index exists to refuse writes cheaply; the signed log is the truth, and
// every device works out permissions for itself by replaying it. Nothing here
// decides anything the log does not already say.
type Authority struct {
	Profile *profile.Profile
}

// New returns an Authority over a validated profile.
func New(p *profile.Profile) *Authority { return &Authority{Profile: p} }

var _ oplog.Authority = (*Authority)(nil)

func storeDown() *oplog.Refusal {
	return refuse(http.StatusServiceUnavailable, codes.StoreUnavailable, nil)
}

// ── the two bars, and the table in force ────────────────────────────────────

// tableAt is the role table in force at a position: the one carried by the
// latest role_table op below it, or the profile's initial table where there is
// none.
//
// Computed on demand. A stored "current table" is a cache of a function of the
// log and the profile, free to drift from both, and the drift is a permission
// the server grants or refuses on its own authority — the one thing this layer
// says it cannot do.
func (a *Authority) tableAt(tx oplog.Tx, at int64) (profile.RoleTable, error) {
	t, ok, err := tx.RoleTableAt(at)
	if err != nil {
		return nil, err
	}
	if ok {
		return t, nil
	}
	return a.Profile.InitialRoleTable, nil
}

// rolesAt is the roles a device holds live at a position, sorted.
func rolesAt(tx oplog.Tx, member [16]byte, at int64) ([]string, error) {
	grants, err := tx.LiveGrantsAt(member, at)
	if err != nil {
		return nil, err
	}
	roles := make([]string, 0, len(grants))
	for _, g := range grants {
		roles = append(roles, g.Role)
	}
	return SortedRoles(roles), nil
}

// permits reports whether any role the device holds live at a position admits a
// class, and returns the roles for the refusal to carry.
func (a *Authority) permits(tx oplog.Tx, member [16]byte, at int64, class byte) (bool, []string, error) {
	roles, err := rolesAt(tx, member, at)
	if err != nil {
		return false, nil, err
	}
	table, err := a.tableAt(tx, at)
	if err != nil {
		return false, nil, err
	}
	for _, r := range roles {
		// An unrecognised role token is refused rather than ignored, and a token
		// the table in force no longer carries admits nothing.
		if entry, ok := table[r]; ok && PermitsClass(entry, class) {
			return true, roles, nil
		}
	}
	return false, roles, nil
}

// ── stage 2 ─────────────────────────────────────────────────────────────────

// Stage2 judges every class but control, in the order §9 fixes.
func (a *Authority) Stage2(_ context.Context, tx oplog.Tx, op oplog.Op) *oplog.Refusal {
	h := op.Header()

	exists, err := tx.WorkspaceExists()
	if err != nil {
		return storeDown()
	}
	if !exists {
		return refuse(http.StatusConflict, codes.WorkspaceNotCreated, nil)
	}

	// The op has no position yet, so it is judged as though it landed next: a
	// grant at the position immediately below authorises it, which is what
	// granted_seq < S means for an op about to be stored.
	at, err := nextPosition(tx)
	if err != nil {
		return storeDown()
	}

	ok, roles, err := a.permits(tx, h.AuthorMemberID, at, h.OpClass)
	if err != nil {
		return storeDown()
	}
	if len(roles) == 0 {
		// A device with zero grants is not revoked; one that had grants and has
		// none live is. The distinction is what the flag reports.
		had, err := tx.HasAnyGrant(h.AuthorMemberID)
		if err != nil {
			return storeDown()
		}
		f := map[string]any{}
		if had {
			f["revoked"] = true
		}
		return refuse(http.StatusForbidden, codes.NoLiveGrant, f)
	}
	if !ok {
		return refuse(http.StatusForbidden, codes.RoleForbidsOpClass, map[string]any{
			"op_class": int(h.OpClass),
			"roles":    roles,
		})
	}

	return a.epochFloor(tx, h)
}

// epochFloor is stage 2's fourth check.
//
// It judges sealed ops only: an unsealed op carries key_epoch 0 by rule, so
// there is nothing there to be stale. The one-epoch slack is deliberate — a
// device offline across a rotation holds already-signed ops at the previous
// epoch and cannot re-sign them without forging its own chain — and the ceiling
// exists because no wrap set is minted for an epoch nothing rotated to.
func (a *Authority) epochFloor(tx oplog.Tx, h wire.Header) *oplog.Refusal {
	if h.Suite == wire.SuiteNone {
		return nil
	}
	current, err := tx.CurrentEpoch()
	if err != nil {
		return storeDown()
	}
	fields := map[string]any{"key_epoch": int(h.KeyEpoch), "current_epoch": int(current)}
	if h.KeyEpoch > current {
		return refuse(http.StatusConflict, codes.KeyEpochUnknown, fields)
	}
	if current > 0 && h.KeyEpoch+1 < current {
		return refuse(http.StatusConflict, codes.KeyEpochStale, fields)
	}
	return nil
}

// nextPosition is the position the op under judgement is about to occupy.
func nextPosition(tx oplog.Tx) (int64, error) { return tx.NextSeq() }

// ── stage 3's role verdict ──────────────────────────────────────────────────

// PermitsPruneType applies rule 5, at the position the prune is about to occupy.
func (a *Authority) PermitsPruneType(_ context.Context, tx oplog.Tx, author [16]byte, pruneType string) *oplog.Refusal {
	at, err := nextPosition(tx)
	if err != nil {
		return storeDown()
	}
	roles, err := rolesAt(tx, author, at)
	if err != nil {
		return storeDown()
	}
	table, err := a.tableAt(tx, at)
	if err != nil {
		return storeDown()
	}
	for _, r := range roles {
		if entry, ok := table[r]; ok && PermitsPruneType(entry, pruneType) {
			return nil
		}
	}
	return refuse(http.StatusForbidden, codes.RoleForbidsPruneType, map[string]any{
		"prune_type": pruneType,
		"roles":      roles,
	})
}

// ── the access gate's deferred half ─────────────────────────────────────────

// EstablishesAccess reports whether an op is the one that establishes its own
// author's access.
//
// The exemption opens nothing, because the exempt op carries a certificate for
// the Workspace it names, signed under that Workspace's own root authority. A
// device may present its own registration anywhere; only the one this
// Workspace's authority signed is accepted — and that is checked below, not
// here.
func (a *Authority) EstablishesAccess(op oplog.Op) bool {
	if op.Header().OpClass != wire.ClassControl {
		return false
	}
	body, err := a.Profile.SizeClasses.UnpackBody(op.Envelope.Body)
	if err != nil {
		return false
	}
	p, r := ParseControlPayload(body)
	if r != nil {
		return false
	}
	switch p.Type {
	case wire.CtlWorkspaceGenesis:
		g, r := ParseGenesis(p.CertBytes)
		return r == nil && g.Founder.MemberID == op.Header().AuthorMemberID
	case wire.CtlMemberRegister:
		reg, r := ParseRegistration(p.CertBytes)
		return r == nil && reg.MemberID == op.Header().AuthorMemberID
	}
	return false
}

// ── root authority ──────────────────────────────────────────────────────────

// rootAuthorityAt is the set of keys that hold root authority at a position: the
// Workspace's current Root, then each delegation live there.
//
// The verdict is positional, exactly like a grant. Revoking a delegation does
// not retroactively invalidate what it signed, for the same reason revoking a
// grant does not invalidate the ops it authorised — a registration a delegate
// issued in March stays valid in June.
func rootAuthorityAt(tx oplog.Tx, at int64, delegable bool) ([][32]byte, error) {
	var keys [][32]byte
	root, ok, err := tx.CurrentRoot()
	if err != nil {
		return nil, err
	}
	if ok {
		keys = append(keys, root)
	}
	if !delegable {
		return keys, nil
	}
	dels, err := tx.LiveDelegationsAt(at)
	if err != nil {
		return nil, err
	}
	for _, d := range dels {
		keys = append(keys, d.PK)
	}
	return keys, nil
}

// verifyUnder checks a certificate signature against a set of candidate keys.
func (a *Authority) verifyUnder(keys [][32]byte, document string, cert []byte, sig [64]byte) bool {
	input := a.Profile.Namespace.CertSigningInput(document, cert)
	for _, k := range keys {
		if ed25519.Verify(ed25519.PublicKey(k[:]), input, sig[:]) {
			return true
		}
	}
	return false
}

func (a *Authority) verifyOne(key [32]byte, document string, cert []byte, sig [64]byte) bool {
	return a.verifyUnder([][32]byte{key}, document, cert, sig)
}
