package authority

import (
	"context"
	"net/http"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/wire"
)

// Stage4 verifies a control op and applies its effect.
//
// The order is fixed and observable. Framing and decoding first, then a served
// type, then the chain — everything in that run is above authority, because
// nothing decides who may do what from bytes whose signature has not verified.
// Then the authority-role check, unless the payload is Root-signed. Then the
// type's own sequence.
func (a *Authority) Stage4(ctx context.Context, tx oplog.Tx, op oplog.Op, at int64) (string, *oplog.Refusal) {
	body, r := a.unpack(op)
	if r != nil {
		return "", r
	}
	p, r := ParseControlPayload(body)
	if r != nil {
		return "", r
	}

	tip, hasTip, err := a.tipBefore(tx, at)
	if err != nil {
		return "", storeDown()
	}
	if r := CheckLink(p, tip, hasTip); r != nil {
		return "", r
	}

	// A payload signed under root authority is accepted regardless of the
	// author's permissions. The bypass has to carry to delegates too: a device a
	// delegate has just certified holds no grant in the Workspace it is joining —
	// that is what joining means — so a literal reading of "Root" would make the
	// one op the delegation exists to authorise the one op the device could not
	// post.
	rootSigned, err := a.isRootSigned(tx, p, at)
	if err != nil {
		return "", storeDown()
	}
	if !rootSigned {
		if r := a.authorityRole(tx, op.Header().AuthorMemberID, at); r != nil {
			return "", r
		}
	}

	if r := a.registerFirst(tx, p, op, at); r != nil {
		return "", r
	}

	switch p.Type {
	case wire.CtlWorkspaceGenesis:
		return p.Type, a.genesis(tx, p, op, at)
	case wire.CtlMemberRegister:
		return p.Type, a.register(tx, p, op, at)
	case wire.CtlMemberAmend:
		return p.Type, a.amend(tx, p, op, at)
	case wire.CtlGrant:
		return p.Type, a.grant(tx, p, op, at)
	case wire.CtlRevoke:
		return p.Type, a.revoke(tx, p, op, at)
	case wire.CtlDelegate:
		return p.Type, a.delegate(tx, p, op, at)
	case wire.CtlRevokeDelegation:
		return p.Type, a.revokeDelegation(tx, p, op, at)
	case wire.CtlRootHandover:
		return p.Type, a.handover(tx, p, op, at)
	case wire.CtlRoleTable:
		return p.Type, a.roleTable(tx, p, op, at)
	case wire.CtlRotate:
		return p.Type, a.rotate(tx, p, op, at)
	}
	return p.Type, refuse(unproc, codes.UnsupportedControlType, nil)
}

func (a *Authority) unpack(op oplog.Op) ([]byte, *oplog.Refusal) {
	payload, err := a.Profile.SizeClasses.UnpackBody(op.Envelope.Body)
	switch {
	case err == nil:
		return payload, nil
	case isErr(err, wire.ErrInvalidBodyLength):
		return nil, refuse(unproc, codes.InvalidBodyLength, nil)
	case isErr(err, wire.ErrPayloadOverrunsBody):
		return nil, refuse(unproc, codes.PayloadOverrunsBody, nil)
	default:
		return nil, refuse(unproc, codes.NonZeroPadding, nil)
	}
}

func isErr(err, target error) bool {
	for e := err; e != nil; {
		if e == target {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

// tipBefore computes the control tip at a position, from the payload of the last
// control op below it.
func (a *Authority) tipBefore(tx oplog.Tx, at int64) ([32]byte, bool, error) {
	var zero [32]byte
	last, ok, err := tx.LastControlOpBefore(at)
	if err != nil || !ok {
		return zero, false, err
	}
	// A control op is never a prune target, so no hard_prune can reach its
	// envelope and the bytes are always there.
	env, perr := wire.ParseEnvelope(last.Envelope)
	if perr != nil {
		return zero, false, perr
	}
	payload, uerr := a.Profile.SizeClasses.UnpackBody(env.Body)
	if uerr != nil {
		return zero, false, uerr
	}
	// The tip is the hash of the previous control op's payload bytes — the
	// unpacked payload, not the envelope and not a re-serialisation.
	return Tip(payload), true, nil
}

// isRootSigned reports whether the payload's certificate verifies under root
// authority at this position.
func (a *Authority) isRootSigned(tx oplog.Tx, p *ControlPayload, at int64) (bool, error) {
	doc, ok := CertificateDocument(p.Type)
	if !ok {
		return false, nil // rotate carries none, and its authority is the sender's grant
	}
	// A genesis verifies under the root_pk inside its own certificate: op 1 has
	// to introduce the key that checks it.
	if p.Type == wire.CtlWorkspaceGenesis {
		g, r := ParseGenesis(p.CertBytes)
		if r != nil {
			return false, nil
		}
		return a.verifyOne(g.RootPK, doc, p.CertBytes, p.CertSig), nil
	}
	// A grant or a revoke names a device authority in the payload, and that is
	// not root authority however it verifies.
	if (p.Type == wire.CtlGrant || p.Type == wire.CtlRevoke) && !p.Granter.Root {
		return false, nil
	}
	keys, err := rootAuthorityAt(tx, at, Delegable(p.Type))
	if err != nil {
		return false, err
	}
	return a.verifyUnder(keys, doc, p.CertBytes, p.CertSig), nil
}

// authorityRole is rule 2: a 0x80 op that is not Root-signed requires owner and
// no other role.
func (a *Authority) authorityRole(tx oplog.Tx, member [16]byte, at int64) *oplog.Refusal {
	roles, err := rolesAt(tx, member, at)
	if err != nil {
		return storeDown()
	}
	if len(roles) == 0 {
		had, err := tx.HasAnyGrant(member)
		if err != nil {
			return storeDown()
		}
		f := map[string]any{}
		if had {
			f["revoked"] = true
		}
		return refuse(http.StatusForbidden, codes.NoLiveGrant, f)
	}
	table, err := a.tableAt(tx, at)
	if err != nil {
		return storeDown()
	}
	for _, r := range roles {
		if entry, ok := table[r]; ok && PermitsClass(entry, wire.ClassControl) {
			return nil
		}
	}
	return refuse(http.StatusForbidden, codes.RoleForbidsOpClass, map[string]any{
		"op_class": int(wire.ClassControl),
		"roles":    roles,
	})
}

// registerFirst is the rule that spans types: an author's first op must be the
// control op that registers it.
func (a *Authority) registerFirst(tx oplog.Tx, p *ControlPayload, op oplog.Op, _ int64) *oplog.Refusal {
	seq := op.Header().AuthorSeq
	registers := p.Type == wire.CtlWorkspaceGenesis || p.Type == wire.CtlMemberRegister
	bad := refuse(unproc, codes.MemberRegisterNotFirst, map[string]any{"author_seq": seq})

	if registers {
		if seq != 1 {
			return bad
		}
		return nil
	}
	if seq == 1 {
		return bad
	}
	return nil
}

// ── workspace_genesis ───────────────────────────────────────────────────────

func (a *Authority) genesis(tx oplog.Tx, p *ControlPayload, op oplog.Op, at int64) *oplog.Refusal {
	g, r := ParseGenesis(p.CertBytes)
	if r != nil {
		return r
	}
	h := op.Header()

	// Not at batch index 0, or the Workspace already exists. A second genesis is
	// not a fork for the server to resolve: both documents claim to be the
	// beginning and the chain rule cannot separate two ops with no predecessor,
	// so the server takes the one that lands.
	exists, err := tx.WorkspaceExists()
	if err != nil {
		return storeDown()
	}
	if exists || op.Index != 0 {
		return refuse(http.StatusConflict, codes.GenesisNotFirst, nil)
	}
	if !a.creatable(g.RootPK, g.WorkspaceID) {
		return refuse(http.StatusForbidden, codes.WorkspaceNotReachable, nil)
	}
	if g.Founder.RegisteredAtSeqIsNotOne(h.AuthorSeq) {
		return refuse(unproc, codes.MemberRegisterNotFirst, map[string]any{"author_seq": h.AuthorSeq})
	}
	// A genesis verifies under the root_pk inside its own certificate, and is
	// never delegable.
	if !a.verifyOne(g.RootPK, wire.DocWorkspaceGenesis, p.CertBytes, p.CertSig) {
		return refuse(unproc, codes.BadRootSignature, nil)
	}
	if g.WorkspaceID != h.WorkspaceID {
		return refuse(unproc, codes.CertWorkspaceMismatch, nil)
	}
	if g.Founder.MemberID != h.AuthorMemberID {
		return refuse(unproc, codes.CertMemberMismatch, nil)
	}
	if r := a.checkFounderKeys(tx, g.Founder, h.AuthorMemberID); r != nil {
		return r
	}
	if !a.knownMemberKind(g.Founder.MemberKind) {
		return refuse(unproc, codes.UnknownMemberKind, nil)
	}

	// A genesis brings the Workspace into being, and carries its own founder's
	// registration: nothing earlier in the log can introduce it.
	if err := tx.MarkGenesis(at); err != nil {
		return storeDown()
	}
	if err := tx.SetRoot(g.RootPK); err != nil {
		return storeDown()
	}
	return a.applyRegistration(tx, g.Founder, at)
}

// RegisteredAtSeqIsNotOne reports whether the founder's op is not its first.
func (r Registration) RegisteredAtSeqIsNotOne(authorSeq uint64) bool { return authorSeq != 1 }

func (a *Authority) creatable(rootPK [32]byte, workspace [16]byte) bool {
	if a.Profile.Creatable != nil {
		return a.Profile.Creatable(rootPK, workspace)
	}
	// Under `derived` with no predicate supplied the answer is the profile's
	// arithmetic, which this core does not compute for it.
	return true
}

func (a *Authority) knownMemberKind(kind string) bool {
	for _, k := range a.Profile.MemberKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// checkFounderKeys is cert_key_mismatch: the certificate must name this device's
// registered keys.
func (a *Authority) checkFounderKeys(tx oplog.Tx, reg Registration, member [16]byte) *oplog.Refusal {
	rec, ok, err := tx.MemberRecord(member)
	if err != nil {
		return storeDown()
	}
	if !ok {
		// No shell record here to compare against; the certificate stands on its
		// own claim, which the signature already covered.
		return nil
	}
	if rec.ControlPK != reg.Control.PK || rec.ContentPK != reg.Content.PK || rec.KexPK != reg.Kex.PK {
		return refuse(unproc, codes.CertKeyMismatch, nil)
	}
	return nil
}

func (a *Authority) applyRegistration(tx oplog.Tx, reg Registration, at int64) *oplog.Refusal {
	err := tx.PutRegistration(oplog.MemberRecord{
		MemberID:     reg.MemberID,
		Kind:         reg.MemberKind,
		HolderRef:    reg.HolderRef,
		ControlPK:    reg.Control.PK,
		ContentPK:    reg.Content.PK,
		KexPK:        reg.Kex.PK,
		RegisteredAt: at,
	})
	if err != nil {
		return storeDown()
	}
	return nil
}

// ── member_register ─────────────────────────────────────────────────────────

func (a *Authority) register(tx oplog.Tx, p *ControlPayload, op oplog.Op, at int64) *oplog.Refusal {
	reg, r := ParseRegistration(p.CertBytes)
	if r != nil {
		return r
	}
	h := op.Header()

	exists, err := tx.WorkspaceExists()
	if err != nil {
		return storeDown()
	}
	if !exists {
		return refuse(http.StatusConflict, codes.WorkspaceNotCreated, nil)
	}
	keys, err := rootAuthorityAt(tx, at, true)
	if err != nil {
		return storeDown()
	}
	if !a.verifyUnder(keys, wire.DocMemberRegister, p.CertBytes, p.CertSig) {
		return refuse(unproc, codes.BadRootSignature, nil)
	}
	if reg.WorkspaceID != h.WorkspaceID {
		return refuse(unproc, codes.CertWorkspaceMismatch, nil)
	}
	if reg.MemberID != h.AuthorMemberID {
		return refuse(unproc, codes.CertMemberMismatch, nil)
	}
	if r := a.checkFounderKeys(tx, *reg, h.AuthorMemberID); r != nil {
		return r
	}
	if !a.knownMemberKind(reg.MemberKind) {
		return refuse(unproc, codes.UnknownMemberKind, nil)
	}
	return a.applyRegistration(tx, *reg, at)
}

// ── member_amend ────────────────────────────────────────────────────────────

func (a *Authority) amend(tx oplog.Tx, p *ControlPayload, op oplog.Op, at int64) *oplog.Refusal {
	am, r := ParseAmendment(p.CertBytes)
	if r != nil {
		return r
	}
	h := op.Header()

	if am.WorkspaceID != h.WorkspaceID {
		return refuse(unproc, codes.CertWorkspaceMismatch, nil)
	}
	// An amend is self-posted, and this is what holds it to that. There is no
	// unknown-member verdict to raise: the device that must hold the new secret
	// keys is the natural device to post the document installing them.
	if am.MemberID != h.AuthorMemberID {
		return refuse(unproc, codes.CertMemberMismatch, nil)
	}
	keys, err := rootAuthorityAt(tx, at, true)
	if err != nil {
		return storeDown()
	}
	if !a.verifyUnder(keys, wire.DocMemberAmend, p.CertBytes, p.CertSig) {
		return refuse(unproc, codes.BadRootSignature, nil)
	}
	used, err := tx.AmendIDUsed(am.AmendID)
	if err != nil {
		return storeDown()
	}
	if used {
		return refuse(http.StatusConflict, codes.AmendIdAlreadyUsed, nil)
	}

	toChange := func(k *KeyBlock) *oplog.KeyChange {
		if k == nil {
			return nil
		}
		return &oplog.KeyChange{PK: k.PK, KeyID: k.KeyID}
	}
	if err := tx.PutAmend(am.MemberID, am.AmendID,
		toChange(am.Control), toChange(am.Content), toChange(am.Kex), at); err != nil {
		return storeDown()
	}
	// Where control is one of the keys, the cascade runs: a credential the
	// retired key already obtained would otherwise outlive the retirement.
	if am.Control != nil {
		if err := tx.EndDeviceSessions(am.MemberID); err != nil {
			return storeDown()
		}
	}
	return nil
}

// ── grant ───────────────────────────────────────────────────────────────────

func (a *Authority) grant(tx oplog.Tx, p *ControlPayload, op oplog.Op, at int64) *oplog.Refusal {
	g, r := ParseGrantCert(p.CertBytes)
	if r != nil {
		return r
	}
	h := op.Header()

	if g.WorkspaceID != h.WorkspaceID {
		return refuse(unproc, codes.CertWorkspaceMismatch, nil)
	}
	// Authority does not travel by courier. The payload's granter says which key
	// to check against and the certificate names its own; a disagreement is a
	// forgery attempt, not a spelling. And a device cannot post a grant claiming
	// some other device approved it.
	if g.Granter != p.Granter || (!p.Granter.Root && p.Granter.Member != h.AuthorMemberID) {
		return refuse(unproc, codes.CertGranterMismatch, nil)
	}
	ok, err := a.verifyGrantAuthority(tx, p.Granter, wire.DocGrant, p.CertBytes, p.CertSig, at)
	if err != nil {
		return storeDown()
	}
	if !ok {
		return refuse(unproc, codes.BadGrantSignature, nil)
	}

	table, err := a.tableAt(tx, at)
	if err != nil {
		return storeDown()
	}
	if _, known := table[g.Role]; !known {
		return refuse(unproc, codes.UnknownRole, nil)
	}
	// Rule 3: an owner grant may only be created with granter = root, and only
	// revoked the same way. If an owner could mint another owner, a compromised
	// device could create an attacker-owner cheaply while removing one still cost
	// Root — an asymmetry that favours the attacker.
	if g.Role == profileOwner && !p.Granter.Root {
		return refuse(unproc, codes.OwnerGrantRequiresRoot, nil)
	}
	// A grant is never held as a dangling forward reference. A shell is not a
	// third cause, it is the same absence read off this Workspace's own log.
	registered, err := tx.Registered(g.MemberID)
	if err != nil {
		return storeDown()
	}
	if !registered {
		return refuse(unproc, codes.UnknownGrantee, nil)
	}
	if r := a.grantAdmissible(tx, g); r != nil {
		return r
	}
	existing, found, err := tx.GrantByID(g.GrantID)
	if err != nil {
		return storeDown()
	}
	if found && existing.Member != g.MemberID {
		return refuse(http.StatusConflict, codes.GrantIdAlreadyUsed, nil)
	}
	if found {
		return refuse(http.StatusConflict, codes.GrantIdAlreadyUsed, nil)
	}

	return storeErr(tx.PutGrant(oplog.Grant{
		GrantID: g.GrantID, Member: g.MemberID, Role: g.Role,
		Granter: p.Granter.Member, GranterIsRoot: p.Granter.Root, Start: at,
	}))
}

const profileOwner = "owner"

func (a *Authority) grantAdmissible(tx oplog.Tx, g *GrantCert) *oplog.Refusal {
	rule, ok := a.Profile.GrantAdmissible.Get()
	if !ok || rule == nil {
		return nil
	}
	if !rule(g.Role, g.Granter.Member, g.MemberID) {
		return refuse(unproc, codes.MemberKindForbidden, nil)
	}
	return nil
}

// verifyGrantAuthority resolves the named authority and checks the signature.
//
// "root" resolves to root authority — the current Root, then each delegation
// live at this position. A uuid resolves to that device's control key in force
// there.
func (a *Authority) verifyGrantAuthority(tx oplog.Tx, who Principal, doc string, cert []byte, sig [64]byte, at int64) (bool, error) {
	if who.Root {
		keys, err := rootAuthorityAt(tx, at, true)
		if err != nil {
			return false, err
		}
		return a.verifyUnder(keys, doc, cert, sig), nil
	}
	key, ok, err := tx.ControlKeyAt(who.Member, at)
	if err != nil || !ok {
		return false, err
	}
	return a.verifyOne(key, doc, cert, sig), nil
}

// ── revoke ──────────────────────────────────────────────────────────────────

func (a *Authority) revoke(tx oplog.Tx, p *ControlPayload, op oplog.Op, at int64) *oplog.Refusal {
	rc, r := ParseRevokeCert(p.CertBytes)
	if r != nil {
		return r
	}
	h := op.Header()

	if rc.WorkspaceID != h.WorkspaceID {
		return refuse(unproc, codes.CertWorkspaceMismatch, nil)
	}
	if rc.Revoker != p.Granter || (!p.Granter.Root && p.Granter.Member != h.AuthorMemberID) {
		return refuse(unproc, codes.CertGranterMismatch, nil)
	}
	ok, err := a.verifyGrantAuthority(tx, p.Granter, wire.DocRevoke, p.CertBytes, p.CertSig, at)
	if err != nil {
		return storeDown()
	}
	if !ok {
		return refuse(unproc, codes.BadRevokeSignature, nil)
	}
	target, found, err := tx.GrantByID(rc.GrantID)
	if err != nil {
		return storeDown()
	}
	if !found {
		return refuse(unproc, codes.UnknownGrant, nil)
	}
	if target.End != 0 {
		return refuse(unproc, codes.AlreadyRevoked, nil)
	}
	if target.Role == profileOwner && !p.Granter.Root {
		return refuse(unproc, codes.OwnerRevokeRequiresRoot, nil)
	}

	// The window closes at this position, immutably. Moving the mark forward
	// would widen the window an already-revoked grant covers.
	if err := tx.CloseGrant(rc.GrantID, at); err != nil {
		return storeDown()
	}
	// Losing the last live grant is a three-part event. Revocation is
	// grant-granular and does not cascade to other grants — revoking the granter
	// leaves the grants it issued live — but losing the last one ends the
	// device's sessions here.
	live, err := tx.LiveGrantsAt(target.Member, at+1)
	if err != nil {
		return storeDown()
	}
	if len(live) == 0 {
		if err := tx.EndDeviceSessions(target.Member); err != nil {
			return storeDown()
		}
	}
	return nil
}

// ── delegate and revoke_delegation ──────────────────────────────────────────

func (a *Authority) delegate(tx oplog.Tx, p *ControlPayload, op oplog.Op, at int64) *oplog.Refusal {
	d, r := ParseDelegateCert(p.CertBytes)
	if r != nil {
		return r
	}
	if d.WorkspaceID != op.Header().WorkspaceID {
		return refuse(unproc, codes.CertWorkspaceMismatch, nil)
	}
	// Signed by Root itself: a delegate that could delegate is a delegate that
	// could outlive its own revocation.
	root, ok, err := tx.CurrentRoot()
	if err != nil {
		return storeDown()
	}
	if !ok || !a.verifyOne(root, wire.DocDelegate, p.CertBytes, p.CertSig) {
		return refuse(unproc, codes.BadRootSignature, nil)
	}
	// A delegation must not name any device's registered signing key here, and
	// must not name the current Root. Both would blur two authorities into one
	// key.
	inUse, err := tx.IsRegisteredSigningKey(d.DelegatePK)
	if err != nil {
		return storeDown()
	}
	if inUse || d.DelegatePK == root {
		return refuse(unproc, codes.DelegatePkInUse, nil)
	}
	if _, found, err := tx.DelegationByID(d.DelegationID); err != nil {
		return storeDown()
	} else if found {
		return refuse(http.StatusConflict, codes.DelegationIdAlreadyUsed, nil)
	}
	return storeErr(tx.PutDelegation(oplog.Delegation{
		DelegationID: d.DelegationID, PK: d.DelegatePK, Start: at,
	}))
}

func (a *Authority) revokeDelegation(tx oplog.Tx, p *ControlPayload, op oplog.Op, at int64) *oplog.Refusal {
	rd, r := ParseRevokeDelegationCert(p.CertBytes)
	if r != nil {
		return r
	}
	if rd.WorkspaceID != op.Header().WorkspaceID {
		return refuse(unproc, codes.CertWorkspaceMismatch, nil)
	}
	root, ok, err := tx.CurrentRoot()
	if err != nil {
		return storeDown()
	}
	if !ok || !a.verifyOne(root, wire.DocRevokeDelegation, p.CertBytes, p.CertSig) {
		return refuse(unproc, codes.BadRootSignature, nil)
	}
	target, found, err := tx.DelegationByID(rd.DelegationID)
	if err != nil {
		return storeDown()
	}
	if !found {
		return refuse(unproc, codes.UnknownDelegation, nil)
	}
	if target.End != 0 {
		return refuse(unproc, codes.AlreadyRevoked, nil)
	}
	// It changes nothing the delegation already signed: registrations it issued
	// stay accepted, grants it minted stay live.
	return storeErr(tx.CloseDelegation(rd.DelegationID, at))
}

// ── root_handover ───────────────────────────────────────────────────────────

func (a *Authority) handover(tx oplog.Tx, p *ControlPayload, op oplog.Op, _ int64) *oplog.Refusal {
	hc, r := ParseHandoverCert(p.CertBytes)
	if r != nil {
		return r
	}
	if hc.WorkspaceID != op.Header().WorkspaceID {
		return refuse(unproc, codes.CertWorkspaceMismatch, nil)
	}
	root, ok, err := tx.CurrentRoot()
	if err != nil {
		return storeDown()
	}
	// cert_root_pk_mismatch sits above the signature deliberately. A device
	// skewed across a handover builds against the retired Root; judged after the
	// signature it would be told bad_root_signature — the code reserved for
	// "forged, and no remedy" — instead of "rebuild against the Root the log
	// reports", which is the entire remedy for skew.
	if !ok || hc.FromRootPK != root {
		return refuse(unproc, codes.CertRootPkMismatch, nil)
	}
	// Signed by the key it retires, never by the key it installs.
	if !a.verifyOne(root, wire.DocRootHandover, p.CertBytes, p.CertSig) {
		return refuse(unproc, codes.BadRootSignature, nil)
	}
	// Moves the current Root and nothing else. The founding Root — the one the
	// Workspace id is bound to — is unchanged and unchangeable.
	return storeErr(tx.SetRoot(hc.ToRootPK))
}

// ── role_table ──────────────────────────────────────────────────────────────

func (a *Authority) roleTable(tx oplog.Tx, p *ControlPayload, op oplog.Op, at int64) *oplog.Refusal {
	t, r := ParseRoleTableCert(p.CertBytes)
	if r != nil {
		return r
	}
	if t.WorkspaceID != op.Header().WorkspaceID {
		return refuse(unproc, codes.CertWorkspaceMismatch, nil)
	}
	// Signed by the current Root itself, never by a delegate: the role table is
	// the authority vocabulary rather than an exercise of authority, and a
	// delegate that could rewrite it could hand itself every class Root never
	// authorised.
	root, ok, err := tx.CurrentRoot()
	if err != nil {
		return storeDown()
	}
	if !ok || !a.verifyOne(root, wire.DocRoleTable, p.CertBytes, p.CertSig) {
		return refuse(unproc, codes.BadRootSignature, nil)
	}
	// Replaces the vocabulary from its own position and changes the verdict of
	// nothing already in the log. Installing one table twice is installing it
	// once, so a replay needs no exemption of its own.
	return storeErr(tx.PutRoleTable(ToProfileTable(t.Roles), at))
}

// ── rotate ──────────────────────────────────────────────────────────────────

func (a *Authority) rotate(tx oplog.Tx, p *ControlPayload, op oplog.Op, at int64) *oplog.Refusal {
	if p.WorkspaceID != op.Header().WorkspaceID {
		return refuse(unproc, codes.CertWorkspaceMismatch, nil)
	}
	current, err := tx.CurrentEpoch()
	if err != nil {
		return storeDown()
	}
	// from_epoch must be the Workspace's current epoch, so two owners racing a
	// rotation cannot both land and leave the log claiming two different keys for
	// one epoch.
	if p.FromEpoch != current {
		return refuse(http.StatusConflict, codes.RotateEpochConflict, map[string]any{
			"from_epoch":          int(p.FromEpoch),
			"expected_from_epoch": int(current),
		})
	}
	return storeErr(tx.PutRotate(p.FromEpoch, p.ToEpoch, p.KeywrapDigest, at))
}

func storeErr(err error) *oplog.Refusal {
	if err != nil {
		return storeDown()
	}
	return nil
}
