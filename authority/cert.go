package authority

import (
	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/strictjson"
	"github.com/loonybin/roundelay/wire"
)

// HLC is a logical clock: [wall_ms, counter, member_id as 32 hex chars]. The
// server stores it and never orders by it.
type HLC struct {
	WallMS  int64
	Counter int64
	Member  [16]byte
}

// KeyBlock is a public key and its derived id.
type KeyBlock struct {
	PK    [32]byte
	KeyID [8]byte
}

// Registration is the member_register document, and — minus workspace_id — the
// founder block a genesis embeds.
type Registration struct {
	WorkspaceID  [16]byte
	MemberID     [16]byte
	MemberKind   string
	HolderRef    [32]byte
	Control      KeyBlock
	Content      KeyBlock
	Kex          KeyBlock
	RegisteredAt HLC
}

// Genesis is the workspace_genesis document.
type Genesis struct {
	WorkspaceID [16]byte
	RootPK      [32]byte
	Founder     Registration
	CreatedAt   HLC
}

// Amendment is the member_amend document.
//
// Its keys object is closed over a subset of {control, content, kex}, at least
// one present. A key the amendment does not name is a key it does not move,
// which is why absence carries meaning here and nowhere else: three mandatory
// members with a convention for "unchanged" would be a second spelling of the
// current value, sitting in a signed document, waiting to disagree with the log.
type Amendment struct {
	WorkspaceID [16]byte
	MemberID    [16]byte
	AmendID     [16]byte
	Control     *KeyBlock
	Content     *KeyBlock
	Kex         *KeyBlock
	AmendedAt   HLC
}

// GrantCert is the grant document.
type GrantCert struct {
	WorkspaceID [16]byte
	GrantID     [16]byte
	MemberID    [16]byte
	Role        string
	Granter     Principal
	GrantedAt   HLC
}

// RevokeCert is the revoke document.
type RevokeCert struct {
	WorkspaceID [16]byte
	RevokeID    [16]byte
	GrantID     [16]byte
	Revoker     Principal
	RevokedAt   HLC
}

// DelegateCert is the delegate document.
type DelegateCert struct {
	WorkspaceID  [16]byte
	DelegationID [16]byte
	DelegatePK   [32]byte
	DelegatedAt  HLC
}

// RevokeDelegationCert is the revoke_delegation document.
type RevokeDelegationCert struct {
	WorkspaceID  [16]byte
	RevocationID [16]byte
	DelegationID [16]byte
	RevokedAt    HLC
}

// HandoverCert is the root_handover document.
//
// It is signed by the key it retires, never by the key it installs: only the
// outgoing Root can attest that the succession is intended, and a signature by
// the incoming key would prove nothing, because anyone can mint a keypair. It
// carries no id of its own — from_root_pk already makes it unrepeatable.
type HandoverCert struct {
	WorkspaceID [16]byte
	FromRootPK  [32]byte
	ToRootPK    [32]byte
	HandedOver  HLC
}

// RoleTableCert is the role_table document: a complete replacement table, never
// a patch.
type RoleTableCert struct {
	WorkspaceID [16]byte
	Roles       []RoleEntry
	AdoptedAt   HLC
}

// RoleEntry is one row of a role table certificate: a closed set of exactly
// three keys.
type RoleEntry struct {
	Role       string
	Classes    []byte
	PruneTypes []string
}

// readHLC reads a [wall_ms, counter, member_id] triple.
func readHLC(o *strictjson.Object, name string) HLC {
	a := o.Array(name)
	var h HLC
	h.WallMS = a.Int(0, strictjson.HLCWallRange)
	h.Counter = a.Int(1, strictjson.HLCCounterRange)
	copy(h.Member[:], a.Hex(2, 16))
	a.Exactly(3)
	return h
}

// readKeyBlock reads a public key and its claimed id, and cross-checks the
// derivation.
//
// Every key id inside a certificate is the first 8 bytes of SHA-256 of the key
// beside it, and a claimed id that disagrees is a forgery attempt, not a variant
// spelling. The verdict is malformed_control_payload: it is arithmetic over the
// document's own literals, so it is shape, settled above the signature.
func readKeyBlock(o *strictjson.Object, pkName, idName string) KeyBlock {
	var k KeyBlock
	pk := o.Bytes(pkName, 32)
	id := o.Bytes(idName, 8)
	if pk == nil || id == nil {
		return k
	}
	copy(k.PK[:], pk)
	copy(k.KeyID[:], id)
	if wire.KeyID(pk) != k.KeyID {
		o.Reject(idName, "is not the first 8 bytes of SHA-256 over the key beside it")
	}
	return k
}

func readRegistrationBody(o *strictjson.Object) Registration {
	var r Registration
	r.MemberID = o.UUID("member_id")
	r.MemberKind = o.Token("member_kind")
	copy(r.HolderRef[:], o.Bytes("holder_ref", 32))
	r.Control = readKeyBlock(o, "control_pk", "control_key_id")
	r.Content = readKeyBlock(o, "content_pk", "content_key_id")
	r.Kex = readKeyBlock(o, "kex_pk", "kex_key_id")
	r.RegisteredAt = readHLC(o, "registered_at_hlc")
	return r
}

// ParseRegistration reads a member_register certificate.
func ParseRegistration(cert []byte) (*Registration, *oplog.Refusal) {
	doc, err := strictjson.Parse(cert)
	if err != nil {
		return nil, malformedPayload()
	}
	o := doc.Root()
	r := readRegistrationBody(o)
	r.WorkspaceID = o.UUID("workspace_id")
	if doc.Err() != nil {
		return nil, malformedPayload()
	}
	return &r, nil
}

// ParseGenesis reads a workspace_genesis certificate.
//
// The founder block is a closed set of exactly ten keys — the registration
// certificate's own set minus workspace_id, which the genesis already carries
// once. A nested copy would be a second spelling of a single value, and the only
// thing to do with a second spelling is cross-check it against the first.
func ParseGenesis(cert []byte) (*Genesis, *oplog.Refusal) {
	doc, err := strictjson.Parse(cert)
	if err != nil {
		return nil, malformedPayload()
	}
	o := doc.Root()
	var g Genesis
	g.WorkspaceID = o.UUID("workspace_id")
	copy(g.RootPK[:], o.Bytes("root_pk", 32))
	g.Founder = readRegistrationBody(o.Object("founder"))
	g.Founder.WorkspaceID = g.WorkspaceID
	g.CreatedAt = readHLC(o, "created_at_hlc")
	if doc.Err() != nil {
		return nil, malformedPayload()
	}
	return &g, nil
}

// ParseAmendment reads a member_amend certificate.
func ParseAmendment(cert []byte) (*Amendment, *oplog.Refusal) {
	doc, err := strictjson.Parse(cert)
	if err != nil {
		return nil, malformedPayload()
	}
	o := doc.Root()
	var a Amendment
	a.WorkspaceID = o.UUID("workspace_id")
	a.MemberID = o.UUID("member_id")
	a.AmendID = o.UUID("amend_id")

	keys := o.Object("keys")
	read := func(name string) *KeyBlock {
		if !keys.Has(name) {
			return nil
		}
		sub := keys.Object(name)
		k := readKeyBlock(sub, "pk", "key_id")
		return &k
	}
	a.Control = read("control")
	a.Content = read("content")
	a.Kex = read("kex")
	a.AmendedAt = readHLC(o, "amended_at_hlc")
	if doc.Err() != nil {
		return nil, malformedPayload()
	}
	// At least one present. An empty keys object is a document that moves
	// nothing, and the subset is what says which keys the amendment touches.
	if a.Control == nil && a.Content == nil && a.Kex == nil {
		return nil, malformedPayload()
	}
	return &a, nil
}

// ParseGrantCert reads a grant certificate.
func ParseGrantCert(cert []byte) (*GrantCert, *oplog.Refusal) {
	doc, err := strictjson.Parse(cert)
	if err != nil {
		return nil, malformedPayload()
	}
	o := doc.Root()
	var g GrantCert
	g.WorkspaceID = o.UUID("workspace_id")
	g.GrantID = o.UUID("grant_id")
	g.MemberID = o.UUID("member_id")
	g.Role = o.Token("role")
	id, isRoot := o.Authority("granter")
	g.Granter = Principal{Root: isRoot, Member: id}
	g.GrantedAt = readHLC(o, "granted_at_hlc")
	if doc.Err() != nil {
		return nil, malformedPayload()
	}
	return &g, nil
}

// ParseRevokeCert reads a revoke certificate.
func ParseRevokeCert(cert []byte) (*RevokeCert, *oplog.Refusal) {
	doc, err := strictjson.Parse(cert)
	if err != nil {
		return nil, malformedPayload()
	}
	o := doc.Root()
	var r RevokeCert
	r.WorkspaceID = o.UUID("workspace_id")
	r.RevokeID = o.UUID("revoke_id")
	r.GrantID = o.UUID("grant_id")
	id, isRoot := o.Authority("revoker")
	r.Revoker = Principal{Root: isRoot, Member: id}
	r.RevokedAt = readHLC(o, "revoked_at_hlc")
	if doc.Err() != nil {
		return nil, malformedPayload()
	}
	return &r, nil
}

// ParseDelegateCert reads a delegate certificate.
//
// A delegate_pk that is not 32 bytes is malformed_root_pk rather than
// malformed_control_payload — a shape verdict of its own, sitting above the
// signature exactly as malformed_role_table does.
func ParseDelegateCert(cert []byte) (*DelegateCert, *oplog.Refusal) {
	doc, err := strictjson.Parse(cert)
	if err != nil {
		return nil, malformedPayload()
	}
	o := doc.Root()
	var d DelegateCert
	d.WorkspaceID = o.UUID("workspace_id")
	d.DelegationID = o.UUID("delegation_id")
	pk := o.Bytes("delegate_pk", 32)
	d.DelegatedAt = readHLC(o, "delegated_at_hlc")
	if err := doc.Err(); err != nil {
		if onlyPath(err, "delegate_pk") {
			return nil, refuse(unproc, codes.MalformedRootPk, nil)
		}
		return nil, malformedPayload()
	}
	copy(d.DelegatePK[:], pk)
	return &d, nil
}

// ParseRevokeDelegationCert reads a revoke_delegation certificate.
func ParseRevokeDelegationCert(cert []byte) (*RevokeDelegationCert, *oplog.Refusal) {
	doc, err := strictjson.Parse(cert)
	if err != nil {
		return nil, malformedPayload()
	}
	o := doc.Root()
	var r RevokeDelegationCert
	r.WorkspaceID = o.UUID("workspace_id")
	r.RevocationID = o.UUID("revocation_id")
	r.DelegationID = o.UUID("delegation_id")
	r.RevokedAt = readHLC(o, "revoked_at_hlc")
	if doc.Err() != nil {
		return nil, malformedPayload()
	}
	return &r, nil
}

// ParseHandoverCert reads a root_handover certificate.
func ParseHandoverCert(cert []byte) (*HandoverCert, *oplog.Refusal) {
	doc, err := strictjson.Parse(cert)
	if err != nil {
		return nil, malformedPayload()
	}
	o := doc.Root()
	var h HandoverCert
	h.WorkspaceID = o.UUID("workspace_id")
	from := o.Bytes("from_root_pk", 32)
	to := o.Bytes("to_root_pk", 32)
	h.HandedOver = readHLC(o, "handed_over_at_hlc")
	if err := doc.Err(); err != nil {
		if onlyPaths(err, "from_root_pk", "to_root_pk") {
			return nil, refuse(unproc, codes.MalformedRootPk, nil)
		}
		return nil, malformedPayload()
	}
	copy(h.FromRootPK[:], from)
	copy(h.ToRootPK[:], to)
	return &h, nil
}

// ParseRoleTableCert reads a role_table certificate and applies the five core
// rules.
//
// malformed_role_table is shape, decided from the certificate's own bytes and
// nothing else, so it sits above the signature. It is distinct from
// malformed_control_payload because the remedies are different sizes: "your
// payload carries a key it should not" is a serialisation bug; "your table has
// two owners" is a table to redesign.
func ParseRoleTableCert(cert []byte) (*RoleTableCert, *oplog.Refusal) {
	badTable := refuse(unproc, codes.MalformedRoleTable, nil)

	doc, err := strictjson.Parse(cert)
	if err != nil {
		return nil, malformedPayload()
	}
	o := doc.Root()
	var t RoleTableCert
	t.WorkspaceID = o.UUID("workspace_id")

	arr := o.Array("roles")
	for i := range arr.Len() {
		e := arr.Object(i)
		var row RoleEntry
		row.Role = e.Token("role")
		classes := e.Array("classes")
		for j := range classes.Len() {
			row.Classes = append(row.Classes, byte(classes.Int(j, strictjson.OpClassRange)))
		}
		types := e.Array("prune_types")
		for j := range types.Len() {
			row.PruneTypes = append(row.PruneTypes, types.String(j))
		}
		t.Roles = append(t.Roles, row)
	}
	t.AdoptedAt = readHLC(o, "adopted_at_hlc")

	if err := doc.Err(); err != nil {
		// A misshapen entry is the table's verdict; a misshapen outer document is
		// the payload's.
		if underRoles(err) {
			return nil, badTable
		}
		return nil, malformedPayload()
	}
	if r := CheckRoleTable(t.Roles); r != nil {
		return nil, r
	}
	return &t, nil
}
