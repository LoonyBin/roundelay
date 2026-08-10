package authority_test

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/loonybin/roundelay/authority"
	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/internal/vectors"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/wire"
)

var b64 = base64.StdEncoding

const (
	zeroLink   = "0000000000000000000000000000000000000000000000000000000000000000"
	someLink   = "1111111111111111111111111111111111111111111111111111111111111111"
	letterLink = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	uuidA      = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
	uuidB      = "11111111-2222-3333-4444-555555555555"
	hlc        = `[1700000000000,0,"00000000000000000000000000000000"]`
)

func b(n int, fill byte) string {
	raw := make([]byte, n)
	for i := range raw {
		raw[i] = fill
	}
	return b64.EncodeToString(raw)
}

// keyPair returns a base64 public key and its correctly derived id.
func keyPair(fill byte) (string, string) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = fill
	}
	id := wire.KeyID(raw)
	return b64.EncodeToString(raw), b64.EncodeToString(id[:])
}

func wantRefusal(t *testing.T, r *oplog.Refusal, code codes.Code) {
	t.Helper()
	if r == nil {
		t.Fatalf("expected %s, got acceptance", code)
	}
	if r.Code != code {
		t.Fatalf("got %s, want %s", r.Code, code)
	}
}

// ── the control payload ─────────────────────────────────────────────────────

func TestControlPayloadClosedKeySets(t *testing.T) {
	ok := `{"type":"grant","prev_control_hash":"` + someLink + `","granter":"root",` +
		`"cert_b64":"QUJD","cert_sig_b64":"` + b(64, 7) + `"}`
	if _, r := authority.ParseControlPayload([]byte(ok)); r != nil {
		t.Fatalf("a well-formed grant payload was refused: %s", r.Code)
	}

	for _, c := range []struct{ name, body string }{
		{"a key from another type", `{"type":"grant","prev_control_hash":"` + someLink + `","granter":"root",
			"revoker":"root","cert_b64":"QUJD","cert_sig_b64":"` + b(64, 7) + `"}`},
		{"a missing key", `{"type":"grant","prev_control_hash":"` + someLink + `","cert_b64":"QUJD","cert_sig_b64":"` + b(64, 7) + `"}`},
		{"a key nothing defines", `{"type":"grant","prev_control_hash":"` + someLink + `","granter":"root",
			"cert_b64":"QUJD","cert_sig_b64":"` + b(64, 7) + `","note":"hi"}`},
		{"no type at all", `{"prev_control_hash":"` + someLink + `","cert_b64":"QUJD"}`},
		{"a type that is not a string", `{"type":1,"prev_control_hash":"` + someLink + `"}`},
		// someLink is all digits, so uppercasing it would be a no-op — hex letters
		// are the whole of what this case is about.
		{"an uppercase link", `{"type":"grant","prev_control_hash":"` + strings.ToUpper(letterLink) + `","granter":"root",
			"cert_b64":"QUJD","cert_sig_b64":"` + b(64, 7) + `"}`},
		{"a short link", `{"type":"grant","prev_control_hash":"abcd","granter":"root",
			"cert_b64":"QUJD","cert_sig_b64":"` + b(64, 7) + `"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, r := authority.ParseControlPayload([]byte(c.body))
			wantRefusal(t, r, codes.MalformedControlPayload)
		})
	}
}

// A type this server does not serve is refused at its door, and that is a
// different verdict from a payload it cannot read.
func TestUnsupportedControlType(t *testing.T) {
	for _, typ := range []string{"fold", "note_something", "Grant", ""} {
		body := `{"type":"` + typ + `","prev_control_hash":"` + someLink + `"}`
		_, r := authority.ParseControlPayload([]byte(body))
		if typ == "" {
			// An empty string is a served-set miss, not a missing member.
			wantRefusal(t, r, codes.UnsupportedControlType)
			continue
		}
		wantRefusal(t, r, codes.UnsupportedControlType)
	}
}

// v1 serves no advisory type. The reservation is a place kept, not a member.
func TestAdvisoryTypesAreNotServed(t *testing.T) {
	if authority.ServesControlType("note_anything") {
		t.Error("an advisory type is in the served set")
	}
	for _, ct := range wire.ControlTypes {
		if !authority.ServesControlType(ct) {
			t.Errorf("%s is not served", ct)
		}
	}
}

// rotate is the one type with no certificate, and the one that carries its
// Workspace in the payload.
func TestRotatePayload(t *testing.T) {
	ok := `{"type":"rotate","prev_control_hash":"` + someLink + `","workspace_id":"` + uuidA + `",
		"from_epoch":2,"to_epoch":3,"keywrap_digest_b64":"` + b(32, 9) + `"}`
	p, r := authority.ParseControlPayload([]byte(ok))
	if r != nil {
		t.Fatalf("a well-formed rotate was refused: %s", r.Code)
	}
	if p.FromEpoch != 2 || p.ToEpoch != 3 || p.WorkspaceID[0] != 0x0a {
		t.Errorf("payload = %+v", p)
	}

	// A rotation that skips an epoch is malformed, not a conflict: it is
	// arithmetic over the document's own literals.
	skip := strings.Replace(ok, `"to_epoch":3`, `"to_epoch":4`, 1)
	_, r = authority.ParseControlPayload([]byte(skip))
	wantRefusal(t, r, codes.MalformedControlPayload)

	// And a rotate carrying a certificate is carrying a key its set does not have.
	withCert := strings.Replace(ok, `"from_epoch":2`, `"cert_b64":"QUJD","from_epoch":2`, 1)
	_, r = authority.ParseControlPayload([]byte(withCert))
	wantRefusal(t, r, codes.MalformedControlPayload)
}

// Only grant and revoke name their authority, because only they have a choice.
func TestGranterIsRootOrADevice(t *testing.T) {
	mk := func(granter string) string {
		return `{"type":"grant","prev_control_hash":"` + someLink + `","granter":` + granter +
			`,"cert_b64":"QUJD","cert_sig_b64":"` + b(64, 7) + `"}`
	}
	p, r := authority.ParseControlPayload([]byte(mk(`"root"`)))
	if r != nil || !p.Granter.Root {
		t.Fatalf("root granter: %v %+v", r, p)
	}
	p, r = authority.ParseControlPayload([]byte(mk(`"` + uuidB + `"`)))
	if r != nil || p.Granter.Root || p.Granter.Member[0] != 0x11 {
		t.Fatalf("device granter: %v %+v", r, p)
	}
	for _, bad := range []string{`"Root"`, `"owner"`, `1`, `null`} {
		_, r := authority.ParseControlPayload([]byte(mk(bad)))
		wantRefusal(t, r, codes.MalformedControlPayload)
	}
}

func TestCertificateDocumentPerType(t *testing.T) {
	for _, c := range []struct{ typ, doc string }{
		{wire.CtlWorkspaceGenesis, wire.DocWorkspaceGenesis},
		{wire.CtlMemberRegister, wire.DocMemberRegister},
		{wire.CtlMemberAmend, wire.DocMemberAmend},
		{wire.CtlGrant, wire.DocGrant},
		{wire.CtlRevoke, wire.DocRevoke},
		{wire.CtlRoleTable, wire.DocRoleTable},
		{wire.CtlDelegate, wire.DocDelegate},
		{wire.CtlRevokeDelegation, wire.DocRevokeDelegation},
		{wire.CtlRootHandover, wire.DocRootHandover},
	} {
		got, ok := authority.CertificateDocument(c.typ)
		if !ok || got != c.doc {
			t.Errorf("%s carries %q, want %q", c.typ, got, c.doc)
		}
	}
	if _, ok := authority.CertificateDocument(wire.CtlRotate); ok {
		t.Error("rotate was given a certificate document")
	}
}

// Four documents are withheld from delegates, and the list is the whole of what
// keeps the hierarchy from being decorative.
func TestDelegableSet(t *testing.T) {
	for _, t2 := range []string{wire.CtlMemberRegister, wire.CtlMemberAmend, wire.CtlGrant, wire.CtlRevoke} {
		if !authority.Delegable(t2) {
			t.Errorf("%s should be delegable", t2)
		}
	}
	for _, t2 := range []string{wire.CtlWorkspaceGenesis, wire.CtlRootHandover, wire.CtlRoleTable,
		wire.CtlDelegate, wire.CtlRevokeDelegation, wire.CtlRotate} {
		if authority.Delegable(t2) {
			t.Errorf("%s must never be delegable", t2)
		}
	}
}

// ── certificates ────────────────────────────────────────────────────────────

func registrationCert(memberID string) string {
	cpk, cid := keyPair(1)
	npk, nid := keyPair(2)
	kpk, kid := keyPair(3)
	return `{"workspace_id":"` + uuidA + `","member_id":"` + memberID + `","member_kind":"device",` +
		`"holder_ref":"` + b(32, 4) + `",` +
		`"control_pk":"` + cpk + `","control_key_id":"` + cid + `",` +
		`"content_pk":"` + npk + `","content_key_id":"` + nid + `",` +
		`"kex_pk":"` + kpk + `","kex_key_id":"` + kid + `",` +
		`"registered_at_hlc":` + hlc + `}`
}

func TestRegistrationCertificate(t *testing.T) {
	r, ref := authority.ParseRegistration([]byte(registrationCert(uuidB)))
	if ref != nil {
		t.Fatalf("a well-formed registration was refused: %s", ref.Code)
	}
	if r.MemberKind != "device" || r.MemberID[0] != 0x11 {
		t.Errorf("registration = %+v", r)
	}
}

// A claimed key id that disagrees with the key beside it is a forgery attempt,
// not a variant spelling — and it is arithmetic over the document's own
// literals, so it is shape.
func TestKeyIDMustBeTheDerivation(t *testing.T) {
	cert := registrationCert(uuidB)
	_, wrongID := keyPair(9)
	broken := strings.Replace(cert, `"control_key_id":"`+mustID(1)+`"`, `"control_key_id":"`+wrongID+`"`, 1)
	if broken == cert {
		t.Fatal("the fixture did not change")
	}
	_, ref := authority.ParseRegistration([]byte(broken))
	wantRefusal(t, ref, codes.MalformedControlPayload)
}

func mustID(fill byte) string {
	_, id := keyPair(fill)
	return id
}

// The founder block is the registration's set minus workspace_id, all ten
// present — a founder with a key missing is malformed, never a founder with
// fewer keys.
func TestGenesisFounderBlockIsClosed(t *testing.T) {
	cpk, cid := keyPair(1)
	npk, nid := keyPair(2)
	kpk, kid := keyPair(3)
	founder := `{"member_id":"` + uuidB + `","member_kind":"device","holder_ref":"` + b(32, 4) + `",` +
		`"control_pk":"` + cpk + `","control_key_id":"` + cid + `",` +
		`"content_pk":"` + npk + `","content_key_id":"` + nid + `",` +
		`"kex_pk":"` + kpk + `","kex_key_id":"` + kid + `",` +
		`"registered_at_hlc":` + hlc + `}`
	cert := `{"workspace_id":"` + uuidA + `","root_pk":"` + b(32, 5) + `","founder":` + founder +
		`,"created_at_hlc":` + hlc + `}`

	g, ref := authority.ParseGenesis([]byte(cert))
	if ref != nil {
		t.Fatalf("a well-formed genesis was refused: %s", ref.Code)
	}
	if g.Founder.WorkspaceID != g.WorkspaceID {
		t.Error("the founder did not inherit the genesis's Workspace")
	}

	// A nested workspace_id would be a second spelling of a single value.
	withWS := strings.Replace(cert, `"founder":{"member_id"`, `"founder":{"workspace_id":"`+uuidA+`","member_id"`, 1)
	_, ref = authority.ParseGenesis([]byte(withWS))
	wantRefusal(t, ref, codes.MalformedControlPayload)

	// A missing key.
	short := strings.Replace(cert, `"kex_key_id":"`+kid+`",`, "", 1)
	_, ref = authority.ParseGenesis([]byte(short))
	wantRefusal(t, ref, codes.MalformedControlPayload)
}

// The amendment's keys object is closed over a subset, at least one present. A
// key it does not name is a key it does not move.
func TestAmendmentSubset(t *testing.T) {
	cpk, cid := keyPair(1)
	mk := func(keys string) string {
		return `{"workspace_id":"` + uuidA + `","member_id":"` + uuidB + `","amend_id":"` + uuidA + `",` +
			`"keys":` + keys + `,"amended_at_hlc":` + hlc + `}`
	}
	one := `{"control":{"pk":"` + cpk + `","key_id":"` + cid + `"}}`
	a, ref := authority.ParseAmendment([]byte(mk(one)))
	if ref != nil {
		t.Fatalf("a one-key amendment was refused: %s", ref.Code)
	}
	if a.Control == nil || a.Content != nil || a.Kex != nil {
		t.Errorf("amendment = %+v", a)
	}

	// Empty moves nothing.
	_, ref = authority.ParseAmendment([]byte(mk(`{}`)))
	wantRefusal(t, ref, codes.MalformedControlPayload)

	// A member outside the closed three.
	_, ref = authority.ParseAmendment([]byte(mk(`{"control":{"pk":"` + cpk + `","key_id":"` + cid + `"},"signing":{"pk":"` + cpk + `","key_id":"` + cid + `"}}`)))
	wantRefusal(t, ref, codes.MalformedControlPayload)
}

// A delegate_pk that is not 32 bytes has a shape verdict of its own.
func TestDelegateCertificateKeyShape(t *testing.T) {
	mk := func(pk string) string {
		return `{"workspace_id":"` + uuidA + `","delegation_id":"` + uuidB + `","delegate_pk":"` + pk +
			`","delegated_at_hlc":` + hlc + `}`
	}
	if _, ref := authority.ParseDelegateCert([]byte(mk(b(32, 6)))); ref != nil {
		t.Fatalf("a well-formed delegate was refused: %s", ref.Code)
	}
	_, ref := authority.ParseDelegateCert([]byte(mk(b(31, 6))))
	wantRefusal(t, ref, codes.MalformedRootPk)

	// A problem elsewhere is the payload's verdict, not the key's.
	_, ref = authority.ParseDelegateCert([]byte(`{"workspace_id":"nope","delegation_id":"` + uuidB +
		`","delegate_pk":"` + b(31, 6) + `","delegated_at_hlc":` + hlc + `}`))
	wantRefusal(t, ref, codes.MalformedControlPayload)
}

func TestHandoverCertificateKeyShape(t *testing.T) {
	mk := func(from, to string) string {
		return `{"workspace_id":"` + uuidA + `","from_root_pk":"` + from + `","to_root_pk":"` + to +
			`","handed_over_at_hlc":` + hlc + `}`
	}
	if _, ref := authority.ParseHandoverCert([]byte(mk(b(32, 1), b(32, 2)))); ref != nil {
		t.Fatalf("a well-formed handover was refused: %s", ref.Code)
	}
	for _, c := range [][2]string{{b(31, 1), b(32, 2)}, {b(32, 1), b(33, 2)}} {
		_, ref := authority.ParseHandoverCert([]byte(mk(c[0], c[1])))
		wantRefusal(t, ref, codes.MalformedRootPk)
	}
}

// ── the role table ──────────────────────────────────────────────────────────

func roleTableCert(roles string) string {
	return `{"workspace_id":"` + uuidA + `","roles":` + roles + `,"adopted_at_hlc":` + hlc + `}`
}

func TestRoleTableCertificate(t *testing.T) {
	ok := `[{"role":"owner","classes":[1,2,128,129],"prune_types":["prune","hard_prune"]},
	        {"role":"participant","classes":[1,2],"prune_types":[]}]`
	tab, ref := authority.ParseRoleTableCert([]byte(roleTableCert(ok)))
	if ref != nil {
		t.Fatalf("a well-formed table was refused: %s", ref.Code)
	}
	if len(tab.Roles) != 2 {
		t.Fatalf("roles = %+v", tab.Roles)
	}
}

// Everything malformed_role_table covers, and each is the table's verdict rather
// than the payload's.
func TestMalformedRoleTable(t *testing.T) {
	for _, c := range []struct{ name, roles string }{
		{"no owner", `[{"role":"participant","classes":[1],"prune_types":[]}]`},
		// Two owners is also a repeated token, and there is no way for it not to
		// be: rule 1's upper bound is unreachable behind the repeat rule, so this
		// case exercises the repeat and the "no owner" case below exercises rule 1.
		{"two owners, which is also a repeated token", `[{"role":"owner","classes":[1],"prune_types":[]},{"role":"owner","classes":[2],"prune_types":[]}]`},
		{"a repeated token", `[{"role":"owner","classes":[1],"prune_types":[]},{"role":"a","classes":[1],"prune_types":[]},{"role":"a","classes":[2],"prune_types":[]}]`},
		{"a bad token", `[{"role":"Owner","classes":[1],"prune_types":[]},{"role":"owner","classes":[1],"prune_types":[]}]`},
		{"a repeated class", `[{"role":"owner","classes":[1,1],"prune_types":[]}]`},
		{"a class out of range", `[{"role":"owner","classes":[256],"prune_types":[]}]`},
		{"a class that is not an integer", `[{"role":"owner","classes":["0x01"],"prune_types":[]}]`},
		{"a non-owner naming 0x80", `[{"role":"owner","classes":[1],"prune_types":[]},{"role":"a","classes":[128],"prune_types":[]}]`},
		{"an unserved prune type", `[{"role":"owner","classes":[129],"prune_types":["fold"]}]`},
		{"a repeated prune type", `[{"role":"owner","classes":[129],"prune_types":["prune","prune"]}]`},
		{"prune types without 0x81", `[{"role":"owner","classes":[1],"prune_types":["prune"]}]`},
		{"an entry key set that is not the closed three", `[{"role":"owner","classes":[1],"prune_types":[],"note":"x"}]`},
		{"a missing prune_types", `[{"role":"owner","classes":[1]}]`},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, ref := authority.ParseRoleTableCert([]byte(roleTableCert(c.roles)))
			wantRefusal(t, ref, codes.MalformedRoleTable)
		})
	}

	// A problem in the outer document is the payload's verdict, because the
	// remedies are different sizes.
	_, ref := authority.ParseRoleTableCert([]byte(
		`{"workspace_id":"` + uuidA + `","roles":[{"role":"owner","classes":[1],"prune_types":[]}],` +
			`"adopted_at_hlc":` + hlc + `,"note":"x"}`))
	wantRefusal(t, ref, codes.MalformedControlPayload)
}

// Rule 5: an entry naming 0x81 confers prune only.
func TestPruneTypeLane(t *testing.T) {
	bare := profileEntry([]byte{0x02, 0x81}, nil)
	if !authority.PermitsPruneType(bare, wire.PruneSoft) {
		t.Error("a bare 0x81 entry does not confer prune")
	}
	for _, typ := range []string{wire.PruneExt, wire.PruneHard} {
		if authority.PermitsPruneType(bare, typ) {
			t.Errorf("a bare 0x81 entry conferred %s", typ)
		}
	}

	named := profileEntry([]byte{0x02, 0x81}, []string{wire.PruneSoft, wire.PruneHard})
	if !authority.PermitsPruneType(named, wire.PruneHard) {
		t.Error("a named hard_prune was not conferred")
	}
	if authority.PermitsPruneType(named, wire.PruneExt) {
		t.Error("prune_ext was conferred without being named")
	}

	// No 0x81 at all confers nothing, whatever the types say.
	none := profileEntry([]byte{0x01}, []string{wire.PruneHard})
	for _, typ := range wire.PruneTypes {
		if authority.PermitsPruneType(none, typ) {
			t.Errorf("a role without 0x81 conferred %s", typ)
		}
	}
}

// ── the control chain ───────────────────────────────────────────────────────

func payloadWithLink(typ, link string) *authority.ControlPayload {
	granter := ""
	if typ == wire.CtlGrant {
		granter = `"granter":"root",`
	}
	body := `{"type":"` + typ + `",` + granter + `"prev_control_hash":"` + link + `","cert_b64":"QUJD","cert_sig_b64":"` + b(64, 7) + `"}`
	p, r := authority.ParseControlPayload([]byte(body))
	if r != nil {
		panic(r.Code)
	}
	return p
}

// An all-zero link is genesis-only, in both directions.
func TestZeroLinkIsGenesisOnly(t *testing.T) {
	var tip [32]byte
	raw, _ := hex.DecodeString(someLink)
	copy(tip[:], raw)

	if r := authority.CheckLink(payloadWithLink(wire.CtlWorkspaceGenesis, zeroLink), tip, false); r != nil {
		t.Errorf("a genesis with a zero link was refused: %s", r.Code)
	}
	if r := authority.CheckLink(payloadWithLink(wire.CtlWorkspaceGenesis, someLink), tip, false); r == nil {
		t.Error("a genesis carrying a link was accepted")
	}
	if r := authority.CheckLink(payloadWithLink(wire.CtlMemberRegister, zeroLink), tip, true); r == nil {
		t.Error("a non-genesis with a zero link was accepted")
	}
}

// A device served a truncated history detects it by this rule, even when its own
// view is empty.
func TestZeroLinkRefusedEvenWithNoTip(t *testing.T) {
	r := authority.CheckLink(payloadWithLink(wire.CtlMemberRegister, zeroLink), [32]byte{}, false)
	wantRefusal(t, r, codes.ControlChainBreak)
	if _, ok := r.Fields["expected_prev_control_hash"]; ok {
		t.Error("the refusal named an expected link where there is none")
	}
}

// The link the op should have named is carried, for the device that cannot read.
func TestChainBreakCarriesTheTip(t *testing.T) {
	var tip [32]byte
	raw, _ := hex.DecodeString(someLink)
	copy(tip[:], raw)

	if r := authority.CheckLink(payloadWithLink(wire.CtlGrant, someLink), tip, true); r != nil {
		t.Fatalf("a correct link was refused: %s", r.Code)
	}
	wrong := strings.Repeat("ab", 32)
	r := authority.CheckLink(payloadWithLink(wire.CtlGrant, wrong), tip, true)
	wantRefusal(t, r, codes.ControlChainBreak)
	if r.Fields["expected_prev_control_hash"] != someLink {
		t.Errorf("expected_prev_control_hash = %v", r.Fields["expected_prev_control_hash"])
	}
}

// A genesis has no predecessor, so there is no expected link to report.
func TestGenesisBreakCarriesNothing(t *testing.T) {
	r := authority.CheckLink(payloadWithLink(wire.CtlWorkspaceGenesis, someLink), [32]byte{}, false)
	wantRefusal(t, r, codes.ControlChainBreak)
	if len(r.Fields) != 0 {
		t.Errorf("fields = %v", r.Fields)
	}
}

// The tip is bare SHA-256 over the previous control op's payload bytes.
func TestTipIsThePayloadHash(t *testing.T) {
	payload := []byte(vectors.ControlPayload)
	if authority.Tip(payload) != wire.PayloadHash(payload) {
		t.Error("the tip is not the payload hash")
	}
}

func profileEntry(classes []byte, pruneTypes []string) profile.RoleEntry {
	return profile.RoleEntry{Classes: classes, PruneTypes: pruneTypes}
}
