package authority_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/loonybin/roundelay/authority"
	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/internal/memstore"
	"github.com/loonybin/roundelay/internal/testprofile"
	"github.com/loonybin/roundelay/internal/vectors"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/wire"
)

// A whole Workspace, driven through the real pipeline against the real
// Authority. Nothing here is a double.
type world struct {
	t     *testing.T
	prof  *profile.Profile
	store *memstore.Store
	pipe  *oplog.Pipeline
	ws    [16]byte
	ns    wire.Namespace
	seq   map[[16]byte]uint64

	// pending is the tip an op built earlier in the batch under construction
	// established. Within a batch the tip advances as the batch walks, so a
	// second control op must link the first — and the store cannot say so,
	// because nothing has committed yet.
	pending string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	p := testprofile.Minimal()
	// The fixture Workspace is whatever the founding Root says it is; the
	// profile's own creation arithmetic is its business, not the core's.
	p.Creation = profile.CreationExplicit
	p.Creatable = func(root [32]byte, ws [16]byte) bool { return ws == vectors.WorkspaceID }
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	st := memstore.New()
	ns, _ := wire.NewNamespace(vectors.Namespace)
	return &world{
		t: t, prof: p, store: st, ws: vectors.WorkspaceID, ns: ns,
		seq:  map[[16]byte]uint64{},
		pipe: &oplog.Pipeline{Profile: p, Store: st, Authority: authority.New(p)},
	}
}

func (w *world) post(device [16]byte, ops ...string) ([]oplog.Result, *oplog.Refusal) {
	w.t.Helper()
	defer w.resync()
	return w.pipe.Append(context.Background(), w.ws, device, ops)
}

// device is a member's three keys, derived from one label.
type device struct {
	id      [16]byte
	label   string
	control ed25519.PrivateKey
	content ed25519.PrivateKey
}

func newDevice(label string) device {
	return device{
		id:      vectors.Bytes16("device/" + label),
		label:   label,
		control: vectors.SignPriv(label + "/control"),
		content: vectors.SignPriv(label + "/content"),
	}
}

func (d device) controlPub() [32]byte { return to32(d.control.Public().(ed25519.PublicKey)) }
func (d device) contentPub() [32]byte { return to32(d.content.Public().(ed25519.PublicKey)) }
func (d device) kexPub() [32]byte     { return to32(vectors.KexPub(d.label + "/kex")) }

func to32(b []byte) [32]byte {
	var out [32]byte
	copy(out[:], b)
	return out
}

func (w *world) next(d device) uint64 {
	w.seq[d.id]++
	return w.seq[d.id]
}

// controlOp wraps a payload in a signed 0x80 envelope.
func (w *world) controlOp(d device, payload map[string]any) string {
	w.t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		w.t.Fatal(err)
	}
	seq := w.next(d)
	h := wire.Header{
		OpClass:        wire.ClassControl,
		Suite:          wire.SuiteNone,
		WorkspaceID:    w.ws,
		OpID:           vectors.Bytes16(fmt.Sprintf("op/%x/%d", d.id[:4], seq)),
		AuthorMemberID: d.id,
		AuthorKeyID:    wire.KeyID(d.control.Public().(ed25519.PublicKey)),
		AuthorSeq:      seq,
	}
	if seq > 1 {
		h.PrevAuthorHash = vectors.PrevHash(fmt.Sprint(seq))
	}
	body, err := w.prof.SizeClasses.PackBody(raw)
	if err != nil {
		w.t.Fatal(err)
	}
	env, err := wire.SignOp(d.control, w.ns.V1(wire.DocOp), h.Marshal(), body)
	if err != nil {
		w.t.Fatal(err)
	}
	w.pending = hexOf(wire.PayloadHash(raw))
	return b64.EncodeToString(env)
}

// resync drops the in-flight tip, so the next op builds against what has
// actually committed. A test that builds an op and does not post it needs this;
// post does it for everything else.
func (w *world) resync() { w.pending = "" }

func (w *world) contentOp(d device) string {
	w.t.Helper()
	seq := w.next(d)
	h := wire.Header{
		OpClass:        wire.ClassContent,
		Suite:          wire.SuiteNone,
		WorkspaceID:    w.ws,
		OpID:           vectors.Bytes16(fmt.Sprintf("op/%x/%d", d.id[:4], seq)),
		AuthorMemberID: d.id,
		AuthorKeyID:    wire.KeyID(d.content.Public().(ed25519.PublicKey)),
		AuthorSeq:      seq,
		PrevAuthorHash: vectors.PrevHash(fmt.Sprint(seq)),
	}
	body, _ := w.prof.SizeClasses.PackBody([]byte("hello"))
	env, err := wire.SignOp(d.content, w.ns.V1(wire.DocOp), h.Marshal(), body)
	if err != nil {
		w.t.Fatal(err)
	}
	return b64.EncodeToString(env)
}

// tip is the control chain link the next control op must name.
func (w *world) tip() string {
	w.t.Helper()
	if w.pending != "" {
		return w.pending
	}
	ops := w.store.Ops(w.ws)
	for i := len(ops) - 1; i >= 0; i-- {
		if ops[i].Class != wire.ClassControl {
			continue
		}
		env, err := wire.ParseEnvelope(ops[i].Envelope)
		if err != nil {
			w.t.Fatal(err)
		}
		payload, err := w.prof.SizeClasses.UnpackBody(env.Body)
		if err != nil {
			w.t.Fatal(err)
		}
		h := wire.PayloadHash(payload)
		return hexOf(h)
	}
	return zeroLink
}

func hexOf(h [32]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range h {
		out[2*i], out[2*i+1] = digits[b>>4], digits[b&0xf]
	}
	return string(out)
}

// signCert produces the detached certificate signature.
func (w *world) signCert(key ed25519.PrivateKey, doc string, cert []byte) string {
	return b64.EncodeToString(ed25519.Sign(key, w.ns.CertSigningInput(doc, cert)))
}

func (w *world) registrationBody(d device) map[string]any {
	c, n, k := d.controlPub(), d.contentPub(), d.kexPub()
	cid, nid, kid := wire.KeyID(c[:]), wire.KeyID(n[:]), wire.KeyID(k[:])
	return map[string]any{
		"member_id":         vectors.UUID(d.id),
		"member_kind":       "device",
		"holder_ref":        b64.EncodeToString(make([]byte, 32)),
		"control_pk":        b64.EncodeToString(c[:]),
		"control_key_id":    b64.EncodeToString(cid[:]),
		"content_pk":        b64.EncodeToString(n[:]),
		"content_key_id":    b64.EncodeToString(nid[:]),
		"kex_pk":            b64.EncodeToString(k[:]),
		"kex_key_id":        b64.EncodeToString(kid[:]),
		"registered_at_hlc": []any{1700000000000, 0, "00000000000000000000000000000000"},
	}
}

// genesis builds the founding op: the Workspace, and its founder's own
// registration, which nothing earlier in the log could introduce.
func (w *world) genesis(root ed25519.PrivateKey, founder device) string {
	w.t.Helper()
	rootPK := to32(root.Public().(ed25519.PublicKey))
	cert, _ := json.Marshal(map[string]any{
		"workspace_id":   vectors.UUID(w.ws),
		"root_pk":        b64.EncodeToString(rootPK[:]),
		"founder":        w.registrationBody(founder),
		"created_at_hlc": []any{1700000000000, 0, "00000000000000000000000000000000"},
	})
	return w.controlOp(founder, map[string]any{
		"type":              wire.CtlWorkspaceGenesis,
		"prev_control_hash": zeroLink,
		"cert_b64":          b64.EncodeToString(cert),
		"cert_sig_b64":      w.signCert(root, wire.DocWorkspaceGenesis, cert),
	})
}

func (w *world) register(signer ed25519.PrivateKey, d device) string {
	w.t.Helper()
	body := w.registrationBody(d)
	body["workspace_id"] = vectors.UUID(w.ws)
	cert, _ := json.Marshal(body)
	return w.controlOp(d, map[string]any{
		"type":              wire.CtlMemberRegister,
		"prev_control_hash": w.tip(),
		"cert_b64":          b64.EncodeToString(cert),
		"cert_sig_b64":      w.signCert(signer, wire.DocMemberRegister, cert),
	})
}

func (w *world) grant(signer ed25519.PrivateKey, poster device, granter authority.Principal, grantee device, role, id string) string {
	w.t.Helper()
	who := "root"
	if !granter.Root {
		who = vectors.UUID(granter.Member)
	}
	cert, _ := json.Marshal(map[string]any{
		"workspace_id":   vectors.UUID(w.ws),
		"grant_id":       id,
		"member_id":      vectors.UUID(grantee.id),
		"role":           role,
		"granter":        who,
		"granted_at_hlc": []any{1700000000000, 0, "00000000000000000000000000000000"},
	})
	return w.controlOp(poster, map[string]any{
		"type":              wire.CtlGrant,
		"prev_control_hash": w.tip(),
		"granter":           who,
		"cert_b64":          b64.EncodeToString(cert),
		"cert_sig_b64":      w.signCert(signer, wire.DocGrant, cert),
	})
}

func (w *world) revoke(signer ed25519.PrivateKey, poster device, revoker authority.Principal, grantID, revokeID string) string {
	w.t.Helper()
	who := "root"
	if !revoker.Root {
		who = vectors.UUID(revoker.Member)
	}
	cert, _ := json.Marshal(map[string]any{
		"workspace_id":   vectors.UUID(w.ws),
		"revoke_id":      revokeID,
		"grant_id":       grantID,
		"revoker":        who,
		"revoked_at_hlc": []any{1700000000000, 0, "00000000000000000000000000000000"},
	})
	return w.controlOp(poster, map[string]any{
		"type":              wire.CtlRevoke,
		"prev_control_hash": w.tip(),
		"revoker":           who,
		"cert_b64":          b64.EncodeToString(cert),
		"cert_sig_b64":      w.signCert(signer, wire.DocRevoke, cert),
	})
}

func rootKey() ed25519.PrivateKey { return vectors.SignPriv("ceremony/root") }

func mustPost(t *testing.T, w *world, d device, ops ...string) []oplog.Result {
	t.Helper()
	res, r := w.post(d.id, ops...)
	if r != nil {
		t.Fatalf("post refused: %s %v", r.Code, r.Fields)
	}
	return res
}

// ── the ceremony ────────────────────────────────────────────────────────────

// A brand-new device posts its whole enrolment as one request: the genesis that
// creates the Workspace and registers its founder, the Root-signed self-grant
// that gives it authority, and a content op the grant authorises.
func TestFoundingBatch(t *testing.T) {
	w := newWorld(t)
	root := rootKey()
	alice := newDevice("alice")

	res := mustPost(t, w, alice,
		w.genesis(root, alice),
		w.grant(root, alice, authority.Principal{Root: true}, alice, "owner", uuidA),
		w.contentOp(alice),
	)
	if len(res) != 3 || res[2].Seq != 3 {
		t.Fatalf("results = %+v", res)
	}

	if pk, ok := w.store.Root(w.ws); !ok || pk != to32(root.Public().(ed25519.PublicKey)) {
		t.Error("the genesis did not install its own Root")
	}
	grants := w.store.Grants(w.ws)
	if len(grants) != 1 || grants[0].Role != "owner" || grants[0].Start != 2 {
		t.Fatalf("grants = %+v", grants)
	}
}

// The content op at index 2 is authorised by the grant at index 1, which is what
// "the effects of earlier ops in the same batch are visible to later ones" buys.
func TestGrantAuthorisesLaterOpInTheSameBatch(t *testing.T) {
	w := newWorld(t)
	root := rootKey()
	alice := newDevice("alice")

	// Without the grant, the content op has no live grant to stand on.
	_, r := w.post(alice.id, w.genesis(root, alice), w.contentOp(alice))
	wantRefusal(t, r, codes.NoLiveGrant)
}

// A second genesis is not a fork for the server to resolve.
func TestGenesisIsOnce(t *testing.T) {
	w := newWorld(t)
	root := rootKey()
	alice := newDevice("alice")
	mustPost(t, w, alice, w.genesis(root, alice))

	bob := newDevice("bob")
	_, r := w.post(bob.id, w.genesis(root, bob))
	wantRefusal(t, r, codes.GenesisNotFirst)
}

// A Root that may not found the id it names is workspace_not_reachable, and a
// genesis raises no cert_root_pk_mismatch: the op carries exactly one root_pk.
func TestGenesisReachability(t *testing.T) {
	w := newWorld(t)
	w.prof.Creatable = func([32]byte, [16]byte) bool { return false }
	_, r := w.post(newDevice("alice").id, w.genesis(rootKey(), newDevice("alice")))
	wantRefusal(t, r, codes.WorkspaceNotReachable)
}

// A joining device's registration is its own first op, exempt from the access
// gate and not from the chain.
func TestJoiningDevice(t *testing.T) {
	w := newWorld(t)
	root := rootKey()
	alice := newDevice("alice")
	mustPost(t, w, alice,
		w.genesis(root, alice),
		w.grant(root, alice, authority.Principal{Root: true}, alice, "owner", uuidA))

	bob := newDevice("bob")
	mustPost(t, w, bob, w.register(root, bob))

	// Registered, but holding no grant: not revoked, and still unable to write.
	_, r := w.post(bob.id, w.contentOp(bob))
	wantRefusal(t, r, codes.NoLiveGrant)
	if _, had := r.Fields["revoked"]; had {
		t.Error("a device with zero grants was reported as revoked")
	}

	// An owner grants it participant, and now it can. The refused content op
	// above consumed a sequence number in the fixture and not in the log.
	w.seq[bob.id] = 1
	mustPost(t, w, alice, w.grant(alice.control, alice,
		authority.Principal{Member: alice.id}, bob, "participant", uuidB))
	mustPost(t, w, bob, w.contentOp(bob))
}

// Rule 3: an owner grant may only be created with granter = root.
func TestOwnerGrantRequiresRoot(t *testing.T) {
	w := newWorld(t)
	root := rootKey()
	alice, bob := newDevice("alice"), newDevice("bob")
	mustPost(t, w, alice,
		w.genesis(root, alice),
		w.grant(root, alice, authority.Principal{Root: true}, alice, "owner", uuidA))
	mustPost(t, w, bob, w.register(root, bob))

	_, r := w.post(alice.id, w.grant(alice.control, alice,
		authority.Principal{Member: alice.id}, bob, "owner", uuidB))
	wantRefusal(t, r, codes.OwnerGrantRequiresRoot)
}

// Rule 2 sits above every type sequence: a 0x80 op that is not Root-signed
// requires owner and no other role. A participant posting a control op is
// answered about the class, never about what the payload said.
func TestControlOpsRequireOwner(t *testing.T) {
	w := newWorld(t)
	root := rootKey()
	alice, bob := newDevice("alice"), newDevice("bob")
	mustPost(t, w, alice,
		w.genesis(root, alice),
		w.grant(root, alice, authority.Principal{Root: true}, alice, "owner", uuidA))
	mustPost(t, w, bob, w.register(root, bob))
	mustPost(t, w, alice, w.grant(alice.control, alice,
		authority.Principal{Member: alice.id}, bob, "participant", uuidB))

	carol := newDevice("carol")
	_, r := w.post(bob.id, w.grant(alice.control, bob,
		authority.Principal{Member: alice.id}, carol, "participant", uuidC))
	wantRefusal(t, r, codes.RoleForbidsOpClass)
	if r.Fields["op_class"] != int(wire.ClassControl) {
		t.Errorf("op_class = %v", r.Fields["op_class"])
	}
}

// Authority does not travel by courier: a device that may write control ops
// still cannot post a grant claiming some other device approved it.
func TestGranterMustBeThePoster(t *testing.T) {
	w := newWorld(t)
	root := rootKey()
	alice, bob := newDevice("alice"), newDevice("bob")
	mustPost(t, w, alice,
		w.genesis(root, alice),
		w.grant(root, alice, authority.Principal{Root: true}, alice, "owner", uuidA))
	mustPost(t, w, bob, w.register(root, bob))
	// Both are owners, so both may write control ops and rule 2 is satisfied.
	mustPost(t, w, alice, w.grant(root, alice, authority.Principal{Root: true}, bob, "owner", uuidB))

	carol := newDevice("carol")
	mustPost(t, w, carol, w.register(root, carol))
	_, r := w.post(bob.id, w.grant(alice.control, bob,
		authority.Principal{Member: alice.id}, carol, "participant", uuidC))
	wantRefusal(t, r, codes.CertGranterMismatch)
}

// A grant is never held as a dangling forward reference.
func TestUnknownGrantee(t *testing.T) {
	w := newWorld(t)
	root := rootKey()
	alice := newDevice("alice")
	mustPost(t, w, alice,
		w.genesis(root, alice),
		w.grant(root, alice, authority.Principal{Root: true}, alice, "owner", uuidA))

	stranger := newDevice("stranger")
	_, r := w.post(alice.id, w.grant(root, alice, authority.Principal{Root: true}, stranger, "participant", uuidB))
	wantRefusal(t, r, codes.UnknownGrantee)
}

// The verdict is positional, and revoking closes the window at the revoke's own
// position rather than retroactively.
func TestRevocationIsPositional(t *testing.T) {
	w := newWorld(t)
	root := rootKey()
	alice, bob := newDevice("alice"), newDevice("bob")
	mustPost(t, w, alice,
		w.genesis(root, alice),
		w.grant(root, alice, authority.Principal{Root: true}, alice, "owner", uuidA))
	mustPost(t, w, bob, w.register(root, bob))
	mustPost(t, w, alice, w.grant(alice.control, alice,
		authority.Principal{Member: alice.id}, bob, "participant", uuidB))
	mustPost(t, w, bob, w.contentOp(bob))

	mustPost(t, w, alice, w.revoke(alice.control, alice,
		authority.Principal{Member: alice.id}, uuidB, uuidC))

	// The op bob already wrote stays legitimate where it landed; the next one
	// does not.
	_, r := w.post(bob.id, w.contentOp(bob))
	wantRefusal(t, r, codes.NoLiveGrant)
	if r.Fields["revoked"] != true {
		t.Errorf("a revoked device was not reported as revoked: %v", r.Fields)
	}

	// Losing the last live grant ends the device's sessions here.
	ended := w.store.SessionsEnded(w.ws)
	if len(ended) != 1 || ended[0] != bob.id {
		t.Errorf("the cascade did not run: %v", ended)
	}

	// A revoke closes grants, never the registration: bob still passes the access
	// gate, which is why no_registration and no_live_grant are different codes.
	if r.Code == codes.NoRegistration {
		t.Error("a revoked device lost its registration")
	}

	// The boundary is immutable.
	_, r = w.post(alice.id, w.revoke(alice.control, alice,
		authority.Principal{Member: alice.id}, uuidB, uuidD))
	wantRefusal(t, r, codes.AlreadyRevoked)
}

// Revocation is grant-granular and does not cascade: revoking the granter leaves
// the grants it issued live.
func TestRevocationDoesNotCascade(t *testing.T) {
	w := newWorld(t)
	root := rootKey()
	alice, bob := newDevice("alice"), newDevice("bob")
	mustPost(t, w, alice,
		w.genesis(root, alice),
		w.grant(root, alice, authority.Principal{Root: true}, alice, "owner", uuidA))
	mustPost(t, w, bob, w.register(root, bob))
	mustPost(t, w, alice, w.grant(alice.control, alice,
		authority.Principal{Member: alice.id}, bob, "participant", uuidB))

	// Root revokes alice's owner grant — rule 3 at the other end.
	mustPost(t, w, alice, w.revoke(root, alice, authority.Principal{Root: true}, uuidA, uuidC))

	// bob's grant is unaffected.
	mustPost(t, w, bob, w.contentOp(bob))
}

// The control chain is one chain per Workspace across all authors, and the loser
// of a race named a tip that has moved.
func TestControlChainAcrossAuthors(t *testing.T) {
	w := newWorld(t)
	root := rootKey()
	alice, bob := newDevice("alice"), newDevice("bob")
	mustPost(t, w, alice,
		w.genesis(root, alice),
		w.grant(root, alice, authority.Principal{Root: true}, alice, "owner", uuidA))

	// bob builds against the current tip, alice lands something first, and bob's
	// link no longer names it.
	stale := w.register(root, bob)
	w.resync() // carol builds against what committed, not against bob's unposted op
	carol := newDevice("carol")
	mustPost(t, w, carol, w.register(root, carol))

	_, r := w.post(bob.id, stale)
	wantRefusal(t, r, codes.ControlChainBreak)
	if r.Fields["expected_prev_control_hash"] != w.tip() {
		t.Errorf("expected_prev_control_hash = %v, want %s", r.Fields["expected_prev_control_hash"], w.tip())
	}
}

const (
	uuidC = "22222222-3333-4444-5555-666666666666"
	uuidD = "33333333-4444-5555-6666-777777777777"
)
