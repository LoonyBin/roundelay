package httpapi_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/loonybin/roundelay/authority"
	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/httpapi"
	"github.com/loonybin/roundelay/identity"
	"github.com/loonybin/roundelay/internal/memstore"
	"github.com/loonybin/roundelay/internal/testprofile"
	"github.com/loonybin/roundelay/internal/vectors"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/wire"
)

// idWorld is a server with the whole credential path wired: no fakeAuth in it.
type idWorld struct {
	t     *testing.T
	rt    http.Handler
	prof  *profile.Profile
	log   *memstore.Store
	ids   *memstore.Identity
	toks  *identity.Tokens
	ns    wire.Namespace
	ws    [16]byte
	clock time.Time
}

func newIDWorld(t *testing.T) *idWorld {
	t.Helper()
	p := testprofile.Minimal()
	p.Creation = profile.CreationExplicit
	p.Creatable = func(_ [32]byte, ws [16]byte) bool { return ws == vectors.WorkspaceID }
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	log := memstore.New()
	ids := memstore.NewIdentity(log)
	log.OnSessionsEnded(func(m [16]byte) { _ = ids.RevokeRefreshFor(t.Context(), m) })

	w := &idWorld{t: t, prof: p, log: log, ids: ids, ws: vectors.WorkspaceID, clock: time.Unix(1700000000, 0)}
	w.ns, _ = wire.NewNamespace(vectors.Namespace)
	w.toks = &identity.Tokens{
		Secret:     make([]byte, 32),
		AccessTTL:  p.Limits.AccessTokenLifetime,
		RefreshTTL: p.Limits.RefreshTokenLifetime,
		Now:        func() time.Time { return w.clock },
	}
	copy(w.toks.Secret, "a server secret nobody else holds")
	if err := w.toks.Validate(); err != nil {
		t.Fatal(err)
	}

	ih := &httpapi.IdentityHandler{
		Registrar: &identity.Registrar{
			Profile: p, Store: ids, Lookup: memstore.Lookup{Log: log}, Admission: identity.AdmitAll{},
		},
		Sessions: &identity.Sessions{Profile: p, Store: ids, Tokens: w.toks},
	}
	rd := &httpapi.ReadHandler{
		Auth: httpapi.TokenAuth{Tokens: w.toks}, Store: log, Profile: p, Authority: authority.New(p),
	}
	ops := &httpapi.OpsHandler{
		Auth:     httpapi.TokenAuth{Tokens: w.toks},
		Pipeline: &oplog.Pipeline{Profile: p, Store: log, Authority: authority.New(p)},
	}

	router := httpapi.NewRouter(httpapi.NewHealth(p, okProbe))
	v1 := http.NewServeMux()
	v1.HandleFunc("POST /members", ih.ServeRegister)
	v1.HandleFunc("POST /members/{member_id}/challenge", ih.ServeChallenge)
	v1.HandleFunc("POST /members/{member_id}/token", ih.ServeToken)
	v1.HandleFunc("POST /members/{member_id}/token/refresh", ih.ServeRefresh)
	v1.HandleFunc("GET /w/{workspace_id}/ops", rd.ServeOps)
	v1.Handle("POST /w/{workspace_id}/ops", ops)
	v1.HandleFunc("/", httpapi.NotFound)
	router.Contract("v1", v1)
	w.rt = router
	return w
}

func (w *idWorld) call(method, path, token, body string) (int, map[string]any) {
	w.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	w.rt.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			w.t.Fatalf("%s %s: %v\n%s", method, path, err, rec.Body.String())
		}
	}
	return rec.Code, out
}

// idDevice is a member with its three keys.
type idDevice struct {
	id      [16]byte
	control ed25519.PrivateKey
	content ed25519.PrivateKey
	kex     [32]byte
}

func newIDDevice(label string) idDevice {
	return idDevice{
		id:      vectors.Bytes16("id/" + label),
		control: vectors.SignPriv(label + "/control"),
		content: vectors.SignPriv(label + "/content"),
		kex:     to32(vectors.KexPub(label + "/kex")),
	}
}

func (d idDevice) controlPK() [32]byte { return to32(d.control.Public().(ed25519.PublicKey)) }
func (d idDevice) contentPK() [32]byte { return to32(d.content.Public().(ed25519.PublicKey)) }

func (w *idWorld) genesisCert(root ed25519.PrivateKey, d idDevice) (string, string) {
	w.t.Helper()
	rootPK := to32(root.Public().(ed25519.PublicKey))
	c, n, k := d.controlPK(), d.contentPK(), d.kex
	cid, nid, kid := wire.KeyID(c[:]), wire.KeyID(n[:]), wire.KeyID(k[:])
	cert, _ := json.Marshal(map[string]any{
		"workspace_id": vectors.UUID(w.ws),
		"root_pk":      base64.StdEncoding.EncodeToString(rootPK[:]),
		"founder": map[string]any{
			"member_id": vectors.UUID(d.id), "member_kind": "device",
			"holder_ref":     base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"control_pk":     base64.StdEncoding.EncodeToString(c[:]),
			"control_key_id": base64.StdEncoding.EncodeToString(cid[:]),
			"content_pk":     base64.StdEncoding.EncodeToString(n[:]),
			"content_key_id": base64.StdEncoding.EncodeToString(nid[:]),
			"kex_pk":         base64.StdEncoding.EncodeToString(k[:]),
			"kex_key_id":     base64.StdEncoding.EncodeToString(kid[:]),
			"registered_at_hlc": []any{1700000000000, 0,
				"00000000000000000000000000000000"},
		},
		"created_at_hlc": []any{1700000000000, 0, "00000000000000000000000000000000"},
	})
	sig := ed25519.Sign(root, w.ns.CertSigningInput(wire.DocWorkspaceGenesis, cert))
	return base64.StdEncoding.EncodeToString(cert), base64.StdEncoding.EncodeToString(sig)
}

func (w *idWorld) registerBody(d idDevice, cert, sig string, root ed25519.PrivateKey, withIDs bool) string {
	c, n, k := d.controlPK(), d.contentPK(), d.kex
	rootPK := to32(root.Public().(ed25519.PublicKey))
	body := map[string]any{
		"member_id":    vectors.UUID(d.id),
		"control_pk":   base64.StdEncoding.EncodeToString(c[:]),
		"content_pk":   base64.StdEncoding.EncodeToString(n[:]),
		"kex_pk":       base64.StdEncoding.EncodeToString(k[:]),
		"cert_b64":     cert,
		"cert_sig_b64": sig,
		"root_pk_b64":  base64.StdEncoding.EncodeToString(rootPK[:]),
	}
	if withIDs {
		cid, nid, kid := wire.KeyID(c[:]), wire.KeyID(n[:]), wire.KeyID(k[:])
		body["key_ids"] = map[string]any{
			"control_key_id": base64.StdEncoding.EncodeToString(cid[:]),
			"content_key_id": base64.StdEncoding.EncodeToString(nid[:]),
			"kex_key_id":     base64.StdEncoding.EncodeToString(kid[:]),
		}
	}
	raw, _ := json.Marshal(body)
	return string(raw)
}

// login walks the three steps a device takes to get a credential.
func (w *idWorld) login(d idDevice) (access, refresh string) {
	w.t.Helper()
	path := "/v1/members/" + vectors.UUID(d.id)
	status, body := w.call("POST", path+"/challenge", "", "")
	if status != http.StatusOK {
		w.t.Fatalf("challenge: %d %v", status, body)
	}
	nonce, err := base64.StdEncoding.DecodeString(body["nonce"].(string))
	if err != nil {
		w.t.Fatal(err)
	}
	sig := ed25519.Sign(d.control, w.ns.AuthChallengeInput(d.id, nonce))
	req, _ := json.Marshal(map[string]any{
		"nonce":     base64.StdEncoding.EncodeToString(nonce),
		"signature": base64.StdEncoding.EncodeToString(sig),
	})
	status, body = w.call("POST", path+"/token", "", string(req))
	if status != http.StatusOK {
		w.t.Fatalf("token: %d %v", status, body)
	}
	if body["token_type"] != "bearer" {
		w.t.Errorf("token_type = %v", body["token_type"])
	}
	return body["access_token"].(string), body["refresh_token"].(string)
}

// ── the whole path ──────────────────────────────────────────────────────────

// Founding is register, then genesis, then vault. This is the first two, with a
// real token in between.
func TestRegisterThenLogInThenWrite(t *testing.T) {
	w := newIDWorld(t)
	root := vectors.SignPriv("identity/root")
	alice := newIDDevice("alice")
	cert, sig := w.genesisCert(root, alice)

	status, body := w.call("POST", "/v1/members", "", w.registerBody(alice, cert, sig, root, true))
	if status != http.StatusCreated {
		t.Fatalf("register: %d %v", status, body)
	}
	// A shell confers nothing: chained is false until the log says otherwise.
	if body["chained"] != false {
		t.Errorf("chained = %v on a fresh shell", body["chained"])
	}
	// Key ids are the server's derivations.
	kid := body["key_ids"].(map[string]any)
	ctrlPK := alice.controlPK()
	want := wire.KeyID(ctrlPK[:])
	if kid["control_key_id"] != base64.StdEncoding.EncodeToString(want[:]) {
		t.Error("control_key_id is not the derivation")
	}

	// An identical repeat answers 200 with the same body.
	status, _ = w.call("POST", "/v1/members", "", w.registerBody(alice, cert, sig, root, true))
	if status != http.StatusOK {
		t.Errorf("identical repeat: %d, want 200", status)
	}

	// The device can now obtain a credential from its own key alone.
	access, refresh := w.login(alice)
	if access == "" || refresh == "" {
		t.Fatal("empty credentials")
	}

	// And the token is a real one: it names the device, and a read accepts it.
	status, body = w.call("GET", "/v1/w/"+vectors.UUID(w.ws)+"/ops", access, "")
	if status != http.StatusOK {
		t.Fatalf("read with a real token: %d %v", status, body)
	}
}

// Root is required to introduce a device and never to operate one, which is why
// a device keeps working for years after the ceremony that created it.
func TestLoginNeedsOnlyTheDeviceKey(t *testing.T) {
	w := newIDWorld(t)
	root := vectors.SignPriv("identity/root")
	alice := newIDDevice("alice")
	cert, sig := w.genesisCert(root, alice)
	if status, _ := w.call("POST", "/v1/members", "", w.registerBody(alice, cert, sig, root, false)); status != http.StatusCreated {
		t.Fatal(status)
	}

	// A signature by the content key is not the credential: the challenge is
	// signed by the control key.
	path := "/v1/members/" + vectors.UUID(alice.id)
	_, body := w.call("POST", path+"/challenge", "", "")
	nonce, _ := base64.StdEncoding.DecodeString(body["nonce"].(string))
	wrong := ed25519.Sign(alice.content, w.ns.AuthChallengeInput(alice.id, nonce))
	req, _ := json.Marshal(map[string]any{
		"nonce":     base64.StdEncoding.EncodeToString(nonce),
		"signature": base64.StdEncoding.EncodeToString(wrong),
	})
	status, body := w.call("POST", path+"/token", "", string(req))
	if status != http.StatusUnauthorized || refusalCode(t, body) != string(codes.BadMemberChallenge) {
		t.Errorf("content-key signature: %d %v", status, body)
	}
}

// The challenge is spent by the attempt, win or lose — and spent before either
// field is decoded, so an unparseable request cannot be the one shape that
// leaves the nonce alive to try again.
func TestChallengeIsSpentByTheAttempt(t *testing.T) {
	w := newIDWorld(t)
	root := vectors.SignPriv("identity/root")
	alice := newIDDevice("alice")
	cert, sig := w.genesisCert(root, alice)
	w.call("POST", "/v1/members", "", w.registerBody(alice, cert, sig, root, false))
	path := "/v1/members/" + vectors.UUID(alice.id)

	// A losing guess spends it.
	_, body := w.call("POST", path+"/challenge", "", "")
	nonce, _ := base64.StdEncoding.DecodeString(body["nonce"].(string))
	guess, _ := json.Marshal(map[string]any{
		"nonce":     base64.StdEncoding.EncodeToString(nonce),
		"signature": base64.StdEncoding.EncodeToString(make([]byte, 64)),
	})
	if status, _ := w.call("POST", path+"/token", "", string(guess)); status != http.StatusUnauthorized {
		t.Fatalf("a bad signature answered %d", status)
	}
	// The same nonce, now correctly signed, no longer works.
	good, _ := json.Marshal(map[string]any{
		"nonce":     base64.StdEncoding.EncodeToString(nonce),
		"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(alice.control, w.ns.AuthChallengeInput(alice.id, nonce))),
	})
	if status, _ := w.call("POST", path+"/token", "", string(good)); status != http.StatusUnauthorized {
		t.Error("a spent nonce was reusable; a guessing loop needs no fresh round trip")
	}

	// An unparseable body spends it too.
	_, body = w.call("POST", path+"/challenge", "", "")
	nonce, _ = base64.StdEncoding.DecodeString(body["nonce"].(string))
	status, body := w.call("POST", path+"/token", "", `{"nonce":"!!!not base64!!!","signature":"!!!"}`)
	if status != http.StatusUnprocessableEntity || refusalCode(t, body) != string(codes.BadMemberChallenge) {
		t.Errorf("undecodable body: %d %v", status, body)
	}
	good, _ = json.Marshal(map[string]any{
		"nonce":     base64.StdEncoding.EncodeToString(nonce),
		"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(alice.control, w.ns.AuthChallengeInput(alice.id, nonce))),
	})
	if status, _ := w.call("POST", path+"/token", "", string(good)); status != http.StatusUnauthorized {
		t.Error("an undecodable attempt left the nonce alive")
	}
}

// The existence check runs first, so sweeping through invented ids creates no
// counters.
func TestChallengeForAnUnknownDevice(t *testing.T) {
	w := newIDWorld(t)
	status, body := w.call("POST", "/v1/members/"+vectors.UUID(vectors.MemberB)+"/challenge", "", "")
	if status != http.StatusNotFound || refusalCode(t, body) != string(codes.UnknownMember) {
		t.Errorf("%d %v", status, body)
	}
}

// Fixed-window, and retry_after_seconds is the remaining lifetime of the current
// window.
func TestChallengeRateLimit(t *testing.T) {
	w := newIDWorld(t)
	w.prof.Limits.ChallengesPerWindow = 2
	w.prof.Limits.ChallengeWindow = 60 * time.Second

	root := vectors.SignPriv("identity/root")
	alice := newIDDevice("alice")
	cert, sig := w.genesisCert(root, alice)
	w.call("POST", "/v1/members", "", w.registerBody(alice, cert, sig, root, false))
	path := "/v1/members/" + vectors.UUID(alice.id) + "/challenge"

	for i := range 2 {
		if status, _ := w.call("POST", path, "", ""); status != http.StatusOK {
			t.Fatalf("request %d: %d", i, status)
		}
	}
	status, body := w.call("POST", path, "", "")
	if status != http.StatusTooManyRequests || refusalCode(t, body) != string(codes.MemberChallengeRateLimited) {
		t.Fatalf("%d %v", status, body)
	}
	detail := body["detail"].(map[string]any)
	if detail["retry_after_seconds"] == nil {
		t.Fatal("no retry_after_seconds")
	}
	// The window is not extended by later requests.
	w.clock = w.clock.Add(30 * time.Second)
	_, body = w.call("POST", path, "", "")
	if got := body["detail"].(map[string]any)["retry_after_seconds"].(float64); got != 30 {
		t.Errorf("retry_after_seconds = %v after half the window, want 30", got)
	}
	w.clock = w.clock.Add(31 * time.Second)
	if status, _ := w.call("POST", path, "", ""); status != http.StatusOK {
		t.Errorf("the window did not reopen: %d", status)
	}
}

// Rotation: the presented token is revoked and a fresh pair issued.
func TestRefreshIsSingleUse(t *testing.T) {
	w := newIDWorld(t)
	root := vectors.SignPriv("identity/root")
	alice := newIDDevice("alice")
	cert, sig := w.genesisCert(root, alice)
	w.call("POST", "/v1/members", "", w.registerBody(alice, cert, sig, root, false))
	_, refresh := w.login(alice)

	path := "/v1/members/" + vectors.UUID(alice.id) + "/token/refresh"
	req := func(tok string) string {
		raw, _ := json.Marshal(map[string]any{"refresh_token": tok})
		return string(raw)
	}
	status, body := w.call("POST", path, "", req(refresh))
	if status != http.StatusOK {
		t.Fatalf("refresh: %d %v", status, body)
	}
	next := body["refresh_token"].(string)
	if next == refresh {
		t.Error("the refresh token was not rotated")
	}
	status, body = w.call("POST", path, "", req(refresh))
	if status != http.StatusUnauthorized || refusalCode(t, body) != string(codes.InvalidRefreshToken) {
		t.Errorf("a presented token stayed live: %d %v", status, body)
	}

	// Scoped to a device. bob is registered, so the refusal is the scoping and
	// not a missing device record — which is what the first version of this test
	// actually exercised.
	bob := newIDDevice("bob")
	bcert, bsig := w.genesisCert(root, bob)
	if status, _ := w.call("POST", "/v1/members", "", w.registerBody(bob, bcert, bsig, root, false)); status != http.StatusCreated {
		t.Fatal("bob did not register")
	}
	other := "/v1/members/" + vectors.UUID(bob.id) + "/token/refresh"
	if status, _ := w.call("POST", other, "", req(next)); status != http.StatusUnauthorized {
		t.Error("a refresh token was spendable by another device")
	}
	// And alice's own token still works, so the refusal above spent nothing it
	// should not have.
	if status, _ := w.call("POST", path, "", req(next)); status != http.StatusOK {
		t.Error("a wrong-device attempt consumed the token")
	}
}

// A refresh token is stored irreversibly: the store holds its hash and nothing
// that could reconstruct it.
func TestRefreshTokensAreStoredIrreversibly(t *testing.T) {
	w := newIDWorld(t)
	root := vectors.SignPriv("identity/root")
	alice := newIDDevice("alice")
	cert, sig := w.genesisCert(root, alice)
	w.call("POST", "/v1/members", "", w.registerBody(alice, cert, sig, root, false))
	_, refresh := w.login(alice)

	if w.ids.LiveRefreshCount(alice.id) != 1 {
		t.Fatalf("live tokens = %d", w.ids.LiveRefreshCount(alice.id))
	}
	// The only way to reach the row is to already hold the token.
	if ok, _ := w.ids.TakeRefresh(t.Context(), identity.RefreshHash(refresh+"x"), alice.id, w.clock); ok {
		t.Error("a near-miss token resolved")
	}
	if ok, _ := w.ids.TakeRefresh(t.Context(), identity.RefreshHash(refresh), alice.id, w.clock); !ok {
		t.Error("the real token did not resolve")
	}
}

// An access token expires, and every route re-tests the bar so an unexpired one
// buys nothing after a revoke.
func TestAccessTokenExpires(t *testing.T) {
	w := newIDWorld(t)
	root := vectors.SignPriv("identity/root")
	alice := newIDDevice("alice")
	cert, sig := w.genesisCert(root, alice)
	w.call("POST", "/v1/members", "", w.registerBody(alice, cert, sig, root, false))
	access, _ := w.login(alice)

	if status, _ := w.call("GET", "/v1/w/"+vectors.UUID(w.ws)+"/ops", access, ""); status != http.StatusOK {
		t.Fatal("a fresh token was refused")
	}
	w.clock = w.clock.Add(w.prof.Limits.AccessTokenLifetime + time.Second)
	status, body := w.call("GET", "/v1/w/"+vectors.UUID(w.ws)+"/ops", access, "")
	if status != http.StatusUnauthorized || refusalCode(t, body) != string(codes.InvalidCredential) {
		t.Errorf("an expired token: %d %v", status, body)
	}
	// A token nobody minted is not a token — including one shaped exactly like a
	// real one. "forged" alone would fail the length check long before the MAC,
	// so this flips a byte of the MAC on a token the server really issued.
	w.clock = w.clock.Add(-w.prof.Limits.AccessTokenLifetime - time.Second)
	fresh, _ := w.login(alice)
	raw, err := base64.RawURLEncoding.DecodeString(fresh)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	if status, _ := w.call("GET", "/v1/w/"+vectors.UUID(w.ws)+"/ops", tampered, ""); status != http.StatusUnauthorized {
		t.Error("a token with a tampered MAC was accepted")
	}
	// And flipping a byte of the device id it names is the same failure.
	raw[len(raw)-1] ^= 0x01
	raw[0] ^= 0x01
	if status, _ := w.call("GET", "/v1/w/"+vectors.UUID(w.ws)+"/ops", base64.RawURLEncoding.EncodeToString(raw), ""); status != http.StatusUnauthorized {
		t.Error("a token naming a different device was accepted")
	}
	if status, _ := w.call("GET", "/v1/w/"+vectors.UUID(w.ws)+"/ops", "forged", ""); status != http.StatusUnauthorized {
		t.Error("a malformed token was accepted")
	}
}

// Losing the last live grant kills every refresh token scoped to that device.
// The cascade fires after the commit, and this is where it lands.
func TestRevokeCascadeKillsSessions(t *testing.T) {
	w := newIDWorld(t)
	root := vectors.SignPriv("identity/root")
	alice := newIDDevice("alice")
	cert, sig := w.genesisCert(root, alice)
	w.call("POST", "/v1/members", "", w.registerBody(alice, cert, sig, root, false))
	w.login(alice)

	if w.ids.LiveRefreshCount(alice.id) != 1 {
		t.Fatalf("live tokens before = %d", w.ids.LiveRefreshCount(alice.id))
	}

	// Seed a grant and revoke it through the store, the way an accepted revoke
	// op does.
	w.log.Seed(w.ws, func(s memstore.Seeder) {
		s.Exists()
		s.Member(oplog.MemberRecord{MemberID: alice.id, Kind: "device"})
		s.Grant(oplog.Grant{GrantID: vectors.Bytes16("g"), Member: alice.id, Role: "owner", Start: 1})
	})
	tx, err := w.log.BeginAppend(t.Context(), w.ws)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.CloseGrant(vectors.Bytes16("g"), 2); err != nil {
		t.Fatal(err)
	}
	if err := tx.EndDeviceSessions(alice.id); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	if n := w.ids.LiveRefreshCount(alice.id); n != 0 {
		t.Errorf("live tokens after the cascade = %d, want 0", n)
	}
}

// A rolled-back batch kills nothing: every effect a control op causes lands
// after the commit.
func TestCascadeDoesNotFireOnRollback(t *testing.T) {
	w := newIDWorld(t)
	root := vectors.SignPriv("identity/root")
	alice := newIDDevice("alice")
	cert, sig := w.genesisCert(root, alice)
	w.call("POST", "/v1/members", "", w.registerBody(alice, cert, sig, root, false))
	w.login(alice)

	tx, _ := w.log.BeginAppend(t.Context(), w.ws)
	_ = tx.EndDeviceSessions(alice.id)
	_ = tx.Rollback()

	if n := w.ids.LiveRefreshCount(alice.id); n != 1 {
		t.Errorf("a rolled-back cascade killed %d sessions", 1-n)
	}
}

// ── the registration door's own refusals ────────────────────────────────────

func TestRegisterRefusals(t *testing.T) {
	w := newIDWorld(t)
	root := vectors.SignPriv("identity/root")
	alice := newIDDevice("alice")
	cert, sig := w.genesisCert(root, alice)
	good := w.registerBody(alice, cert, sig, root, true)

	// A claimed key id that disagrees with the derivation.
	ctrl, cont := alice.controlPK(), alice.contentPK()
	bad := strings.Replace(good, `"control_key_id":"`+kidOf(ctrl)+`"`,
		`"control_key_id":"`+kidOf(cont)+`"`, 1)
	status, body := w.call("POST", "/v1/members", "", bad)
	if status != http.StatusUnprocessableEntity || refusalCode(t, body) != string(codes.KeyIdNotDerivedFromSignPk) {
		t.Errorf("key id claim: %d %v", status, body)
	}

	// A Root that may not found the id it names.
	w.prof.Creatable = func([32]byte, [16]byte) bool { return false }
	status, body = w.call("POST", "/v1/members", "", good)
	if status != http.StatusForbidden || refusalCode(t, body) != string(codes.WorkspaceNotReachable) {
		t.Errorf("reachability: %d %v", status, body)
	}
	w.prof.Creatable = func(_ [32]byte, ws [16]byte) bool { return ws == vectors.WorkspaceID }

	// A signature nobody made.
	forged := strings.Replace(good, `"cert_sig_b64":"`+sig+`"`,
		`"cert_sig_b64":"`+base64.StdEncoding.EncodeToString(make([]byte, 64))+`"`, 1)
	status, body = w.call("POST", "/v1/members", "", forged)
	if status != http.StatusUnprocessableEntity || refusalCode(t, body) != string(codes.BadRootSignature) {
		t.Errorf("forged signature: %d %v", status, body)
	}

	// The same id with a different key is a collision, not a takeover.
	if status, _ := w.call("POST", "/v1/members", "", good); status != http.StatusCreated {
		t.Fatal("the good registration did not land")
	}
	impostor := newIDDevice("impostor")
	impostor.id = alice.id
	icert, isig := w.genesisCert(root, impostor)
	status, body = w.call("POST", "/v1/members", "", w.registerBody(impostor, icert, isig, root, false))
	if status != http.StatusConflict || refusalCode(t, body) != string(codes.MemberIdAlreadyRegistered) {
		t.Errorf("collision: %d %v", status, body)
	}
}

// The joining branch needs the Workspace to exist with this Root as its current
// one.
func TestJoiningBranchRefusals(t *testing.T) {
	w := newIDWorld(t)
	root := vectors.SignPriv("identity/root")
	bob := newIDDevice("bob")
	c, n, k := bob.controlPK(), bob.contentPK(), bob.kex
	cid, nid, kid := wire.KeyID(c[:]), wire.KeyID(n[:]), wire.KeyID(k[:])
	cert, _ := json.Marshal(map[string]any{
		"workspace_id": vectors.UUID(w.ws), "member_id": vectors.UUID(bob.id), "member_kind": "device",
		"holder_ref":     base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"control_pk":     base64.StdEncoding.EncodeToString(c[:]),
		"control_key_id": base64.StdEncoding.EncodeToString(cid[:]),
		"content_pk":     base64.StdEncoding.EncodeToString(n[:]),
		"content_key_id": base64.StdEncoding.EncodeToString(nid[:]),
		"kex_pk":         base64.StdEncoding.EncodeToString(k[:]),
		"kex_key_id":     base64.StdEncoding.EncodeToString(kid[:]),
		"registered_at_hlc": []any{1700000000000, 0,
			"00000000000000000000000000000000"},
	})
	sig := ed25519.Sign(root, w.ns.CertSigningInput(wire.DocMemberRegister, cert))
	body := w.registerBody(bob,
		base64.StdEncoding.EncodeToString(cert),
		base64.StdEncoding.EncodeToString(sig), root, false)

	// No genesis yet.
	status, resp := w.call("POST", "/v1/members", "", body)
	if status != http.StatusConflict || refusalCode(t, resp) != string(codes.WorkspaceNotCreated) {
		t.Fatalf("no genesis: %d %v", status, resp)
	}

	// The Workspace exists under another Root: rebuild, not forged.
	other := to32(vectors.SignPub("identity/other-root"))
	w.log.Seed(w.ws, func(s memstore.Seeder) { s.Exists() })
	tx, _ := w.log.BeginAppend(t.Context(), w.ws)
	_ = tx.SetRoot(other)
	_ = tx.Commit()

	status, resp = w.call("POST", "/v1/members", "", body)
	if status != http.StatusUnprocessableEntity || refusalCode(t, resp) != string(codes.CertRootPkMismatch) {
		t.Errorf("wrong Root: %d %v", status, resp)
	}
}

// Admission gates the founding branch and nothing else.
func TestAdmissionGatesFoundingOnly(t *testing.T) {
	w := newIDWorld(t)
	w.prof.Admission = profile.AdmissionServer
	root := vectors.SignPriv("identity/root")
	alice := newIDDevice("alice")
	cert, sig := w.genesisCert(root, alice)

	ih := &httpapi.IdentityHandler{
		Registrar: &identity.Registrar{
			Profile: w.prof, Store: w.ids, Lookup: memstore.Lookup{Log: w.log},
			Admission: refuseAdmission{},
		},
		Sessions: &identity.Sessions{Profile: w.prof, Store: w.ids, Tokens: w.toks},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /members", ih.ServeRegister)
	req := httptest.NewRequest("POST", "/members", strings.NewReader(w.registerBody(alice, cert, sig, root, false)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if refusalCode(t, resp) != string(codes.AdmissionRefused) {
		t.Errorf("code = %v", resp)
	}
}

type refuseAdmission struct{}

func (refuseAdmission) Admit(_ context.Context, _ string) bool { return false }

func kidOf(pk [32]byte) string {
	id := wire.KeyID(pk[:])
	return base64.StdEncoding.EncodeToString(id[:])
}
