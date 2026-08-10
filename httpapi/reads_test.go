package httpapi_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/loonybin/roundelay/authority"
	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/httpapi"
	"github.com/loonybin/roundelay/internal/memstore"
	"github.com/loonybin/roundelay/internal/testprofile"
	"github.com/loonybin/roundelay/internal/vectors"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/wire"
)

// readWorld is a Workspace with a log in it, served by the real read handlers
// over the real bar.
type readWorld struct {
	t     *testing.T
	rt    http.Handler
	store *memstore.Store
	ws    [16]byte
	dev   [16]byte
	pipe  *oplog.Pipeline
	seq   uint64
}

func newReadWorld(t *testing.T) *readWorld {
	t.Helper()
	p := testprofile.Minimal()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	st := memstore.New()
	ws, dev := vectors.WorkspaceID, vectors.MemberA

	st.Seed(ws, func(s memstore.Seeder) {
		s.Exists()
		s.Member(oplog.MemberRecord{
			MemberID:  dev,
			Kind:      "device",
			ControlPK: to32(vectors.SignPub(vectors.LabelDeviceAControl)),
			ContentPK: to32(vectors.SignPub(vectors.LabelDeviceAContent)),
			KexPK:     to32(vectors.KexPub(vectors.LabelDeviceAKex)),
		})
		// A live owner grant from position 0, so the fixture's writes land.
		s.Grant(oplog.Grant{GrantID: vectors.Bytes16("grant/a"), Member: dev, Role: "owner", GranterIsRoot: true})
	})

	rd := &httpapi.ReadHandler{
		Auth: fakeAuth{device: dev}, Store: st, Profile: p, Authority: authority.New(p),
	}
	router := httpapi.NewRouter(httpapi.NewHealth(p, okProbe))
	v1 := http.NewServeMux()
	v1.HandleFunc("GET /w/{workspace_id}/ops", rd.ServeOps)
	v1.HandleFunc("GET /w/{workspace_id}/members", rd.ServeMembers)
	v1.HandleFunc("/", httpapi.NotFound)
	router.Contract("v1", v1)

	return &readWorld{
		t: t, rt: router, store: st, ws: ws, dev: dev,
		pipe: &oplog.Pipeline{Profile: p, Store: st, Authority: authority.New(p)},
	}
}

func to32(b []byte) [32]byte {
	var out [32]byte
	copy(out[:], b)
	return out
}

// write appends n content ops through the real pipeline, so the log holds real
// envelopes rather than fixtures.
func (rw *readWorld) write(n int) {
	rw.t.Helper()
	ops := make([]string, n)
	for i := range n {
		rw.seq++
		h := wire.Header{
			OpClass: wire.ClassContent, Suite: wire.SuiteNone,
			WorkspaceID: rw.ws, AuthorMemberID: rw.dev,
			OpID:        vectors.Bytes16(fmt.Sprintf("read/op/%d", rw.seq)),
			AuthorKeyID: wire.KeyID(vectors.SignPub(vectors.LabelDeviceAContent)),
			AuthorSeq:   rw.seq,
		}
		if rw.seq > 1 {
			h.PrevAuthorHash = vectors.PrevHash(fmt.Sprint(rw.seq))
		}
		body, _ := testprofile.Minimal().SizeClasses.PackBody([]byte(fmt.Sprintf("op %d", rw.seq)))
		ns, _ := wire.NewNamespace(vectors.Namespace)
		env, err := wire.SignOp(vectors.SignPriv(vectors.LabelDeviceAContent), ns.V1(wire.DocOp), h.Marshal(), body)
		if err != nil {
			rw.t.Fatal(err)
		}
		ops[i] = base64.StdEncoding.EncodeToString(env)
	}
	if _, r := rw.pipe.Append(rw.t.Context(), rw.ws, rw.dev, ops); r != nil {
		rw.t.Fatalf("seeding writes: %s %v", r.Code, r.Fields)
	}
}

func (rw *readWorld) get(path string) (int, map[string]any) {
	rw.t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	rw.rt.ServeHTTP(rec, req)
	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			rw.t.Fatalf("%s: %v\n%s", path, err, rec.Body.String())
		}
	}
	return rec.Code, body
}

func (rw *readWorld) ops(query string) (int, []any, bool) {
	rw.t.Helper()
	status, body := rw.get("/v1/w/" + vectors.UUID(rw.ws) + "/ops" + query)
	if status != http.StatusOK {
		return status, nil, false
	}
	list, _ := body["ops"].([]any)
	more, _ := body["has_more"].(bool)
	return status, list, more
}

func seqsOf(t *testing.T, list []any) []int {
	t.Helper()
	out := make([]int, 0, len(list))
	for _, e := range list {
		out = append(out, int(e.(map[string]any)["seq"].(float64)))
	}
	return out
}

// ── GET /ops ────────────────────────────────────────────────────────────────

func TestOpsPaging(t *testing.T) {
	rw := newReadWorld(t)
	rw.write(5)

	_, list, more := rw.ops("")
	if !slices.Equal(seqsOf(t, list), []int{1, 2, 3, 4, 5}) || more {
		t.Fatalf("whole log = %v has_more=%v", seqsOf(t, list), more)
	}

	// `since` is exclusive.
	_, list, more = rw.ops("?since=2")
	if !slices.Equal(seqsOf(t, list), []int{3, 4, 5}) || more {
		t.Errorf("since=2 gave %v has_more=%v", seqsOf(t, list), more)
	}

	// has_more is exact: true iff at least one further op exists under the same
	// filter.
	_, list, more = rw.ops("?limit=2")
	if !slices.Equal(seqsOf(t, list), []int{1, 2}) || !more {
		t.Errorf("limit=2 gave %v has_more=%v", seqsOf(t, list), more)
	}
	_, list, more = rw.ops("?since=3&limit=2")
	if !slices.Equal(seqsOf(t, list), []int{4, 5}) || more {
		t.Errorf("the last exact page gave %v has_more=%v", seqsOf(t, list), more)
	}
	_, list, more = rw.ops("?since=5")
	if len(list) != 0 || more {
		t.Errorf("past the end gave %v has_more=%v", seqsOf(t, list), more)
	}
}

// Served back byte-identical.
func TestOpsAreServedVerbatim(t *testing.T) {
	rw := newReadWorld(t)
	rw.write(1)
	_, list, _ := rw.ops("")
	got := list[0].(map[string]any)["envelope"].(string)
	stored := rw.store.Ops(rw.ws)[0]
	if got != base64.StdEncoding.EncodeToString(stored.Envelope) {
		t.Error("the served envelope is not byte-identical to what was stored")
	}
}

// Clamping would let a device built against a larger deployment silently
// receive short pages and mistake one for the end of the log.
func TestOpsParametersAreNeverClamped(t *testing.T) {
	rw := newReadWorld(t)
	rw.write(2)
	for _, q := range []string{"?limit=0", "?limit=99999", "?since=-1", "?since=1.5"} {
		status, body := rw.get("/v1/w/" + vectors.UUID(rw.ws) + "/ops" + q)
		if status != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, want 422", q, status)
			continue
		}
		if got := refusalCode(t, body); got != string(codes.MalformedRequest) {
			t.Errorf("%s: code %q", q, got)
		}
	}
}

// include_reprised must be exactly "true" or "false".
func TestIncludeReprisedIsExact(t *testing.T) {
	rw := newReadWorld(t)
	rw.write(1)
	for _, v := range []string{"1", "TRUE", "yes", ""} {
		status, _ := rw.get("/v1/w/" + vectors.UUID(rw.ws) + "/ops?include_reprised=" + v)
		if status != http.StatusUnprocessableEntity {
			t.Errorf("include_reprised=%q: status %d, want 422", v, status)
		}
	}
	for _, v := range []string{"true", "false"} {
		if status, _ := rw.get("/v1/w/" + vectors.UUID(rw.ws) + "/ops?include_reprised=" + v); status != http.StatusOK {
			t.Errorf("include_reprised=%s: status %d", v, status)
		}
	}
}

func TestOpsUnknownParameter(t *testing.T) {
	rw := newReadWorld(t)
	status, body := rw.get("/v1/w/" + vectors.UUID(rw.ws) + "/ops?cursor=3")
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d", status)
	}
	if got := refusalCode(t, body); got != string(codes.UnknownRequestField) {
		t.Errorf("code %q", got)
	}
}

// A prune deletes nothing: the mark is a filter, and include_reprised=true
// serves the op back.
func TestRepriseFilterAndHistoryView(t *testing.T) {
	rw := newReadWorld(t)
	rw.write(3)

	// Mark op 2 reprised by op 3, the way an accepted prune would.
	tx, err := rw.store.BeginAppend(t.Context(), rw.ws)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkReprised(2, 3); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	_, list, _ := rw.ops("")
	if !slices.Equal(seqsOf(t, list), []int{1, 3}) {
		t.Errorf("default read = %v, want the marked op hidden", seqsOf(t, list))
	}
	_, list, _ = rw.ops("?include_reprised=true")
	if !slices.Equal(seqsOf(t, list), []int{1, 2, 3}) {
		t.Errorf("history view = %v", seqsOf(t, list))
	}

	// has_more counts servable entries only, so a filtered page is not a short
	// page with a wrong flag.
	_, list, more := rw.ops("?limit=1")
	if !slices.Equal(seqsOf(t, list), []int{1}) || !more {
		t.Errorf("filtered limit=1 gave %v has_more=%v", seqsOf(t, list), more)
	}
	_, list, more = rw.ops("?since=1&limit=1")
	if !slices.Equal(seqsOf(t, list), []int{3}) || more {
		t.Errorf("the last filtered page gave %v has_more=%v", seqsOf(t, list), more)
	}
}

// has_more counts servable entries only, and the case that says so is a hidden
// op sitting *after* the last servable one: a page that fills its limit and is
// followed by nothing but marked ops must still report has_more false.
func TestHasMoreIgnoresHiddenTrailingOps(t *testing.T) {
	rw := newReadWorld(t)
	rw.write(3)

	tx, err := rw.store.BeginAppend(t.Context(), rw.ws)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkReprised(3, 3); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	_, list, more := rw.ops("?limit=2")
	if !slices.Equal(seqsOf(t, list), []int{1, 2}) {
		t.Fatalf("page = %v", seqsOf(t, list))
	}
	if more {
		t.Error("has_more counted a hidden op; a caller would walk to an empty page")
	}
}

// include_reprised=true no longer returns a hard-pruned op. The position is
// absent from the page, and the hard_prune that removed it is in the log.
func TestHardPrunedOpsAreAbsentFromEveryPage(t *testing.T) {
	rw := newReadWorld(t)
	rw.write(3)

	tx, _ := rw.store.BeginAppend(t.Context(), rw.ws)
	_ = tx.MarkReprised(2, 3)
	_ = tx.DropEnvelope(2)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	for _, q := range []string{"", "?include_reprised=true"} {
		_, list, _ := rw.ops(q)
		if slices.Contains(seqsOf(t, list), 2) {
			t.Errorf("%q served a hard-pruned position: %v", q, seqsOf(t, list))
		}
	}
	// The history view is not a retention promise, and the tombstone stays.
	if got := rw.store.Ops(rw.ws)[1]; !got.Dropped() || got.Seq != 2 {
		t.Errorf("the tombstone did not survive: %+v", got)
	}
}

// ── bar 1 ───────────────────────────────────────────────────────────────────

// Reading a Workspace that does not exist yet returns an empty page, not an
// error — which is how a device discovers it needs to create one.
func TestReadingAnUncreatedWorkspace(t *testing.T) {
	rw := newReadWorld(t)
	other := vectors.Bytes16("no-such-workspace")

	status, body := rw.get("/v1/w/" + vectors.UUID(other) + "/ops")
	if status != http.StatusOK {
		t.Fatalf("status %d, want an empty page", status)
	}
	if list, _ := body["ops"].([]any); len(list) != 0 || body["has_more"] != false {
		t.Errorf("body = %v", body)
	}

	status, body = rw.get("/v1/w/" + vectors.UUID(other) + "/members")
	if status != http.StatusOK {
		t.Fatalf("members status %d", status)
	}
	if list, _ := body["members"].([]any); len(list) != 0 || body["has_more"] != false {
		t.Errorf("members body = %v", body)
	}
}

func TestBarOneRefusals(t *testing.T) {
	p := testprofile.Minimal()
	st := memstore.New()
	ws := vectors.WorkspaceID
	stranger, pregrant, revoked := vectors.MemberB, vectors.Bytes16("pre"), vectors.Bytes16("rev")

	st.Seed(ws, func(s memstore.Seeder) {
		s.Exists()
		s.Member(oplog.MemberRecord{MemberID: pregrant, Kind: "device"})
		s.Member(oplog.MemberRecord{MemberID: revoked, Kind: "device"})
		// Held a grant and holds none live.
		s.Grant(oplog.Grant{GrantID: vectors.Bytes16("g/rev"), Member: revoked, Role: "owner", Start: 1, End: 2})
	})

	serve := func(device [16]byte) (int, map[string]any) {
		rd := &httpapi.ReadHandler{Auth: fakeAuth{device: device}, Store: st, Profile: p, Authority: authority.New(p)}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /w/{workspace_id}/ops", rd.ServeOps)
		req := httptest.NewRequest("GET", "/w/"+vectors.UUID(ws)+"/ops", nil)
		req.Header.Set("Authorization", "Bearer good")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}

	// Never let in.
	status, body := serve(stranger)
	if status != http.StatusForbidden || refusalCode(t, body) != string(codes.NoRegistration) {
		t.Errorf("stranger: %d %v", status, body)
	}

	// Let in and never granted anything: not revoked, and passes. This is what
	// lets an enrolling device replay the control log before it holds any
	// permission.
	if status, body := serve(pregrant); status != http.StatusOK {
		t.Errorf("pre-grant device was refused: %d %v", status, body)
	}

	// Let in and then removed.
	status, body = serve(revoked)
	if status != http.StatusForbidden || refusalCode(t, body) != string(codes.NoLiveGrant) {
		t.Fatalf("revoked: %d %v", status, body)
	}
	if detail := body["detail"].(map[string]any); detail["revoked"] != true {
		t.Errorf("a revoked device was not reported as revoked: %v", detail)
	}
}

// ── GET /members ────────────────────────────────────────────────────────────

// Ordered by raw member id bytes ascending, which is not the order a base64
// spelling or a signed 64-bit comparison gives.
func TestMembersOrderIsRawBytes(t *testing.T) {
	p := testprofile.Minimal()
	st := memstore.New()
	ws := vectors.WorkspaceID
	reader := vectors.MemberA

	low := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	high := [16]byte{0xd0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	st.Seed(ws, func(s memstore.Seeder) {
		s.Exists()
		s.Member(oplog.MemberRecord{MemberID: reader, Kind: "device"})
		s.Member(oplog.MemberRecord{MemberID: high, Kind: "device"})
		s.Member(oplog.MemberRecord{MemberID: low, Kind: "device"})
	})

	rd := &httpapi.ReadHandler{Auth: fakeAuth{device: reader}, Store: st, Profile: p, Authority: authority.New(p)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /w/{workspace_id}/members", rd.ServeMembers)

	call := func(q string) map[string]any {
		req := httptest.NewRequest("GET", "/w/"+vectors.UUID(ws)+"/members"+q, nil)
		req.Header.Set("Authorization", "Bearer good")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: %v\n%s", q, err, rec.Body.String())
		}
		return body
	}

	ids := func(body map[string]any) []string {
		list, _ := body["members"].([]any)
		out := make([]string, 0, len(list))
		for _, e := range list {
			out = append(out, e.(map[string]any)["member_id"].(string))
		}
		return out
	}

	got := ids(call(""))
	// 0x00… sorts first by raw bytes; base64 would put 0xd0… first (its leading
	// '0' is 0x30, below 'A'), and a signed 64-bit comparison would too.
	if got[0] != vectors.UUID(low) || got[len(got)-1] != vectors.UUID(high) {
		t.Errorf("order = %v", got)
	}
	if !slices.IsSorted(got) {
		t.Errorf("canonical lowercase UUIDs should sort as their bytes do: %v", got)
	}

	// `after` is exclusive, and a position rather than a lookup: a value naming
	// no member is legal and the page begins strictly above those bytes.
	after := call("?after=" + vectors.UUID(low))
	if slices.Contains(ids(after), vectors.UUID(low)) {
		t.Error("after is not exclusive")
	}
	nobody := "88888888-8888-8888-8888-888888888888"
	if body := call("?after=" + nobody); body["members"] == nil {
		t.Error("an after naming no member was refused")
	}

	// has_more is exact.
	one := call("?limit=1")
	if len(ids(one)) != 1 || one["has_more"] != true {
		t.Errorf("limit=1 gave %v has_more=%v", ids(one), one["has_more"])
	}
	last := call("?after=" + vectors.UUID(high))
	if len(ids(last)) != 0 || last["has_more"] != false {
		t.Errorf("past the end gave %v has_more=%v", ids(last), last["has_more"])
	}

	// Key ids are derived, never claimed, and there is no chained flag.
	entry := call("?limit=1")["members"].([]any)[0].(map[string]any)
	if _, present := entry["chained"]; present {
		t.Error("an entry carried a chained flag; presence in this list is the chaining")
	}
	kid := entry["key_ids"].(map[string]any)
	for _, k := range []string{"control_key_id", "content_key_id", "kex_key_id"} {
		if kid[k] == nil {
			t.Errorf("key_ids is missing %s", k)
		}
	}
	pk, _ := base64.StdEncoding.DecodeString(entry["control_pk"].(string))
	want := wire.KeyID(pk)
	if kid["control_key_id"] != base64.StdEncoding.EncodeToString(want[:]) {
		t.Error("control_key_id is not the derivation of the key beside it")
	}
}

func TestMembersParameters(t *testing.T) {
	rw := newReadWorld(t)
	base := "/v1/w/" + vectors.UUID(rw.ws) + "/members"

	// after and limit are the only parameters this route accepts.
	status, body := rw.get(base + "?since=1")
	if status != http.StatusUnprocessableEntity || refusalCode(t, body) != string(codes.UnknownRequestField) {
		t.Errorf("since: %d %v", status, body)
	}
	// A misshapen cursor is refused for being misshapen, and for nothing else.
	status, body = rw.get(base + "?after=NOT-A-UUID")
	if status != http.StatusUnprocessableEntity || refusalCode(t, body) != string(codes.MalformedRequest) {
		t.Errorf("after: %d %v", status, body)
	}
	status, _ = rw.get(base + "?limit=0")
	if status != http.StatusUnprocessableEntity {
		t.Errorf("limit=0: status %d", status)
	}
}
