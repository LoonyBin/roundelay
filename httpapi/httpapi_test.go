package httpapi_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/httpapi"
	"github.com/loonybin/roundelay/internal/memstore"
	"github.com/loonybin/roundelay/internal/testprofile"
	"github.com/loonybin/roundelay/internal/vectors"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/strictjson"
	"github.com/loonybin/roundelay/wire"
)

// newRouter wires a router over a profile, with a v1 mux carrying one route and
// the ordinary unrouted answer beneath it.
func newRouter(t *testing.T, p *profile.Profile, probe httpapi.Probe) *httpapi.Router {
	t.Helper()
	if err := p.Validate(); err != nil {
		t.Fatalf("profile: %v", err)
	}
	rt := httpapi.NewRouter(httpapi.NewHealth(p, probe))

	v1 := http.NewServeMux()
	v1.HandleFunc("GET /w/{workspace_id}/ops", func(w http.ResponseWriter, r *http.Request) {
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{"ops": []any{}, "has_more": false})
	})
	v1.HandleFunc("/", httpapi.NotFound)
	rt.Contract("v1", v1)
	return rt
}

func okProbe(context.Context) error   { return nil }
func downProbe(context.Context) error { return errors.New("store is unavailable") }

func do(t *testing.T, rt http.Handler, method, path string) (int, map[string]any, http.Header) {
	t.Helper()
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s %s: response is not JSON: %v\n%s", method, path, err, rec.Body.String())
		}
	}
	return rec.Code, body, rec.Header()
}

func refusalCode(t *testing.T, body map[string]any) string {
	t.Helper()
	detail, ok := body["detail"].(map[string]any)
	if !ok {
		t.Fatalf("response carries no detail object: %v", body)
	}
	code, ok := detail["code"].(string)
	if !ok {
		t.Fatalf("detail carries no code: %v", detail)
	}
	return code
}

// ── the version demultiplexer ───────────────────────────────────────────────

func TestServedVersionDispatches(t *testing.T) {
	rt := newRouter(t, testprofile.Minimal(), okProbe)
	status, body, _ := do(t, rt, "GET", "/v1/w/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9/ops")
	if status != http.StatusOK {
		t.Fatalf("status %d, body %v", status, body)
	}
	if _, ok := body["has_more"]; !ok {
		t.Errorf("the v1 handler did not see the request: %v", body)
	}
}

// "This server is older than me" — recoverable, and worth surfacing to someone.
func TestUnservedVersion(t *testing.T) {
	rt := newRouter(t, testprofile.Minimal(), okProbe)
	for _, path := range []string{"/v2/w/x/ops", "/v2", "/v0/anything", "/v99/"} {
		status, body, _ := do(t, rt, "GET", path)
		if status != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", path, status)
		}
		if got := refusalCode(t, body); got != string(codes.UnsupportedContractVersion) {
			t.Errorf("%s: code %q, want unsupported_contract_version", path, got)
		}
		detail := body["detail"].(map[string]any)
		if detail["requested"] == nil {
			t.Errorf("%s: refusal names no requested version", path)
		}
		served, ok := detail["served"].([]any)
		if !ok || len(served) != 1 || served[0] != "v1" {
			t.Errorf("%s: served = %v, want [v1]", path, detail["served"])
		}
	}
}

// "I built the wrong URL" — a bug in the client, and a different 404.
//
// CONF-VER-003 names all five of these, and v01 is the one the layer document's
// own `^v[0-9]+$` would have sent down the other branch.
func TestNotVersionShapedAndUnknownSuffix(t *testing.T) {
	rt := newRouter(t, testprofile.Minimal(), okProbe)
	for _, path := range []string{
		"/api/w/x/ops",
		"/V2/w/x/ops",
		"/v01/w/x/ops",
		"/v1x/w/x/ops",
		"/v1/nope",
		"/",
		"/health/nope",
	} {
		status, body, _ := do(t, rt, "GET", path)
		if status != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", path, status)
		}
		if got := refusalCode(t, body); got != string(codes.NotFound) {
			t.Errorf("%s: code %q, want not_found", path, got)
		}
	}
}

// A leading zero is the whole of the difference, so pin it from both sides.
func TestLeadingZeroIsNotAVersion(t *testing.T) {
	rt := newRouter(t, testprofile.Minimal(), okProbe)
	_, body, _ := do(t, rt, "GET", "/v01/x")
	if got := refusalCode(t, body); got != string(codes.NotFound) {
		t.Errorf("/v01 answered %q; the checklist puts it on the not_found branch", got)
	}
	_, body, _ = do(t, rt, "GET", "/v1/x")
	if got := refusalCode(t, body); got != string(codes.NotFound) {
		t.Errorf("/v1/x answered %q, want not_found from the v1 mux", got)
	}
	_, body, _ = do(t, rt, "GET", "/v2/x")
	if got := refusalCode(t, body); got != string(codes.UnsupportedContractVersion) {
		t.Errorf("/v2 answered %q, want unsupported_contract_version", got)
	}
}

func TestServedVersionsAreAscendingByNumber(t *testing.T) {
	rt := httpapi.NewRouter(httpapi.NewHealth(testprofile.Minimal(), okProbe))
	for _, v := range []string{"v10", "v2", "v1"} {
		rt.Contract(v, http.HandlerFunc(httpapi.NotFound))
	}
	if got := rt.Served(); !slices.Equal(got, []string{"v1", "v2", "v10"}) {
		t.Errorf("served = %v, want [v1 v2 v10]; a version sorts as a number", got)
	}
}

// ── GET /health ─────────────────────────────────────────────────────────────

func TestHealthDocument(t *testing.T) {
	rt := newRouter(t, testprofile.Extended(), okProbe)
	status, body, hdr := do(t, rt, "GET", "/health")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if ct := hdr.Get("Content-Type"); ct != httpapi.ContentType {
		t.Errorf("content type %q", ct)
	}

	if body["status"] != "ok" || body["version"] != "1.4.2" ||
		body["protocol_namespace"] != "acme" || body["profile"] != "acme/p2" {
		t.Errorf("document header is wrong: %v", body)
	}
	if cv, _ := body["contract_versions"].([]any); len(cv) != 1 || cv[0] != "v1" {
		t.Errorf("contract_versions = %v", body["contract_versions"])
	}

	// Every enabled class mapped to its NAME, keyed by the class number in
	// decimal as a JSON string. 197 is 0xC5.
	ext, ok := body["extension_classes"].(map[string]any)
	if !ok || len(ext) != 1 || ext["197"] != "retention-sweep" {
		t.Errorf("extension_classes = %v", body["extension_classes"])
	}

	sets, ok := body["served_sets"].(map[string]any)
	if !ok {
		t.Fatalf("served_sets = %v", body["served_sets"])
	}
	for _, key := range []string{"suites", "op_classes", "control_types", "prune_types"} {
		if sets[key] == nil {
			t.Errorf("served_sets is missing %s", key)
		}
	}
	if got := ints(t, sets["suites"]); !slices.Equal(got, []int{0, 1}) {
		t.Errorf("suites = %v", got)
	}
	// All three ranges, ascending, with nothing to say which range a byte is from.
	if got := ints(t, sets["op_classes"]); !slices.Equal(got, []int{1, 2, 69, 128, 129, 191, 197}) {
		t.Errorf("op_classes = %v", got)
	}
	if got := strs(t, sets["control_types"]); len(got) != 10 || !slices.IsSorted(got) {
		t.Errorf("control_types = %v", got)
	}
	if got := strs(t, sets["prune_types"]); !slices.Equal(got, []string{"hard_prune", "prune", "prune_ext"}) {
		t.Errorf("prune_types = %v", got)
	}

	limits, ok := body["limits"].(map[string]any)
	if !ok {
		t.Fatalf("limits = %v", body["limits"])
	}
	for _, key := range []string{"max_ops_per_batch", "max_page_size", "default_page_size", "signal_keepalive_seconds"} {
		if limits[key] == nil {
			t.Errorf("limits is missing %s", key)
		}
	}
}

// {} rather than an absent field: absent is indistinguishable from a server too
// old to carry it, and a client that cannot tell those apart guesses.
func TestExtensionClassesIsEmptyObjectNotAbsent(t *testing.T) {
	rt := newRouter(t, testprofile.Minimal(), okProbe)
	_, body, _ := do(t, rt, "GET", "/health")

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var probe struct {
		Ext *map[string]string `json:"extension_classes"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatal(err)
	}
	if probe.Ext == nil {
		t.Fatal("extension_classes is absent or null; it must be {} when none are enabled")
	}
	if len(*probe.Ext) != 0 {
		t.Errorf("extension_classes = %v, want {}", *probe.Ext)
	}
}

// op_classes and extension_classes never disagree: the same 0xC5 appears in
// both, spelled as an integer in one and a decimal string key in the other.
func TestServedSetsAndExtensionClassesAgree(t *testing.T) {
	p := testprofile.Extended()
	rt := newRouter(t, p, okProbe)
	_, body, _ := do(t, rt, "GET", "/health")

	sets := body["served_sets"].(map[string]any)
	classes := ints(t, sets["op_classes"])
	for key := range body["extension_classes"].(map[string]any) {
		var n int
		if _, err := fmt.Sscanf(key, "%d", &n); err != nil {
			t.Fatalf("extension_classes key %q is not decimal", key)
		}
		if !slices.Contains(classes, n) {
			t.Errorf("%d is in extension_classes but not in op_classes", n)
		}
	}
	// And the advertisement is truthful: every advertised byte is one the
	// profile actually serves.
	for _, c := range classes {
		if !p.ServesClass(byte(c)) {
			t.Errorf("op_classes advertises %d, which the profile refuses", c)
		}
	}
}

// GET /health MUST remain reachable while the backing store is unavailable —
// that is its purpose.
func TestHealthAnswersWhileTheStoreIsDown(t *testing.T) {
	rt := newRouter(t, testprofile.Minimal(), downProbe)
	if status, _, _ := do(t, rt, "GET", "/health"); status != http.StatusOK {
		t.Errorf("GET /health answered %d while the store was down", status)
	}
	status, body, _ := do(t, rt, "GET", "/health/db")
	if status != http.StatusServiceUnavailable {
		t.Errorf("GET /health/db answered %d, want 503", status)
	}
	if got := refusalCode(t, body); got != string(codes.StoreUnavailable) {
		t.Errorf("code %q, want store_unavailable", got)
	}
	// The refusal says nothing else: it is a statement about the server, and the
	// only code in the vocabulary that is.
	if detail := body["detail"].(map[string]any); len(detail) != 1 {
		t.Errorf("store_unavailable carried extra fields: %v", detail)
	}
}

func TestHealthDBOK(t *testing.T) {
	rt := newRouter(t, testprofile.Minimal(), okProbe)
	status, body, _ := do(t, rt, "GET", "/health/db")
	if status != http.StatusOK || body["status"] != "ok" {
		t.Errorf("status %d, body %v", status, body)
	}
}

// A server with no probe cannot claim its store answers.
func TestHealthDBWithoutAProbeFailsClosed(t *testing.T) {
	rt := newRouter(t, testprofile.Minimal(), nil)
	if status, _, _ := do(t, rt, "GET", "/health/db"); status != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503", status)
	}
}

// ── the refusal shape ───────────────────────────────────────────────────────

func TestRefusalShape(t *testing.T) {
	rec := httptest.NewRecorder()
	httpapi.Refuse(rec, codes.BatchTooLarge, map[string]any{"max_ops": 1000})

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d, want 413 from the code's own row", rec.Code)
	}
	var body struct {
		Detail map[string]any `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Detail["code"] != "batch_too_large" || body.Detail["max_ops"] != float64(1000) {
		t.Errorf("detail = %v", body.Detail)
	}
}

// 401 responses carry WWW-Authenticate: Bearer, and nothing else does.
func TestUnauthorizedCarriesWWWAuthenticate(t *testing.T) {
	rec := httptest.NewRecorder()
	httpapi.Refuse(rec, codes.InvalidCredential, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("WWW-Authenticate = %q", got)
	}

	rec = httptest.NewRecorder()
	httpapi.Refuse(rec, codes.NotFound, nil)
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("a 404 carried WWW-Authenticate: %q", got)
	}
}

// detail.code is the code, whatever a caller passes beside it.
func TestExtraFieldsCannotOverwriteTheCode(t *testing.T) {
	rec := httptest.NewRecorder()
	httpapi.Refuse(rec, codes.NotFound, map[string]any{"code": "something_else"})
	var body struct {
		Detail map[string]any `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Detail["code"] != "not_found" {
		t.Errorf("detail.code = %v", body.Detail["code"])
	}
}

// A code the document raises under two statuses cannot be written without one.
func TestMultiStatusCodeRequiresAnExplicitStatus(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Refuse accepted a code with two statuses")
		}
	}()
	httpapi.Refuse(httptest.NewRecorder(), codes.BadMemberChallenge, nil)
}

// The versioned surface's two structural codes, mapped from one decoder.
func TestRefuseDecode(t *testing.T) {
	body, err := strictjson.Parse([]byte(`{"known": 1, "surprise": 2}`))
	if err != nil {
		t.Fatal(err)
	}
	body.Root().Int("known", 0, 10)

	rec := httptest.NewRecorder()
	if !httpapi.RefuseDecode(rec, body.Err()) {
		t.Fatal("RefuseDecode wrote nothing for an unknown field")
	}
	var got struct {
		Detail struct {
			Code   string   `json:"code"`
			Fields []string `json:"fields"`
		} `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusUnprocessableEntity || got.Detail.Code != "unknown_request_field" {
		t.Errorf("status %d code %q", rec.Code, got.Detail.Code)
	}
	if !slices.Equal(got.Detail.Fields, []string{"surprise"}) {
		t.Errorf("fields = %v", got.Detail.Fields)
	}

	body, _ = strictjson.Parse([]byte(`{"a": 1, "a": 2}`))
	body.Root().Int("a", 0, 10)
	rec = httptest.NewRecorder()
	httpapi.RefuseDecode(rec, body.Err())
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Detail.Code != "malformed_request" {
		t.Errorf("a duplicated key mapped to %q", got.Detail.Code)
	}

	if httpapi.RefuseDecode(httptest.NewRecorder(), nil) {
		t.Error("RefuseDecode wrote something for a nil error")
	}
}

// ── methods ─────────────────────────────────────────────────────────────────

// The status table carries no 405 and the vocabulary is closed, so a route that
// exists only under another method answers "no such thing".
func TestUnexpectedMethod(t *testing.T) {
	rt := newRouter(t, testprofile.Minimal(), okProbe)
	for _, c := range []struct{ method, path string }{
		{"POST", "/health"},
		{"DELETE", "/health/db"},
		{"POST", "/v1/w/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9/ops"},
	} {
		status, body, _ := do(t, rt, c.method, c.path)
		if status != http.StatusNotFound {
			t.Errorf("%s %s: status %d, want 404", c.method, c.path, status)
		}
		if got := refusalCode(t, body); got != string(codes.NotFound) {
			t.Errorf("%s %s: code %q", c.method, c.path, got)
		}
	}
}

// ── the generated vocabulary ────────────────────────────────────────────────

func TestCodeRegistry(t *testing.T) {
	if len(codes.All) != 122 {
		t.Errorf("the vocabulary carries %d codes, the document lists 117 server plus 5 client", len(codes.All))
	}
	var server, client int
	for _, s := range codes.All {
		switch s.Kind {
		case codes.KindServer:
			server++
			if len(s.Statuses) == 0 {
				t.Errorf("%s is a server code with no status", s.Code)
			}
			if !slices.IsSorted(s.Statuses) {
				t.Errorf("%s statuses are not ascending: %v", s.Code, s.Statuses)
			}
		case codes.KindClient:
			client++
			if len(s.Statuses) != 0 {
				t.Errorf("%s is a client code carrying a status: %v", s.Code, s.Statuses)
			}
		}
	}
	if server != 117 || client != 5 {
		t.Errorf("%d server and %d client codes, want 117 and 5", server, client)
	}

	// Spot-check the shape the generator has to get right, including the one
	// code the document raises under two statuses.
	if s, ok := codes.Lookup(codes.BadMemberChallenge); !ok || !slices.Equal(s.Statuses, []int{401, 422}) {
		t.Errorf("bad_member_challenge = %+v", s)
	}
	if _, ok := codes.Status(codes.BadMemberChallenge); ok {
		t.Error("a two-status code reported a single status")
	}
	if s, ok := codes.Lookup(codes.WorkspaceQuotaExhausted); !ok || s.Deterministic {
		t.Errorf("workspace_quota_exhausted should not be deterministic: %+v", s)
	}
	if s, ok := codes.Lookup(codes.AdmissionRefused); !ok || !s.Deterministic {
		t.Errorf("admission_refused should be deterministic: %+v", s)
	}
	if codes.CloseProtocolError != 4400 || codes.CloseInvalidToken != 4401 || codes.CloseNoMembership != 4403 {
		t.Error("signal close codes moved")
	}
}

func ints(t *testing.T, v any) []int {
	t.Helper()
	raw, ok := v.([]any)
	if !ok {
		t.Fatalf("%v is not an array", v)
	}
	out := make([]int, 0, len(raw))
	for _, e := range raw {
		f, ok := e.(float64)
		if !ok {
			t.Fatalf("%v is not a number; class and suite bytes are JSON integers", e)
		}
		out = append(out, int(f))
	}
	if !slices.IsSorted(out) {
		t.Errorf("%v is not ascending", out)
	}
	return out
}

func strs(t *testing.T, v any) []string {
	t.Helper()
	raw, ok := v.([]any)
	if !ok {
		t.Fatalf("%v is not an array", v)
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		s, ok := e.(string)
		if !ok {
			t.Fatalf("%v is not a string", e)
		}
		out = append(out, s)
	}
	return out
}

// ── POST /v1/w/{workspace_id}/ops ───────────────────────────────────────────

type fakeAuth struct{ device [16]byte }

func (a fakeAuth) Device(_ context.Context, bearer string) ([16]byte, bool) {
	if bearer != "good" {
		return [16]byte{}, false
	}
	return a.device, true
}

type openAuthority struct{}

func (openAuthority) Stage2(context.Context, oplog.Tx, oplog.Op) *oplog.Refusal { return nil }
func (openAuthority) Stage4(context.Context, oplog.Tx, oplog.Op, int64) (string, *oplog.Refusal) {
	return "", nil
}
func (openAuthority) PermitsPruneType(context.Context, oplog.Tx, [16]byte, string) *oplog.Refusal {
	return nil
}
func (openAuthority) EstablishesAccess(oplog.Op) bool { return false }

func opsRouter(t *testing.T) (*httpapi.Router, *memstore.Store, [16]byte) {
	t.Helper()
	p := testprofile.Minimal()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	st := memstore.New()
	ws, dev := vectors.WorkspaceID, vectors.MemberA
	st.Seed(ws, func(s memstore.Seeder) {
		s.Exists()
		s.Register(dev,
			wire.KeyID(vectors.SignPub(vectors.LabelDeviceAControl)),
			wire.KeyID(vectors.SignPub(vectors.LabelDeviceAContent)))
	})

	rt := httpapi.NewRouter(httpapi.NewHealth(p, okProbe))
	v1 := http.NewServeMux()
	v1.Handle("POST /w/{workspace_id}/ops", &httpapi.OpsHandler{
		Auth:     fakeAuth{device: dev},
		Pipeline: &oplog.Pipeline{Profile: p, Store: st, Authority: openAuthority{}},
	})
	v1.HandleFunc("/", httpapi.NotFound)
	rt.Contract("v1", v1)
	return rt, st, ws
}

func post(t *testing.T, rt http.Handler, path, token, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("response is not JSON: %v\n%s", err, rec.Body.String())
		}
	}
	return rec.Code, out
}

func signedContent(t *testing.T, seq uint64) string {
	t.Helper()
	h := vectors.Header(wire.ClassContent, wire.SuiteNone, 0, seq,
		vectors.PrevHash(fmt.Sprint(seq)), vectors.ZeroNonce, vectors.LabelDeviceAContent)
	h.OpID = vectors.Bytes16(fmt.Sprintf("http/op/%d", seq))
	body, err := testprofile.Minimal().SizeClasses.PackBody([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	ns, _ := wire.NewNamespace(vectors.Namespace)
	env, err := wire.SignOp(vectors.SignPriv(vectors.LabelDeviceAContent), ns.V1(wire.DocOp), h.Marshal(), body)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(env)
}

func TestOpsRoute(t *testing.T) {
	rt, _, ws := opsRouter(t)
	path := "/v1/w/" + vectors.UUID(ws) + "/ops"
	one := signedContent(t, 1)

	status, body := post(t, rt, path, "good", `{"ops":["`+one+`"]}`)
	if status != http.StatusOK {
		t.Fatalf("status %d, body %v", status, body)
	}
	results, ok := body["results"].([]any)
	if !ok || len(results) != 1 {
		t.Fatalf("results = %v", body["results"])
	}
	first := results[0].(map[string]any)
	if first["seq"] != float64(1) || first["duplicate"] != false {
		t.Errorf("result = %v", first)
	}

	// A repeat returns the position the op already holds.
	_, body = post(t, rt, path, "good", `{"ops":["`+one+`"]}`)
	first = body["results"].([]any)[0].(map[string]any)
	if first["duplicate"] != true || first["seq"] != float64(1) {
		t.Errorf("repeat = %v", first)
	}

	// An empty ops array returns an empty results array and changes nothing.
	status, body = post(t, rt, path, "good", `{"ops":[]}`)
	if status != http.StatusOK || len(body["results"].([]any)) != 0 {
		t.Errorf("empty batch: %d %v", status, body)
	}
}

func TestOpsRouteCredentialPrecedesUnknownField(t *testing.T) {
	rt, _, ws := opsRouter(t)
	path := "/v1/w/" + vectors.UUID(ws) + "/ops"

	// No credential, and a body with an unrecognised field: the credential
	// answers, so the field set is not a free oracle.
	status, body := post(t, rt, path, "", `{"ops":[],"surprise":1}`)
	if status != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", status)
	}
	if got := refusalCode(t, body); got != string(codes.InvalidCredential) {
		t.Errorf("code %q", got)
	}

	// With a credential, the field answers.
	status, body = post(t, rt, path, "good", `{"ops":[],"surprise":1}`)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422", status)
	}
	if got := refusalCode(t, body); got != string(codes.UnknownRequestField) {
		t.Errorf("code %q", got)
	}
}

func TestOpsRouteRefusalsCarryIndex(t *testing.T) {
	rt, _, ws := opsRouter(t)
	path := "/v1/w/" + vectors.UUID(ws) + "/ops"

	status, body := post(t, rt, path, "good", `{"ops":["`+signedContent(t, 1)+`","not base64!!"]}`)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d", status)
	}
	detail := body["detail"].(map[string]any)
	if detail["code"] != "malformed_base64" || detail["index"] != float64(1) {
		t.Errorf("detail = %v", detail)
	}

	// An ops element that is not a string is a body problem, named by path.
	status, body = post(t, rt, path, "good", `{"ops":[1]}`)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d", status)
	}
	detail = body["detail"].(map[string]any)
	if detail["code"] != "malformed_request" {
		t.Errorf("code = %v", detail["code"])
	}
	if fields, _ := detail["fields"].([]any); len(fields) != 1 || fields[0] != "ops.0" {
		t.Errorf("fields = %v", detail["fields"])
	}
}

func TestOpsRouteMalformedWorkspaceID(t *testing.T) {
	rt, _, _ := opsRouter(t)
	status, body := post(t, rt, "/v1/w/NOT-A-UUID/ops", "good", `{"ops":[]}`)
	if status != http.StatusNotFound {
		t.Fatalf("status %d", status)
	}
	if got := refusalCode(t, body); got != string(codes.NotFound) {
		t.Errorf("code %q", got)
	}
}
