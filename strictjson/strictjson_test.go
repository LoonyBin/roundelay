package strictjson_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/loonybin/roundelay/strictjson"
)

func parse(t *testing.T, s string) *strictjson.Body {
	t.Helper()
	b, err := strictjson.Parse([]byte(s))
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return b
}

func unknownFields(t *testing.T, err error) []string {
	t.Helper()
	var e *strictjson.UnknownFields
	if !errors.As(err, &e) {
		t.Fatalf("got %v, want *UnknownFields", err)
	}
	return e.Fields
}

func malformedFields(t *testing.T, err error) []string {
	t.Helper()
	var e *strictjson.Malformed
	if !errors.As(err, &e) {
		t.Fatalf("got %v, want *Malformed", err)
	}
	return e.Fields
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── unknown fields ──────────────────────────────────────────────────────────

// Every offending path in one response, at any depth, with bare decimal indices
// for array positions.
func TestUnknownFieldsAtEveryDepth(t *testing.T) {
	b := parse(t, `{
		"epoch": 3,
		"epoch_note": "x",
		"wraps": [
			{"member_id": "00000000-0000-0000-0000-000000000000", "rotation_hint": 1},
			{"member_id": "00000000-0000-0000-0000-000000000000"}
		],
		"nested": {"known": 1, "deep": {"also_unknown": true}}
	}`)

	o := b.Root()
	o.In("epoch", strictjson.EpochRange)
	wraps := o.Array("wraps")
	for i := range wraps.Len() {
		wraps.Object(i).UUID("member_id")
	}
	nested := o.Object("nested")
	nested.In("known", strictjson.Range{Lo: 0, Hi: 10})
	nested.Object("deep")

	got := unknownFields(t, b.Err())
	want := []string{"epoch_note", "nested.deep.also_unknown", "wraps.0.rotation_hint"}
	if !equal(got, want) {
		t.Errorf("fields = %v, want %v", got, want)
	}
}

// Sorted lexicographically by UTF-8 bytes, which is not numeric order for array
// indices and not case-insensitive order for names.
func TestUnknownFieldsSortOrder(t *testing.T) {
	b := parse(t, `{"items": [{},{},{},{},{},{},{},{},{},{},{"a":1}], "Zed": 1, "alpha": 1}`)
	o := b.Root()
	items := o.Array("items")
	for i := range items.Len() {
		items.Object(i)
	}

	got := unknownFields(t, b.Err())
	want := []string{"Zed", "alpha", "items.10.a"}
	if !equal(got, want) {
		t.Errorf("fields = %v, want %v", got, want)
	}
}

// Numeric-looking indices sort as text: wraps.10 precedes wraps.2.
func TestArrayIndicesSortAsText(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"w":[`)
	for i := range 11 {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"x":1}`)
	}
	sb.WriteString(`]}`)

	b := parse(t, sb.String())
	w := b.Root().Array("w")
	for i := range w.Len() {
		w.Object(i)
	}
	got := unknownFields(t, b.Err())
	if got[0] != "w.0.x" || got[1] != "w.1.x" || got[2] != "w.10.x" || got[3] != "w.2.x" {
		t.Errorf("indices did not sort as text: %v", got[:4])
	}
}

// A member nobody asked for is reported at its own path, and its children are
// not enumerated beside it.
func TestUnvisitedSubtreeReportsOnlyItsRoot(t *testing.T) {
	b := parse(t, `{"known": 1, "surprise": {"a": 1, "b": {"c": 2}}}`)
	b.Root().In("known", strictjson.Range{Lo: 0, Hi: 10})

	got := unknownFields(t, b.Err())
	if !equal(got, []string{"surprise"}) {
		t.Errorf("fields = %v, want [surprise]", got)
	}
}

// ── duplicate keys ──────────────────────────────────────────────────────────

func TestDuplicateKeysAreRefused(t *testing.T) {
	b := parse(t, `{"a": 1, "a": 2, "n": {"b": 1, "b": 2}}`)
	o := b.Root()
	o.In("a", strictjson.Range{Lo: 0, Hi: 10})
	o.Object("n").In("b", strictjson.Range{Lo: 0, Hi: 10})

	got := malformedFields(t, b.Err())
	if !equal(got, []string{"a", "n.b"}) {
		t.Errorf("fields = %v, want [a n.b]", got)
	}
}

// Never last-wins: the reading a duplicate produces is refused rather than
// picked, so the first value is what the tree holds and the request still fails.
func TestDuplicateKeyIsNotResolved(t *testing.T) {
	b := parse(t, `{"limit": 1, "limit": 999}`)
	if got := b.Root().Int("limit", 0, 10); got != 1 {
		t.Errorf("kept %d; the tree should hold the first occurrence", got)
	}
	if _, ok := b.Err().(*strictjson.Malformed); !ok {
		t.Error("a duplicated key was resolved rather than refused")
	}
}

// A duplicate is answered before an unrecognised member: a body with no single
// reading has nothing else worth reporting about it.
func TestDuplicatePrecedesUnknown(t *testing.T) {
	b := parse(t, `{"a": 1, "a": 2, "surprise": 3}`)
	b.Root().In("a", strictjson.Range{Lo: 0, Hi: 10})
	if got := malformedFields(t, b.Err()); !equal(got, []string{"a"}) {
		t.Errorf("fields = %v, want [a]", got)
	}
}

// And an unrecognised member is answered before a malformed value: the first is
// an instruction nobody will carry out.
func TestUnknownPrecedesMalformed(t *testing.T) {
	b := parse(t, `{"epoch": "not a number", "surprise": 1}`)
	b.Root().In("epoch", strictjson.EpochRange)
	if got := unknownFields(t, b.Err()); !equal(got, []string{"surprise"}) {
		t.Errorf("fields = %v, want [surprise]", got)
	}
}

// ── integers ────────────────────────────────────────────────────────────────

func TestIntegerSpellings(t *testing.T) {
	for _, lit := range []string{`1.0`, `1e0`, `1E2`, `0.5`, `"1"`, `true`, `null`, `[]`, `{}`} {
		b := parse(t, `{"n": `+lit+`}`)
		b.Root().Int("n", 0, 1000)
		if got := malformedFields(t, b.Err()); !equal(got, []string{"n"}) {
			t.Errorf("%s was accepted as an integer (fields=%v)", lit, got)
		}
	}
	for _, lit := range []string{`0`, `1`, `-1`, `4294967295`, `9223372036854775807`, `-9223372036854775808`} {
		b := parse(t, `{"n": `+lit+`}`)
		b.Root().Int("n", -1<<63, 1<<63-1)
		if err := b.Err(); err != nil {
			t.Errorf("%s was refused: %v", lit, err)
		}
	}
}

func TestIntegerRangesAreNotClamped(t *testing.T) {
	b := parse(t, `{"epoch": 4294967296}`)
	if got := b.Root().In("epoch", strictjson.EpochRange); got != 0 {
		t.Errorf("returned %d for an out-of-range value; it should yield the zero value and refuse", got)
	}
	if got := malformedFields(t, b.Err()); !equal(got, []string{"epoch"}) {
		t.Errorf("fields = %v, want [epoch]", got)
	}

	// Positions count from 1, so there is no zeroth value to accept.
	b = parse(t, `{"seq": 0}`)
	b.Root().In("seq", strictjson.PositionRange)
	if got := malformedFields(t, b.Err()); !equal(got, []string{"seq"}) {
		t.Errorf("seq 0 was accepted; fields = %v", got)
	}

	// A number too large for a signed 64-bit integer is refused, not truncated.
	b = parse(t, `{"since": 9223372036854775808}`)
	b.Root().In("since", strictjson.SinceRange)
	if got := malformedFields(t, b.Err()); !equal(got, []string{"since"}) {
		t.Errorf("an over-wide integer was accepted; fields = %v", got)
	}
}

// ── binary and textual shapes ───────────────────────────────────────────────

func TestBase64IsStrictAndPadded(t *testing.T) {
	// "QR==" and "QQ==" decode to the same byte under a lenient decoder: the
	// final quantum of the first carries non-zero unused bits.
	for _, s := range []string{`"QR=="`, `"QQ"`, `"QQ="`, `"!!!!"`, `"QUJD REVG"`, `"QUJDRA"`} {
		b := parse(t, `{"k": `+s+`}`)
		b.Root().BytesAny("k")
		if err := b.Err(); err == nil {
			t.Errorf("%s was accepted as strict padded base64", s)
		}
	}
	b := parse(t, `{"k": "QQ=="}`)
	if got := b.Root().BytesAny("k"); len(got) != 1 || got[0] != 'A' {
		t.Errorf("QQ== decoded to %v", got)
	}
	if err := b.Err(); err != nil {
		t.Error(err)
	}
}

func TestBase64ExactLength(t *testing.T) {
	b := parse(t, `{"pk": "QUJD"}`) // 3 bytes
	b.Root().Bytes("pk", 32)
	if got := malformedFields(t, b.Err()); !equal(got, []string{"pk"}) {
		t.Errorf("fields = %v, want [pk]", got)
	}
}

func TestHexIsLowercaseAndExact(t *testing.T) {
	for _, s := range []string{
		`"AABBCC"`, // uppercase
		`"aabb"`,   // short
		`"aabbccdd"`,
		`"zzzzzz"`,
	} {
		b := parse(t, `{"h": `+s+`}`)
		b.Root().Hex("h", 3)
		if err := b.Err(); err == nil {
			t.Errorf("%s was accepted as 3 bytes of lowercase hex", s)
		}
	}
	b := parse(t, `{"h": "aabbcc"}`)
	got := b.Root().Hex("h", 3)
	if err := b.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != 0xaa || got[1] != 0xbb || got[2] != 0xcc {
		t.Errorf("decoded %x", got)
	}
}

func TestUUIDIsCanonicalOnly(t *testing.T) {
	const canonical = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
	for _, s := range []string{
		"{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}",
		"urn:uuid:0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9",
		"0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9",
		"0a1b2c3d4e5f60718293a4b5c6d7e8f9",
		"0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f",
		"0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9 ",
	} {
		if _, err := strictjson.ParseUUID(s); err == nil {
			t.Errorf("%q was accepted as canonical", s)
		}
	}
	id, err := strictjson.ParseUUID(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if strictjson.FormatUUID(id) != canonical {
		t.Errorf("round trip gave %q", strictjson.FormatUUID(id))
	}
}

func TestAuthorityIsRootOrUUID(t *testing.T) {
	b := parse(t, `{"granter": "root"}`)
	if _, isRoot := b.Root().Authority("granter"); !isRoot {
		t.Error(`"root" was not read as root authority`)
	}
	if err := b.Err(); err != nil {
		t.Error(err)
	}

	b = parse(t, `{"granter": "00000000-0000-0000-0000-000000000001"}`)
	id, isRoot := b.Root().Authority("granter")
	if isRoot || id[15] != 1 {
		t.Errorf("a UUID granter read as root=%v id=%x", isRoot, id)
	}

	for _, s := range []string{`"Root"`, `"owner"`, `""`} {
		b = parse(t, `{"granter": `+s+`}`)
		b.Root().Authority("granter")
		if err := b.Err(); err == nil {
			t.Errorf("%s was accepted as an authority", s)
		}
	}
}

func TestTokenShape(t *testing.T) {
	for _, s := range []string{"owner", "a", "0", "a-b-0"} {
		if !strictjson.ValidToken(s) {
			t.Errorf("%q was refused", s)
		}
	}
	for _, s := range []string{"", "-a", "a-", "A", "a_b", "a/b", strings.Repeat("a", 33)} {
		if strictjson.ValidToken(s) {
			t.Errorf("%q was accepted", s)
		}
	}
}

// ── missing members ─────────────────────────────────────────────────────────

// A required member omitted from an object that is present is named at its own
// path — key_ids.control_key_id rather than key_ids.
func TestMissingMemberNamesItsOwnPath(t *testing.T) {
	b := parse(t, `{"key_ids": {"control_key_id": "QUJDRA==", "content_key_id": "QUJDRA=="}}`)
	if ids, ok := b.Root().OptionalObject("key_ids"); ok {
		ids.Bytes("control_key_id", 4)
		ids.Bytes("content_key_id", 4)
		ids.Bytes("kex_key_id", 4)
	}
	if got := malformedFields(t, b.Err()); !equal(got, []string{"key_ids.kex_key_id"}) {
		t.Errorf("fields = %v, want [key_ids.kex_key_id]", got)
	}
}

// Optional as a whole, never member by member: an absent object reports nothing.
func TestOptionalObjectAbsentIsSilent(t *testing.T) {
	b := parse(t, `{"member_id": "00000000-0000-0000-0000-000000000000"}`)
	o := b.Root()
	o.UUID("member_id")
	if ids, ok := o.OptionalObject("key_ids"); ok {
		t.Fatal("OptionalObject reported an absent member as present")
	} else {
		ids.Bytes("control_key_id", 8) // a dead cursor records nothing
	}
	if err := b.Err(); err != nil {
		t.Errorf("an absent optional object produced %v", err)
	}
}

// A required object that is absent is named once, and its members are not
// enumerated underneath it.
func TestMissingRequiredObjectDoesNotCascade(t *testing.T) {
	b := parse(t, `{}`)
	ids := b.Root().Object("key_ids")
	ids.Bytes("control_key_id", 8)
	ids.Bytes("content_key_id", 8)
	if got := malformedFields(t, b.Err()); !equal(got, []string{"key_ids"}) {
		t.Errorf("fields = %v, want [key_ids]", got)
	}
}

// ── syntax ──────────────────────────────────────────────────────────────────

func TestSyntaxFailures(t *testing.T) {
	for _, s := range []string{
		``,
		`{`,
		`{"a": }`,
		`{"a": 1} {"b": 2}`, // two documents in one request
		`{"a": 1}trailing`,
		`{"a": 01}`, // JSON has no leading zeros
		`{"a": +1}`,
	} {
		if _, err := strictjson.Parse([]byte(s)); !errors.Is(err, strictjson.ErrSyntax) {
			t.Errorf("Parse(%q) gave %v, want ErrSyntax", s, err)
		}
	}
	if _, err := strictjson.Parse([]byte{'{', '"', 0xff, '"', ':', '1', '}'}); !errors.Is(err, strictjson.ErrSyntax) {
		t.Error("invalid UTF-8 was accepted")
	}
}

func TestNonObjectRoot(t *testing.T) {
	for _, s := range []string{`1`, `"x"`, `[]`, `null`, `true`} {
		b := parse(t, s)
		b.Root().String("anything")
		if err := b.Err(); err == nil {
			t.Errorf("a %s root was accepted as an object", s)
		}
	}
}

func TestDepthLimit(t *testing.T) {
	deep := strings.Repeat(`{"a":`, strictjson.MaxDepth+5) + `1` + strings.Repeat(`}`, strictjson.MaxDepth+5)
	b, err := strictjson.Parse([]byte(deep))
	if err != nil {
		t.Fatal(err)
	}
	o := b.Root()
	for range strictjson.MaxDepth + 5 {
		o = o.Object("a")
	}
	if b.Err() == nil {
		t.Error("a body nested past MaxDepth was accepted")
	}
}

// ── query strings ───────────────────────────────────────────────────────────

func TestQueryUnknownParameter(t *testing.T) {
	v, _ := url.ParseQuery("since=5&limit=100&surprise=1&another=2")
	q := strictjson.NewQuery(v)
	q.Int("since", strictjson.SinceRange)
	q.Int("limit", strictjson.Range{Lo: 1, Hi: 1000})

	got := unknownFields(t, q.Err())
	if !equal(got, []string{"another", "surprise"}) {
		t.Errorf("fields = %v, want [another surprise]", got)
	}
}

func TestQueryNeverClamps(t *testing.T) {
	v, _ := url.ParseQuery("limit=5000")
	q := strictjson.NewQuery(v)
	if n, ok := q.Int("limit", strictjson.Range{Lo: 1, Hi: 1000}); ok || n != 0 {
		t.Errorf("limit=5000 gave (%d, %v); it must be refused, never clamped", n, ok)
	}
	if got := malformedFields(t, q.Err()); !equal(got, []string{"limit"}) {
		t.Errorf("fields = %v, want [limit]", got)
	}
}

func TestQueryBoolIsExact(t *testing.T) {
	for _, s := range []string{"1", "TRUE", "True", "yes", ""} {
		v, _ := url.ParseQuery("include_reprised=" + s)
		q := strictjson.NewQuery(v)
		q.Bool("include_reprised")
		if err := q.Err(); err == nil {
			t.Errorf("include_reprised=%q was accepted", s)
		}
	}
	for _, c := range []struct {
		s    string
		want bool
	}{{"true", true}, {"false", false}} {
		v, _ := url.ParseQuery("include_reprised=" + c.s)
		q := strictjson.NewQuery(v)
		got, ok := q.Bool("include_reprised")
		if !ok || got != c.want {
			t.Errorf("include_reprised=%s gave (%v,%v)", c.s, got, ok)
		}
		if err := q.Err(); err != nil {
			t.Error(err)
		}
	}
}

// after_epoch has no default value, so absence and after_epoch=0 are different
// requests: epochs start at 0, and no in-range value means "before everything".
func TestQueryPresenceIsDistinctFromZero(t *testing.T) {
	q := strictjson.NewQuery(url.Values{})
	if _, ok := q.Int("after_epoch", strictjson.EpochRange); ok {
		t.Error("an absent after_epoch reported as present")
	}
	v, _ := url.ParseQuery("after_epoch=0")
	q = strictjson.NewQuery(v)
	n, ok := q.Int("after_epoch", strictjson.EpochRange)
	if !ok || n != 0 {
		t.Errorf("after_epoch=0 gave (%d,%v)", n, ok)
	}
}

func TestQueryRepeatedParameter(t *testing.T) {
	v, _ := url.ParseQuery("limit=1&limit=2")
	q := strictjson.NewQuery(v)
	q.Int("limit", strictjson.Range{Lo: 1, Hi: 1000})
	if got := malformedFields(t, q.Err()); !equal(got, []string{"limit"}) {
		t.Errorf("fields = %v, want [limit]", got)
	}
}

// ── an actual request body ──────────────────────────────────────────────────

// POST /v1/members, as Identity §4 shapes it.
func TestMembersRequestBody(t *testing.T) {
	const body = `{
		"member_id": "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9",
		"control_pk": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"content_pk": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"kex_pk":     "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"key_ids": {"control_key_id": "AAECAwQFBgc=",
		            "content_key_id": "AAECAwQFBgc=",
		            "kex_key_id":     "AAECAwQFBgc="},
		"cert_b64": "QUJD",
		"cert_sig_b64": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHw==",
		"root_pk_b64": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	}`

	read := func(raw string) error {
		b := parse(t, raw)
		o := b.Root()
		o.UUID("member_id")
		o.Bytes("control_pk", 32)
		o.Bytes("content_pk", 32)
		o.Bytes("kex_pk", 32)
		if ids, ok := o.OptionalObject("key_ids"); ok {
			ids.Bytes("control_key_id", 8)
			ids.Bytes("content_key_id", 8)
			ids.Bytes("kex_key_id", 8)
		}
		o.BytesAny("cert_b64")
		o.Bytes("cert_sig_b64", 64)
		o.Bytes("root_pk_b64", 32)
		return b.Err()
	}

	if err := read(body); err != nil {
		t.Fatalf("a well-formed body was refused: %v", err)
	}

	// The whole object may be omitted.
	withoutIDs := strings.Replace(body,
		`"key_ids": {"control_key_id": "AAECAwQFBgc=",
		            "content_key_id": "AAECAwQFBgc=",
		            "kex_key_id":     "AAECAwQFBgc="},`, "", 1)
	if err := read(withoutIDs); err != nil {
		t.Errorf("an omitted key_ids was refused: %v", err)
	}

	// An unrecognised member inside it is reported as key_ids.<name>.
	withExtra := strings.Replace(body, `"kex_key_id":     "AAECAwQFBgc="`,
		`"kex_key_id": "AAECAwQFBgc=", "spare_key_id": "AAECAwQFBgc="`, 1)
	if got := unknownFields(t, read(withExtra)); !equal(got, []string{"key_ids.spare_key_id"}) {
		t.Errorf("fields = %v, want [key_ids.spare_key_id]", got)
	}
}
