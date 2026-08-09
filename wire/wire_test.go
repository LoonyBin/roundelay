package wire_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/loonybin/roundelay/internal/vectors"
	"github.com/loonybin/roundelay/wire"
)

var b64 = base64.StdEncoding

func ns(t *testing.T) wire.Namespace {
	t.Helper()
	n, err := wire.NewNamespace(vectors.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func loadVector(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "vectors", name))
	if err != nil {
		t.Fatalf("read vectors/%s: %v (run: go generate ./...)", name, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse vectors/%s: %v", name, err)
	}
	return doc
}

func rows(t *testing.T, doc map[string]any, key string) []map[string]any {
	t.Helper()
	raw, ok := doc[key].([]any)
	if !ok {
		t.Fatalf("vector key %q is not an array", key)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("vector key %q holds a non-object", key)
		}
		out = append(out, m)
	}
	return out
}

func str(t *testing.T, m map[string]any, k string) string {
	t.Helper()
	s, ok := m[k].(string)
	if !ok {
		t.Fatalf("field %q is missing or not a string", k)
	}
	return s
}

func num(t *testing.T, m map[string]any, k string) int {
	t.Helper()
	f, ok := m[k].(float64)
	if !ok {
		t.Fatalf("field %q is missing or not a number", k)
	}
	return int(f)
}

// ── the geometry is literal, and stated here rather than derived ─────────────

// These are the numbers the specification writes down. Asserting them against
// named constants would be a tautology; the point is that the constants equal
// the document.
func TestV1GeometryIsLiteral(t *testing.T) {
	for _, c := range []struct {
		name string
		got  int
		want int
	}{
		{"header", wire.HeaderLen, 158},
		{"signature", wire.SigLen, 64},
		{"overhead", wire.Overhead, 222},
		{"tag", wire.TagLen, 16},
		{"key id", wire.KeyIDLen, 8},
		{"content key", wire.ContentKeyLen, 32},
		{"member wrap", wire.MemberWrapLen, 104},
		{"escrow wrap", wire.EscrowWrapLen, 72},
		{"digest", wire.DigestLen, 32},
		{"nonce", wire.NonceLen, 24},
		{"payload_len prefix", wire.PayloadLenPrefix, 4},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d, the v1 constructions fix it at %d", c.name, c.got, c.want)
		}
	}
	if n := len(wire.CoreDocuments); n != 15 {
		t.Errorf("core domain table has %d documents, Keys §2 closes it at 15", n)
	}
}

// ── framing ─────────────────────────────────────────────────────────────────

// TestFramedIsInjective is the property the length prefix exists for, checked
// without reference to the frozen file: two (domain, rest) pairs whose plain
// concatenation is identical must frame to different bytes.
func TestFramedIsInjective(t *testing.T) {
	a := wire.Framed("acme/op", []byte("/v1|payload"))
	b := wire.Framed("acme/op/v1", []byte("|payload"))
	if bytes.Equal(a, b) {
		t.Fatal("framed() collided on a pair plain concatenation cannot separate")
	}
	// And the literal layout, by hand: length byte, domain, rest.
	want := append([]byte{7}, append([]byte("acme/op"), []byte("/v1|payload")...)...)
	if !bytes.Equal(a, want) {
		t.Errorf("framed() = %x, want %x", a, want)
	}
}

func TestFramedRejectsUnframeableDomain(t *testing.T) {
	for _, d := range []string{"", string(make([]byte, 256))} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("framed() accepted a %d-byte domain", len(d))
				}
			}()
			wire.Framed(d, nil)
		}()
	}
}

func TestFramingVectors(t *testing.T) {
	doc := loadVector(t, "framing.json")
	for _, r := range rows(t, doc, "cases") {
		rest, err := hex.DecodeString(str(t, r, "rest_hex"))
		if err != nil {
			t.Fatal(err)
		}
		got := hex.EncodeToString(wire.Framed(str(t, r, "domain"), rest))
		if want := str(t, r, "framed_hex"); got != want {
			t.Errorf("%s: framed = %s, vector says %s", str(t, r, "name"), got, want)
		}
	}
}

// ── domains ─────────────────────────────────────────────────────────────────

func TestDomainVectors(t *testing.T) {
	n := ns(t)
	doc := loadVector(t, "domains.json")
	for _, r := range rows(t, doc, "core") {
		if got, want := n.V1(str(t, r, "document")), str(t, r, "domain"); got != want {
			t.Errorf("domain for %q = %q, vector says %q", str(t, r, "document"), got, want)
		}
	}
	if got, want := n.ExtDomain(vectors.ExtName), "acme/ext/retention-sweep/v1"; got != want {
		t.Errorf("ext domain = %q, want %q", got, want)
	}
}

// TestExtensionClassesLeaveTheOpDomain is rule 2 of the extension range: an
// extension's ops are not signed under <ns>/op/v1, because a client built
// against one NAME must not be able to verify an op written under another.
func TestExtensionClassesLeaveTheOpDomain(t *testing.T) {
	n := ns(t)
	for _, class := range []byte{0x01, 0x02, 0x45, 0x80, 0x81, 0xBF} {
		if got := n.OpDomain(class, "anything"); got != n.V1(wire.DocOp) {
			t.Errorf("class %#x signs under %q, want the op domain", class, got)
		}
	}
	for _, class := range []byte{0xC0, 0xC5, 0xFF} {
		if got := n.OpDomain(class, "sweep"); got != n.ExtDomain("sweep") {
			t.Errorf("class %#x signs under %q, want the ext domain", class, got)
		}
	}
}

func TestNamespaceValidation(t *testing.T) {
	for _, bad := range []string{"", "-acme", "acme-", "Acme", "acme/p1", "a_b", string(make([]byte, 33))} {
		if _, err := wire.NewNamespace(bad); !errors.Is(err, wire.ErrBadNamespace) {
			t.Errorf("NewNamespace(%q) accepted it", bad)
		}
	}
	for _, ok := range []string{"a", "acme", "acme-p1", "0", "a-0-b"} {
		if _, err := wire.NewNamespace(ok); err != nil {
			t.Errorf("NewNamespace(%q): %v", ok, err)
		}
	}
}

// ── bit 7 ───────────────────────────────────────────────────────────────────

// The single most important boundary in the system, and it is one bit rather
// than a table.
func TestServerReadsIsBitSeven(t *testing.T) {
	for c := 0; c <= 0xFF; c++ {
		class := byte(c)
		if got, want := wire.ServerReads(class), class >= 0x80; got != want {
			t.Fatalf("ServerReads(%#x) = %v, want %v", class, got, want)
		}
		if got, want := wire.IsExtension(class), class >= 0xC0; got != want {
			t.Fatalf("IsExtension(%#x) = %v, want %v", class, got, want)
		}
	}
}

// ── key ids ─────────────────────────────────────────────────────────────────

func TestKeyIDVectors(t *testing.T) {
	doc := loadVector(t, "keyid.json")
	for _, r := range rows(t, doc, "cases") {
		pub, err := b64.DecodeString(str(t, r, "public_key_b64"))
		if err != nil {
			t.Fatal(err)
		}
		id := wire.KeyID(pub)
		if got, want := b64.EncodeToString(id[:]), str(t, r, "key_id_b64"); got != want {
			t.Errorf("%s: key id = %s, vector says %s", str(t, r, "label"), got, want)
		}
		// Independently: the first 8 bytes of SHA-256, spelled out.
		sum := sha256.Sum256(pub)
		if !bytes.Equal(id[:], sum[:8]) {
			t.Errorf("%s: key id is not SHA-256(pk)[:8]", str(t, r, "label"))
		}
	}
}

// ── body framing and padding ────────────────────────────────────────────────

func TestBodyVectors(t *testing.T) {
	l := vectors.Ladder
	doc := loadVector(t, "body.json")

	for _, r := range rows(t, doc, "padding") {
		n := num(t, r, "payload_len")
		body, err := l.PackBody(vectors.Filler(n))
		if err != nil {
			t.Fatal(err)
		}
		if got, want := len(body), num(t, r, "body_len"); got != want {
			t.Errorf("payload %d: body is %d bytes, vector says %d", n, got, want)
		}
		sum := sha256.Sum256(body)
		if got, want := hex.EncodeToString(sum[:]), str(t, r, "body_sha256_hex"); got != want {
			t.Errorf("payload %d: body sha256 = %s, vector says %s", n, got, want)
		}
	}

	for _, r := range rows(t, doc, "legal_body_len") {
		n := num(t, r, "body_len")
		want, _ := r["legal"].(bool)
		if got := l.LegalBodyLen(n); got != want {
			t.Errorf("LegalBodyLen(%d) = %v, vector says %v", n, got, want)
		}
	}
}

// TestPaddingBoundaries pins the class edges by arithmetic rather than by the
// file: the size class must fit payload_len AND the payload, so the last
// payload that fits a 512 class is 508 bytes, not 512.
func TestPaddingBoundaries(t *testing.T) {
	l := vectors.Ladder
	for _, c := range []struct{ payload, body int }{
		{0, 512}, {508, 512}, {509, 4096}, {4092, 4096}, {4093, 8192}, {8188, 8192}, {8189, 12288},
	} {
		got, err := l.BodyLen(c.payload)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.body {
			t.Errorf("BodyLen(%d) = %d, want %d", c.payload, got, c.body)
		}
	}
}

func TestPackUnpackRoundTrip(t *testing.T) {
	l := vectors.Ladder
	for _, n := range []int{0, 1, 508, 509, 4092, 5000} {
		payload := vectors.Filler(n)
		body, err := l.PackBody(payload)
		if err != nil {
			t.Fatal(err)
		}
		got, err := l.UnpackBody(body)
		if err != nil {
			t.Fatalf("payload %d: %v", n, err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("payload %d did not round-trip", n)
		}
	}
}

// The three rules that bind anyone who unpacks a body.
func TestUnpackBodyRefusals(t *testing.T) {
	l := vectors.Ladder

	if _, err := l.UnpackBody(make([]byte, 513)); !errors.Is(err, wire.ErrInvalidBodyLength) {
		t.Errorf("513-byte body: got %v, want invalid body length", err)
	}

	overrun, _ := l.PackBody(nil)
	overrun[0], overrun[1], overrun[2], overrun[3] = 0xFF, 0xFF, 0xFF, 0xFF
	if _, err := l.UnpackBody(overrun); !errors.Is(err, wire.ErrPayloadOverrunsBody) {
		t.Errorf("overrunning payload_len: got %v, want overrun", err)
	}

	dirty, _ := l.PackBody([]byte("hi"))
	dirty[len(dirty)-1] = 1
	if _, err := l.UnpackBody(dirty); !errors.Is(err, wire.ErrNonZeroPadding) {
		t.Errorf("non-zero padding: got %v, want non-zero padding", err)
	}
}

func TestLadderValidation(t *testing.T) {
	for _, bad := range []wire.Ladder{
		{Classes: nil, Step: 4096},
		{Classes: []int{0, 512}, Step: 4096},
		{Classes: []int{4096, 512}, Step: 4096},
		{Classes: []int{512, 512}, Step: 4096},
		{Classes: []int{512}, Step: 0},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("Validate accepted %+v", bad)
		}
	}
	if err := vectors.Ladder.Validate(); err != nil {
		t.Errorf("acme/p1 ladder: %v", err)
	}
	if vectors.Ladder.AmbiguousOversize() {
		t.Error("acme/p1 ladder should not separate the two oversize readings")
	}
	if !(wire.Ladder{Classes: []int{512, 3000}, Step: 1024}).AmbiguousOversize() {
		t.Error("a largest class that is not a multiple of the step should be flagged")
	}
}

// ── envelopes ───────────────────────────────────────────────────────────────

func TestHeaderRoundTrip(t *testing.T) {
	h := vectors.Header(wire.ClassContent, wire.SuiteEncrypted, 3, 2,
		vectors.PrevHash("op/1"), vectors.Nonce("op/2"), vectors.LabelDeviceAContent)
	b := h.Marshal()
	if len(b) != wire.HeaderLen {
		t.Fatalf("marshalled header is %d bytes", len(b))
	}
	got, err := wire.ParseHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != h {
		t.Errorf("header did not round-trip:\n got %+v\nwant %+v", got, h)
	}
	if _, err := wire.ParseHeader(b[:157]); !errors.Is(err, wire.ErrTruncatedEnvelope) {
		t.Errorf("157 bytes: got %v, want truncated", err)
	}
}

// TestHeaderFieldOffsets checks the canonical order against the offsets the
// specification tables, by reading each field back out of the raw bytes.
func TestHeaderFieldOffsets(t *testing.T) {
	h := vectors.Header(0xC5, wire.SuiteEncrypted, 0x01020304, 0x0102030405060708,
		vectors.PrevHash("x"), vectors.Nonce("y"), vectors.LabelDeviceAControl)
	b := h.Marshal()
	check := func(name string, off, size int, want []byte) {
		if !bytes.Equal(b[off:off+size], want) {
			t.Errorf("%s at offset %d: got %x, want %x", name, off, b[off:off+size], want)
		}
	}
	check("op_class", 0, 1, []byte{0xC5})
	check("suite", 1, 1, []byte{0x01})
	check("workspace_id", 2, 16, h.WorkspaceID[:])
	check("key_epoch", 18, 4, []byte{0x01, 0x02, 0x03, 0x04})
	check("op_id", 22, 16, h.OpID[:])
	check("author_member_id", 38, 16, h.AuthorMemberID[:])
	check("author_key_id", 54, 8, h.AuthorKeyID[:])
	check("author_seq", 62, 8, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	check("prev_author_hash", 70, 32, h.PrevAuthorHash[:])
	check("observed_head", 102, 32, make([]byte, 32))
	check("nonce", 134, 24, h.Nonce[:])
}

func TestEnvelopeVectors(t *testing.T) {
	n := ns(t)
	l := vectors.Ladder
	doc := loadVector(t, "envelope.json")

	for _, r := range rows(t, doc, "envelopes") {
		name := str(t, r, "name")
		want, err := b64.DecodeString(str(t, r, "envelope_b64"))
		if err != nil {
			t.Fatal(err)
		}

		e, err := wire.ParseEnvelope(want)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := len(want); got != num(t, r, "envelope_len") {
			t.Errorf("%s: envelope is %d bytes, vector says %d", name, got, num(t, r, "envelope_len"))
		}
		if got, want := hex.EncodeToString(e.Header.Marshal()), str(t, r, "header_hex"); got != want {
			t.Errorf("%s: header = %s, vector says %s", name, got, want)
		}

		domain := str(t, r, "signing_domain")
		if got := n.OpDomain(e.Header.OpClass, vectors.ExtName); got != domain {
			t.Errorf("%s: OpDomain says %q, vector says %q", name, got, domain)
		}

		// The signing input is over the SEALED body under suite 0x01.
		input := wire.OpSigningInput(domain, e.Header.Marshal(), e.Body)
		sum := sha256.Sum256(input)
		if got, want := hex.EncodeToString(sum[:]), str(t, r, "signing_input_sha256_hex"); got != want {
			t.Errorf("%s: signing input sha256 = %s, vector says %s", name, got, want)
		}

		eh := wire.EnvelopeHash(want)
		if got, w := hex.EncodeToString(eh[:]), str(t, r, "envelope_hash_hex"); got != w {
			t.Errorf("%s: envelope hash = %s, vector says %s", name, got, w)
		}

		// The body's length is derived, not declared, and must be a legal class
		// for the suite the header names.
		bodyLen := len(e.Body)
		if e.Header.Suite == wire.SuiteEncrypted {
			bodyLen -= wire.TagLen
		}
		if !l.LegalBodyLen(bodyLen) {
			t.Errorf("%s: plaintext body length %d is not a legal size class", name, bodyLen)
		}

		// Every envelope in the corpus verifies under the key its author_key_id names.
		label := vectors.LabelDeviceAContent
		if wire.ServerReads(e.Header.OpClass) {
			label = vectors.LabelDeviceAControl
		}
		if !wire.VerifyOp(vectors.SignPub(label), domain, e) {
			t.Errorf("%s: signature does not verify", name)
		}
	}
}

// TestSealedEnvelopeOpens closes the loop the vectors cannot: the sealed op's
// body must decrypt, under the header as associated data, to the same padded
// plaintext the plaintext op carries.
func TestSealedEnvelopeOpens(t *testing.T) {
	n := ns(t)
	l := vectors.Ladder
	payload := []byte("hello roundelay")

	h := vectors.Header(wire.ClassContent, wire.SuiteEncrypted, 3, 2,
		vectors.PrevHash("op/1"), vectors.Nonce("op/2"), vectors.LabelDeviceAContent)
	plaintext, err := l.PackBody(payload)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := wire.SealBody(h.Marshal(), vectors.ContentKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != len(plaintext)+wire.TagLen {
		t.Fatalf("sealed body is %d bytes, want %d", len(sealed), len(plaintext)+wire.TagLen)
	}

	opened, err := wire.OpenBody(h.Marshal(), vectors.ContentKey, sealed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := l.UnpackBody(opened)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("sealed body did not round-trip to its payload")
	}

	// The literal header is the associated data, so changing any header byte —
	// here the epoch — must stop the body opening, with no second binding to keep
	// in step.
	tampered := h
	tampered.KeyEpoch = 4
	if _, err := wire.OpenBody(tampered.Marshal(), vectors.ContentKey, sealed); !errors.Is(err, wire.ErrOpen) {
		t.Errorf("body opened under a tampered header: %v", err)
	}

	// And the signature is over the sealed bytes, so a flipped ciphertext byte
	// fails the signature rather than reaching the AEAD at all.
	env, err := wire.SignOp(vectors.SignPriv(vectors.LabelDeviceAContent), n.V1(wire.DocOp), h.Marshal(), sealed)
	if err != nil {
		t.Fatal(err)
	}
	env[wire.HeaderLen] ^= 0x01
	e, err := wire.ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	if wire.VerifyOp(vectors.SignPub(vectors.LabelDeviceAContent), n.V1(wire.DocOp), e) {
		t.Error("a tampered ciphertext still verified")
	}
}

// TestSignatureIsDomainBound is what the fifteen domains buy: the same bytes
// signed for one document must not verify as another.
func TestSignatureIsDomainBound(t *testing.T) {
	n := ns(t)
	cert := []byte(vectors.GrantCert)
	sig := ed25519.Sign(vectors.SignPriv(vectors.LabelRoot), n.CertSigningInput(wire.DocGrant, cert))

	if !ed25519.Verify(vectors.SignPub(vectors.LabelRoot), n.CertSigningInput(wire.DocGrant, cert), sig) {
		t.Fatal("grant signature does not verify under its own domain")
	}
	for _, other := range []string{wire.DocRevoke, wire.DocRoleTable, wire.DocDelegate, wire.DocMemberRegister} {
		if ed25519.Verify(vectors.SignPub(vectors.LabelRoot), n.CertSigningInput(other, cert), sig) {
			t.Errorf("a grant signature verified as a %s", other)
		}
	}
	// And across namespaces: two deployments' signatures must not verify against
	// each other, which is why the namespace must be globally unique.
	other, err := wire.NewNamespace("other")
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(vectors.SignPub(vectors.LabelRoot), other.CertSigningInput(wire.DocGrant, cert), sig) {
		t.Error("a signature crossed the namespace boundary")
	}
}

func TestControlChainHashIsOverThePayload(t *testing.T) {
	doc := loadVector(t, "envelope.json")
	cc, ok := doc["control_chain"].(map[string]any)
	if !ok {
		t.Fatal("envelope.json has no control_chain")
	}
	h := wire.PayloadHash([]byte(vectors.ControlPayload))
	if got, want := hex.EncodeToString(h[:]), str(t, cc, "prev_control_hash_hex"); got != want {
		t.Errorf("prev_control_hash = %s, vector says %s", got, want)
	}
	// Bare SHA-256, not framed: the link identifies bytes, it does not
	// authenticate them.
	sum := sha256.Sum256([]byte(vectors.ControlPayload))
	if !bytes.Equal(h[:], sum[:]) {
		t.Error("prev_control_hash is not bare SHA-256 over the payload")
	}
}

// ── key plane ───────────────────────────────────────────────────────────────

func TestKeyplaneVectors(t *testing.T) {
	n := ns(t)
	doc := loadVector(t, "keyplane.json")
	ws := vectors.WorkspaceID
	epoch := uint32(num(t, doc, "epoch"))

	key, err := b64.DecodeString(str(t, doc, "content_key_b64"))
	if err != nil {
		t.Fatal(err)
	}
	var contentKey [32]byte
	copy(contentKey[:], key)

	entries := make([]wire.WrapEntry, 0, 2)
	for _, r := range rows(t, doc, "member_wraps") {
		label := str(t, r, "label")
		kexLabel := vectors.LabelDeviceAKex
		memberID := vectors.MemberA
		ephLabel, nonceLabel := "keywrap/ephemeral/a", "keywrap/nonce/a"
		if label == "device_b" {
			kexLabel, memberID = vectors.LabelDeviceBKex, vectors.MemberB
			ephLabel, nonceLabel = "keywrap/ephemeral/b", "keywrap/nonce/b"
		}

		kexPub := vectors.KexPub(kexLabel)
		p := wire.MemberWrapParams{
			Namespace: n, WorkspaceID: ws, Epoch: epoch,
			MemberID: memberID, KexKeyID: wire.KeyID(kexPub), KexPub: kexPub,
		}
		got, err := wire.SealMemberWrap(p, vectors.KexPriv(ephLabel), vectors.Nonce(nonceLabel), contentKey)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != wire.MemberWrapLen {
			t.Errorf("%s: wrap is %d bytes, the construction fixes it at 104", label, len(got))
		}
		if b64.EncodeToString(got) != str(t, r, "wrap_b64") {
			t.Errorf("%s: member wrap does not match the vector", label)
		}

		// It opens under the device's own sealing key, and only under that key.
		opened, err := wire.OpenMemberWrap(p, vectors.KexPriv(kexLabel), got)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if opened != contentKey {
			t.Errorf("%s: wrap opened to the wrong key", label)
		}
		wrong := p
		wrong.Epoch = epoch + 1
		if _, err := wire.OpenMemberWrap(wrong, vectors.KexPriv(kexLabel), got); !errors.Is(err, wire.ErrOpen) {
			t.Errorf("%s: wrap opened at the wrong epoch", label)
		}

		entries = append(entries, wire.WrapEntry{MemberID: memberID, KexKeyID: p.KexKeyID, Wrap: got})
	}

	esc, ok := doc["escrow_wrap"].(map[string]any)
	if !ok {
		t.Fatal("keyplane.json has no escrow_wrap")
	}
	escrow, err := wire.SealEscrowWrap(n, ws, epoch, vectors.MasterWrapKey, vectors.Nonce("escrow/nonce/3"), contentKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(escrow) != wire.EscrowWrapLen {
		t.Errorf("escrow wrap is %d bytes, the construction fixes it at 72", len(escrow))
	}
	if b64.EncodeToString(escrow) != str(t, esc, "escrow_wrap_b64") {
		t.Error("escrow wrap does not match the vector")
	}
	opened, err := wire.OpenEscrowWrap(n, ws, epoch, vectors.MasterWrapKey, escrow)
	if err != nil {
		t.Fatal(err)
	}
	if opened != contentKey {
		t.Error("escrow wrap opened to the wrong key")
	}

	dg, ok := doc["keywrap_digest"].(map[string]any)
	if !ok {
		t.Fatal("keyplane.json has no keywrap_digest")
	}
	digest, err := wire.KeywrapDigest(n, epoch, entries, escrow)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := b64.EncodeToString(digest[:]), str(t, dg, "digest_b64"); got != want {
		t.Errorf("keywrap digest = %s, vector says %s", got, want)
	}
}

// TestKeywrapDigestSortKey is the diagnostic the device fixtures cannot be: it
// uses ids chosen so that the raw-unsigned-bytes ordering the specification
// fixes disagrees with the base64 spelling and with a signed 64-bit comparison.
// An implementation that sorts either of those other ways computes a different
// digest here, and a Workspace that ships it becomes permanently unrotatable.
func TestKeywrapDigestSortKey(t *testing.T) {
	n := ns(t)
	doc := loadVector(t, "keyplane.json")
	ord, ok := doc["keywrap_digest_ordering"].(map[string]any)
	if !ok {
		t.Fatal("keyplane.json has no keywrap_digest_ordering")
	}
	epoch := uint32(num(t, ord, "epoch"))

	entries := make([]wire.WrapEntry, 0, len(vectors.OrderingSet))
	for _, e := range vectors.OrderingSet {
		entries = append(entries, wire.WrapEntry{MemberID: e.MemberID, KexKeyID: e.KexKeyID, Wrap: e.Wrap})
	}

	want, err := wire.KeywrapDigest(n, epoch, entries, vectors.OrderingEscrow)
	if err != nil {
		t.Fatal(err)
	}
	if v := str(t, ord, "digest_b64"); b64.EncodeToString(want[:]) != v {
		t.Errorf("ordering digest = %s, vector says %s", b64.EncodeToString(want[:]), v)
	}

	// The preimage, rebuilt here by hand from the specification's own text, so
	// that this test checks the construction rather than re-running it. Each
	// candidate ordering is fed through the same arithmetic; only the order of
	// the per-member block changes.
	digestUnder := func(order []vectors.OrderingEntry) [32]byte {
		var epochBE, countBE [4]byte
		binary.BigEndian.PutUint32(epochBE[:], epoch)
		binary.BigEndian.PutUint32(countBE[:], uint32(len(order)))
		var rest []byte
		rest = append(rest, epochBE[:]...)
		rest = append(rest, countBE[:]...)
		for _, e := range order {
			h := sha256.Sum256(e.Wrap)
			rest = append(rest, e.MemberID[:]...)
			rest = append(rest, e.KexKeyID[:]...)
			rest = append(rest, h[:]...)
		}
		eh := sha256.Sum256(vectors.OrderingEscrow)
		rest = append(rest, eh[:]...)
		return sha256.Sum256(wire.Framed(n.V1(wire.DocKeywrapDigest), rest))
	}

	byRaw := sortedCopy(vectors.OrderingSet, func(a, b vectors.OrderingEntry) int {
		if c := bytes.Compare(a.MemberID[:], b.MemberID[:]); c != 0 {
			return c
		}
		return bytes.Compare(a.KexKeyID[:], b.KexKeyID[:])
	})
	byB64 := sortedCopy(vectors.OrderingSet, func(a, b vectors.OrderingEntry) int {
		if c := strings.Compare(b64.EncodeToString(a.MemberID[:]), b64.EncodeToString(b.MemberID[:])); c != 0 {
			return c
		}
		return strings.Compare(b64.EncodeToString(a.KexKeyID[:]), b64.EncodeToString(b.KexKeyID[:]))
	})
	bySigned := sortedCopy(vectors.OrderingSet, func(a, b vectors.OrderingEntry) int {
		// A platform UUID type comparing two signed 64-bit halves.
		ah, bh := int64(binary.BigEndian.Uint64(a.MemberID[:8])), int64(binary.BigEndian.Uint64(b.MemberID[:8]))
		if ah != bh {
			return int(ah>>62 - bh>>62)
		}
		return bytes.Compare(a.KexKeyID[:], b.KexKeyID[:])
	})

	if got := digestUnder(byRaw); got != want {
		t.Error("the raw-unsigned-bytes ordering does not reproduce KeywrapDigest")
	}
	for _, c := range []struct {
		name  string
		order []vectors.OrderingEntry
	}{
		{"base64 spelling", byB64},
		{"signed 64-bit halves", bySigned},
	} {
		if labels(c.order) == labels(byRaw) {
			t.Fatalf("the ordering fixture is not diagnostic: %s agrees with raw bytes (%v)", c.name, labels(byRaw))
		}
		if digestUnder(c.order) == want {
			t.Errorf("sorting by %s produced the same digest; the vector cannot catch it", c.name)
		}
	}
}

func sortedCopy(s []vectors.OrderingEntry, cmp func(a, b vectors.OrderingEntry) int) []vectors.OrderingEntry {
	out := append([]vectors.OrderingEntry(nil), s...)
	slices.SortStableFunc(out, cmp)
	return out
}

func labels(s []vectors.OrderingEntry) string {
	out := ""
	for _, e := range s {
		out += e.Label + " "
	}
	return out
}

// TestKeywrapDigestDescribesTheSet is the property the sort exists for: the
// digest must not depend on the order the server happened to receive the wraps
// in, and must depend on every byte of every wrap.
func TestKeywrapDigestDescribesTheSet(t *testing.T) {
	n := ns(t)
	ws, epoch := vectors.WorkspaceID, uint32(3)
	escrow, err := wire.SealEscrowWrap(n, ws, epoch, vectors.MasterWrapKey, vectors.Nonce("escrow/nonce/3"), vectors.ContentKey)
	if err != nil {
		t.Fatal(err)
	}

	mk := func(memberID [16]byte, kexLabel, ephLabel, nonceLabel string) wire.WrapEntry {
		kexPub := vectors.KexPub(kexLabel)
		p := wire.MemberWrapParams{
			Namespace: n, WorkspaceID: ws, Epoch: epoch,
			MemberID: memberID, KexKeyID: wire.KeyID(kexPub), KexPub: kexPub,
		}
		w, err := wire.SealMemberWrap(p, vectors.KexPriv(ephLabel), vectors.Nonce(nonceLabel), vectors.ContentKey)
		if err != nil {
			t.Fatal(err)
		}
		return wire.WrapEntry{MemberID: memberID, KexKeyID: p.KexKeyID, Wrap: w}
	}
	a := mk(vectors.MemberA, vectors.LabelDeviceAKex, "keywrap/ephemeral/a", "keywrap/nonce/a")
	b := mk(vectors.MemberB, vectors.LabelDeviceBKex, "keywrap/ephemeral/b", "keywrap/nonce/b")

	forward, err := wire.KeywrapDigest(n, epoch, []wire.WrapEntry{a, b}, escrow)
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := wire.KeywrapDigest(n, epoch, []wire.WrapEntry{b, a}, escrow)
	if err != nil {
		t.Fatal(err)
	}
	if forward != reverse {
		t.Error("keywrap digest depends on input order; it must describe the set")
	}

	// A curated set — one member dropped, or one wrap altered — must not hash to
	// the same commitment. That is the whole of what the digest is for.
	short, err := wire.KeywrapDigest(n, epoch, []wire.WrapEntry{a}, escrow)
	if err != nil {
		t.Fatal(err)
	}
	if short == forward {
		t.Error("dropping a member left the digest unchanged")
	}
	altered := b
	altered.Wrap = append([]byte(nil), b.Wrap...)
	altered.Wrap[0] ^= 0x01
	tampered, err := wire.KeywrapDigest(n, epoch, []wire.WrapEntry{a, altered}, escrow)
	if err != nil {
		t.Fatal(err)
	}
	if tampered == forward {
		t.Error("altering a wrap left the digest unchanged")
	}
	if _, err := wire.KeywrapDigest(n, epoch, []wire.WrapEntry{a, a}, escrow); !errors.Is(err, wire.ErrDuplicateWrapEntry) {
		t.Error("a duplicate (member, key) pair was admitted into a digest")
	}
}

// ── auth and vault ──────────────────────────────────────────────────────────

func TestAuthAndVaultVectors(t *testing.T) {
	n := ns(t)
	doc := loadVector(t, "auth.json")

	ac, ok := doc["auth_challenge"].(map[string]any)
	if !ok {
		t.Fatal("auth.json has no auth_challenge")
	}
	nonce := vectors.Bytes32("challenge/nonce/1")
	input := n.AuthChallengeInput(vectors.MemberA, nonce[:])
	if got, want := hex.EncodeToString(input), str(t, ac, "signing_input_hex"); got != want {
		t.Errorf("auth challenge input = %s, vector says %s", got, want)
	}
	sig, err := b64.DecodeString(str(t, ac, "signature_b64"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(vectors.SignPub(vectors.LabelDeviceAControl), input, sig) {
		t.Error("auth challenge signature does not verify")
	}
	// The member id is bound so a captured signature cannot be replayed into
	// another device's pending challenge.
	if ed25519.Verify(vectors.SignPub(vectors.LabelDeviceAControl), n.AuthChallengeInput(vectors.MemberB, nonce[:]), sig) {
		t.Error("an auth challenge signature replayed into another member's slot")
	}

	vt, ok := doc["vault"].(map[string]any)
	if !ok {
		t.Fatal("auth.json has no vault")
	}
	locator := vectors.Bytes32("vault/locator/1")
	blob, err := b64.DecodeString(str(t, vt, "blob_b64"))
	if err != nil {
		t.Fatal(err)
	}
	vinput := n.VaultInput(locator, uint64(num(t, vt, "version")), blob)
	vsig, err := b64.DecodeString(str(t, vt, "root_sig_b64"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(vectors.SignPub(vectors.LabelRoot), vinput, vsig) {
		t.Error("vault signature does not verify")
	}
	// The locator is inside the signed bytes, so a record signed for one slot
	// cannot be replayed into another.
	other := vectors.Bytes32("vault/locator/2")
	if ed25519.Verify(vectors.SignPub(vectors.LabelRoot), n.VaultInput(other, 1, blob), vsig) {
		t.Error("a vault record replayed into another slot")
	}
	// And the version, so a record cannot be rolled back under its own signature.
	if ed25519.Verify(vectors.SignPub(vectors.LabelRoot), n.VaultInput(locator, 2, blob), vsig) {
		t.Error("a vault signature covered a different version")
	}
}
