// Command vectorgen writes the frozen test vectors in ../../vectors.
//
// Run it with `go generate ./...` or `go run ./internal/vectorgen`. It is
// deterministic: every byte of key material is derived from a label by
// Seed below, so a second implementation can regenerate the whole corpus from
// the labels alone and compare, rather than taking this one's word for it.
//
// Regenerating and committing a diff is a change to the cross-implementation
// contract. Review it as one.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/loonybin/roundelay/internal/vectors"
	"github.com/loonybin/roundelay/wire"
)

// b64 is the encoding the protocol uses on the wire: standard, padded, and
// validated strictly on the way back in.
var b64 = base64.StdEncoding

func main() {
	out := "vectors"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		log.Fatal(err)
	}

	ns, err := wire.NewNamespace(vectors.Namespace)
	if err != nil {
		log.Fatal(err)
	}

	files := map[string]any{
		"domains.json":  buildDomains(ns),
		"framing.json":  buildFraming(ns),
		"keyid.json":    buildKeyIDs(),
		"body.json":     buildBody(),
		"envelope.json": buildEnvelopes(ns),
		"keyplane.json": buildKeyplane(ns),
		"auth.json":     buildAuth(ns),
	}

	for name, doc := range files {
		b, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			log.Fatalf("%s: %v", name, err)
		}
		b = append(b, '\n')
		if err := os.WriteFile(filepath.Join(out, name), b, 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("wrote %s (%d bytes)\n", filepath.Join(out, name), len(b))
	}
}

// ── domains ──────────────────────────────────────────────────────────────────

func buildDomains(ns wire.Namespace) any {
	type row struct {
		Document string `json:"document"`
		Domain   string `json:"domain"`
	}
	core := make([]row, 0, len(wire.CoreDocuments))
	for _, d := range wire.CoreDocuments {
		core = append(core, row{Document: d, Domain: ns.V1(d)})
	}
	return map[string]any{
		"note": "The fifteen fixed core domains, plus the open ext family. " +
			"A core domain is <namespace>/<document>/v<n>; an extension class signs " +
			"under <namespace>/ext/<name>/v1 instead, one domain per enabled NAME.",
		"namespace":    string(ns),
		"core":         core,
		"core_count":   len(core),
		"ext_examples": []row{{Document: "ext:" + vectors.ExtName, Domain: ns.ExtDomain(vectors.ExtName)}},
		"op_class_to_domain": []map[string]string{
			{"op_class": "1", "domain": ns.OpDomain(0x01, "")},
			{"op_class": "128", "domain": ns.OpDomain(0x80, "")},
			{"op_class": "191", "domain": ns.OpDomain(0xBF, "")},
			{"op_class": "197", "domain": ns.OpDomain(0xC5, vectors.ExtName)},
		},
	}
}

// ── framing ──────────────────────────────────────────────────────────────────

func buildFraming(ns wire.Namespace) any {
	type row struct {
		Name      string `json:"name"`
		Domain    string `json:"domain"`
		DomainLen int    `json:"domain_len"`
		RestHex   string `json:"rest_hex"`
		FramedHex string `json:"framed_hex"`
	}
	mk := func(name, domain string, rest []byte) row {
		return row{
			Name:      name,
			Domain:    domain,
			DomainLen: len(domain),
			RestHex:   hex.EncodeToString(rest),
			FramedHex: hex.EncodeToString(wire.Framed(domain, rest)),
		}
	}
	return map[string]any{
		"note": "framed(domain, rest) = [1 byte: len(domain)] [domain] [rest]. " +
			"The length prefix is what makes the construction injective: the collision " +
			"pair below is the case plain concatenation gets wrong.",
		"cases": []row{
			mk("empty_rest", ns.V1(wire.DocOp), nil),
			mk("one_byte", ns.V1(wire.DocOp), []byte{0x00}),
			mk("digit_leading_rest", ns.V1(wire.DocVault), []byte("2foo")),
			mk("collision_a", "acme/op", []byte("/v1|payload")),
			mk("collision_b", "acme/op/v1", []byte("|payload")),
		},
		"collision_note": "collision_a and collision_b concatenate to identical bytes " +
			"without the length prefix and to distinct bytes with it. An implementation " +
			"whose framed_hex values match for those two rows has dropped the prefix.",
	}
}

// ── key ids ──────────────────────────────────────────────────────────────────

func buildKeyIDs() any {
	type row struct {
		Label    string `json:"label"`
		Kind     string `json:"kind"`
		PubB64   string `json:"public_key_b64"`
		KeyIDB64 string `json:"key_id_b64"`
		KeyIDHex string `json:"key_id_hex"`
	}
	rows := []row{}
	add := func(label, kind string, pub []byte) {
		id := wire.KeyID(pub)
		rows = append(rows, row{
			Label: label, Kind: kind,
			PubB64:   b64.EncodeToString(pub),
			KeyIDB64: b64.EncodeToString(id[:]),
			KeyIDHex: hex.EncodeToString(id[:]),
		})
	}
	add(vectors.LabelDeviceAControl, "ed25519", vectors.SignPub(vectors.LabelDeviceAControl))
	add(vectors.LabelDeviceAContent, "ed25519", vectors.SignPub(vectors.LabelDeviceAContent))
	add(vectors.LabelDeviceAKex, "x25519", vectors.KexPub(vectors.LabelDeviceAKex))
	add(vectors.LabelDeviceBKex, "x25519", vectors.KexPub(vectors.LabelDeviceBKex))
	add(vectors.LabelRoot, "ed25519", vectors.SignPub(vectors.LabelRoot))

	return map[string]any{
		"note": "key_id = the first 8 bytes of SHA-256 over the public key. " +
			"Always derived by the server; a client's claim is cross-checked and discarded.",
		"cases": rows,
	}
}

// ── body framing and padding ─────────────────────────────────────────────────

func buildBody() any {
	l := vectors.Ladder

	type padRow struct {
		PayloadLen  int    `json:"payload_len"`
		BodyLen     int    `json:"body_len"`
		SealedLen   int    `json:"sealed_body_len"`
		PayloadHex  string `json:"payload_hex,omitempty"`
		BodyHeadHex string `json:"body_first_16_hex"`
		BodySHA256  string `json:"body_sha256_hex"`
	}
	pads := []padRow{}
	for _, n := range []int{0, 1, 507, 508, 509, 4091, 4092, 4093, 8188} {
		payload := vectors.Filler(n)
		body, err := l.PackBody(payload)
		if err != nil {
			log.Fatal(err)
		}
		sum := sha256.Sum256(body)
		head := body
		if len(head) > 16 {
			head = head[:16]
		}
		r := padRow{
			PayloadLen:  n,
			BodyLen:     len(body),
			SealedLen:   len(body) + wire.TagLen,
			BodyHeadHex: hex.EncodeToString(head),
			BodySHA256:  hex.EncodeToString(sum[:]),
		}
		if n <= 8 {
			r.PayloadHex = hex.EncodeToString(payload)
		}
		pads = append(pads, r)
	}

	legal := []map[string]any{}
	for _, n := range []int{0, 4, 511, 512, 513, 1024, 4095, 4096, 4097, 8192, 12288, 12289} {
		legal = append(legal, map[string]any{"body_len": n, "legal": l.LegalBodyLen(n)})
	}

	// The oversize step has two available readings. They agree for every ladder
	// whose largest class is a multiple of the step, and this one is; the second
	// ladder below is the case that separates them, recorded rather than decided.
	amb := wire.Ladder{Classes: []int{512, 3000}, Step: 1024}
	ambFromZero, _ := amb.BodyLen(3000)

	return map[string]any{
		"note": "Body = payload_len (u32 big-endian) || payload || zero padding to a size class. " +
			"Above the largest class, to the next multiple of the oversize step. " +
			"Under suite 0x01 the on-wire body is 16 bytes longer than the class it padded to.",
		"ladder": map[string]any{
			"classes":            l.Classes,
			"oversize_step":      l.Step,
			"ambiguous_oversize": l.AmbiguousOversize(),
		},
		"payload_filler": "byte i of a payload of length n is (i mod 251), so every " +
			"vector's payload is reproducible from its length alone.",
		"padding":          pads,
		"legal_body_len":   legal,
		"min_envelope_len": map[string]int{"suite_0x00": l.MinEnvelopeLen(0x00), "suite_0x01": l.MinEnvelopeLen(0x01)},
		"ambiguous_ladder_note": map[string]any{
			"warning": "NOT a conformance vector. This ladder separates the two readings of " +
				"'above the largest, to the next multiple of a fixed step', and the core does " +
				"not say which is meant. A profile should not choose a ladder whose largest " +
				"class is not a multiple of its step.",
			"classes":                    amb.Classes,
			"oversize_step":              amb.Step,
			"payload_len":                3000,
			"reading_multiple_of_step":   ambFromZero,
			"reading_largest_plus_step":  amb.Largest() + amb.Step,
			"this_implementation_writes": ambFromZero,
		},
	}
}

// ── envelopes ────────────────────────────────────────────────────────────────

func buildEnvelopes(ns wire.Namespace) any {
	type row struct {
		Name            string         `json:"name"`
		Header          map[string]any `json:"header"`
		HeaderHex       string         `json:"header_hex"`
		SigningDomain   string         `json:"signing_domain"`
		PayloadHex      string         `json:"payload_hex,omitempty"`
		PayloadUTF8     string         `json:"payload_utf8,omitempty"`
		PayloadSHA256   string         `json:"payload_sha256_hex,omitempty"`
		ContentKeyB64   string         `json:"content_key_b64,omitempty"`
		SigningInputSHA string         `json:"signing_input_sha256_hex"`
		SignatureB64    string         `json:"signature_b64"`
		EnvelopeLen     int            `json:"envelope_len"`
		EnvelopeB64     string         `json:"envelope_b64"`
		EnvelopeHashHex string         `json:"envelope_hash_hex"`
	}

	build := func(name string, h wire.Header, payload []byte, signLabel string, extName string, key *[32]byte) row {
		l := vectors.Ladder
		plaintext, err := l.PackBody(payload)
		if err != nil {
			log.Fatal(err)
		}
		body := plaintext
		hdr := h.Marshal()
		if h.Suite == wire.SuiteEncrypted {
			body, err = wire.SealBody(hdr, *key, plaintext)
			if err != nil {
				log.Fatal(err)
			}
		}
		domain := ns.OpDomain(h.OpClass, extName)
		input := wire.OpSigningInput(domain, hdr, body)
		inputSum := sha256.Sum256(input)

		env, err := wire.SignOp(vectors.SignPriv(signLabel), domain, hdr, body)
		if err != nil {
			log.Fatal(err)
		}
		eh := wire.EnvelopeHash(env)

		r := row{
			Name:            name,
			Header:          headerJSON(h),
			HeaderHex:       hex.EncodeToString(hdr),
			SigningDomain:   domain,
			SigningInputSHA: hex.EncodeToString(inputSum[:]),
			SignatureB64:    b64.EncodeToString(env[len(env)-wire.SigLen:]),
			EnvelopeLen:     len(env),
			EnvelopeB64:     b64.EncodeToString(env),
			EnvelopeHashHex: hex.EncodeToString(eh[:]),
		}
		if wire.ServerReads(h.OpClass) {
			// Server-read payloads are plaintext JSON for ever, so showing them is
			// showing what the server actually parses.
			r.PayloadUTF8 = string(payload)
			ph := wire.PayloadHash(payload)
			r.PayloadSHA256 = hex.EncodeToString(ph[:])
		} else {
			r.PayloadHex = hex.EncodeToString(payload)
		}
		if key != nil {
			r.ContentKeyB64 = b64.EncodeToString(key[:])
		}
		return r
	}

	contentKey := vectors.ContentKey
	rows := []row{
		build("content_plaintext",
			vectors.Header(wire.ClassContent, wire.SuiteNone, 0, 1, vectors.ZeroHash, vectors.ZeroNonce,
				vectors.LabelDeviceAContent),
			[]byte("hello roundelay"), vectors.LabelDeviceAContent, "", nil),

		build("content_sealed",
			vectors.Header(wire.ClassContent, wire.SuiteEncrypted, 3, 2, vectors.PrevHash("op/1"), vectors.Nonce("op/2"),
				vectors.LabelDeviceAContent),
			[]byte("hello roundelay"), vectors.LabelDeviceAContent, "", &contentKey),

		build("control_grant",
			vectors.Header(wire.ClassControl, wire.SuiteNone, 0, 3, vectors.PrevHash("op/2"), vectors.ZeroNonce,
				vectors.LabelDeviceAControl),
			[]byte(vectors.ControlPayload), vectors.LabelDeviceAControl, "", nil),

		build("ext_op",
			vectors.Header(0xC5, wire.SuiteNone, 0, 4, vectors.PrevHash("op/3"), vectors.ZeroNonce,
				vectors.LabelDeviceAControl),
			[]byte(`{"swept":1}`), vectors.LabelDeviceAControl, vectors.ExtName, nil),
	}

	ph := wire.PayloadHash([]byte(vectors.ControlPayload))
	return map[string]any{
		"note": "Header is 158 bytes, big-endian, fixed widths; signature is 64 bytes over " +
			"framed(domain, header || body); body length is len(envelope) - 222. " +
			"Under suite 0x01 the signature covers the SEALED body.",
		"geometry": map[string]int{
			"header_len": wire.HeaderLen, "sig_len": wire.SigLen,
			"overhead": wire.Overhead, "tag_len": wire.TagLen,
		},
		"header_offsets": []map[string]any{
			{"field": "op_class", "offset": 0, "size": 1},
			{"field": "suite", "offset": 1, "size": 1},
			{"field": "workspace_id", "offset": 2, "size": 16},
			{"field": "key_epoch", "offset": 18, "size": 4},
			{"field": "op_id", "offset": 22, "size": 16},
			{"field": "author_member_id", "offset": 38, "size": 16},
			{"field": "author_key_id", "offset": 54, "size": 8},
			{"field": "author_seq", "offset": 62, "size": 8},
			{"field": "prev_author_hash", "offset": 70, "size": 32},
			{"field": "observed_head", "offset": 102, "size": 32},
			{"field": "nonce", "offset": 134, "size": 24},
		},
		"envelopes": rows,
		"control_chain": map[string]any{
			"note": "prev_control_hash is bare SHA-256 over the previous control op's " +
				"unpacked payload bytes — not the envelope, not a re-serialisation.",
			"payload_utf8":            vectors.ControlPayload,
			"prev_control_hash_hex":   hex.EncodeToString(ph[:]),
			"genesis_link_hex":        hex.EncodeToString(make([]byte, 32)),
			"genesis_link_note":       "An all-zero link is genesis-only, in both directions.",
			"envelope_hash_is_framed": false,
		},
	}
}

func headerJSON(h wire.Header) map[string]any {
	return map[string]any{
		"op_class":          int(h.OpClass),
		"suite":             int(h.Suite),
		"workspace_id":      vectors.UUID(h.WorkspaceID),
		"key_epoch":         h.KeyEpoch,
		"op_id":             vectors.UUID(h.OpID),
		"author_member_id":  vectors.UUID(h.AuthorMemberID),
		"author_key_id_b64": b64.EncodeToString(h.AuthorKeyID[:]),
		"author_seq":        h.AuthorSeq,
		"prev_author_hash":  hex.EncodeToString(h.PrevAuthorHash[:]),
		"observed_head":     hex.EncodeToString(h.ObservedHead[:]),
		"nonce_b64":         b64.EncodeToString(h.Nonce[:]),
	}
}

// ── key plane ────────────────────────────────────────────────────────────────

func buildKeyplane(ns wire.Namespace) any {
	ws := vectors.WorkspaceID
	const epoch = 3
	k := vectors.ContentKey

	type wrapRow struct {
		Label       string `json:"label"`
		MemberID    string `json:"member_id"`
		KexKeyIDB64 string `json:"kex_key_id_b64"`
		KexPubB64   string `json:"kex_public_key_b64"`
		EphPrivB64  string `json:"ephemeral_private_key_b64"`
		EphPubB64   string `json:"ephemeral_public_key_b64"`
		NonceB64    string `json:"nonce_b64"`
		InfoHex     string `json:"info_hex"`
		WrapLen     int    `json:"wrap_len"`
		WrapB64     string `json:"wrap_b64"`
	}

	mkWrap := func(label string, memberID [16]byte, kexLabel string, ephLabel string, nonceLabel string) (wrapRow, wire.WrapEntry) {
		kexPub := vectors.KexPub(kexLabel)
		p := wire.MemberWrapParams{
			Namespace:   ns,
			WorkspaceID: ws,
			Epoch:       epoch,
			MemberID:    memberID,
			KexKeyID:    wire.KeyID(kexPub),
			KexPub:      kexPub,
		}
		eph := vectors.KexPriv(ephLabel)
		nonce := vectors.Nonce(nonceLabel)
		w, err := wire.SealMemberWrap(p, eph, nonce, k)
		if err != nil {
			log.Fatal(err)
		}
		// The info is not on the wire, but it is the value two implementations
		// most often get wrong, so it is published rather than left implicit.
		var epochBE [4]byte
		epochBE[3] = epoch
		info := wire.Framed(ns.V1(wire.DocKeywrap),
			eph.PublicKey().Bytes(), ws[:], epochBE[:], memberID[:], p.KexKeyID[:])

		return wrapRow{
				Label:       label,
				MemberID:    vectors.UUID(memberID),
				KexKeyIDB64: b64.EncodeToString(p.KexKeyID[:]),
				KexPubB64:   b64.EncodeToString(kexPub),
				EphPrivB64:  b64.EncodeToString(eph.Bytes()),
				EphPubB64:   b64.EncodeToString(eph.PublicKey().Bytes()),
				NonceB64:    b64.EncodeToString(nonce[:]),
				InfoHex:     hex.EncodeToString(info),
				WrapLen:     len(w),
				WrapB64:     b64.EncodeToString(w),
			}, wire.WrapEntry{
				MemberID: memberID, KexKeyID: p.KexKeyID, Wrap: w,
			}
	}

	rowA, entryA := mkWrap("device_a", vectors.MemberA, vectors.LabelDeviceAKex, "keywrap/ephemeral/a", "keywrap/nonce/a")
	rowB, entryB := mkWrap("device_b", vectors.MemberB, vectors.LabelDeviceBKex, "keywrap/ephemeral/b", "keywrap/nonce/b")

	// Publish the rows in the digest's own sort order — raw member id bytes,
	// unsigned — so the file shows the ordering rather than asserting it. Which
	// of the two labels sorts first is a fact about their derived ids, not about
	// their names.
	published := []wrapRow{rowA, rowB}
	if bytes.Compare(vectors.MemberB[:], vectors.MemberA[:]) < 0 {
		published = []wrapRow{rowB, rowA}
	}

	escrowNonce := vectors.Nonce("escrow/nonce/3")
	escrow, err := wire.SealEscrowWrap(ns, ws, epoch, vectors.MasterWrapKey, escrowNonce, k)
	if err != nil {
		log.Fatal(err)
	}

	// Deliberately supplied out of sort order: the digest describes the set, not
	// the upload order, so both orderings must produce the same value.
	unsorted := []wire.WrapEntry{entryB, entryA}
	digest, err := wire.KeywrapDigest(ns, epoch, unsorted, escrow)
	if err != nil {
		log.Fatal(err)
	}
	sortedDigest, err := wire.KeywrapDigest(ns, epoch, []wire.WrapEntry{entryA, entryB}, escrow)
	if err != nil {
		log.Fatal(err)
	}
	if digest != sortedDigest {
		log.Fatal("keywrap digest depends on input order")
	}

	return map[string]any{
		"note": "Member wrap is 104 bytes: epk || nonce || XChaCha20-Poly1305(K). " +
			"Escrow wrap is 72 bytes: nonce || XChaCha20-Poly1305(K). " +
			"HKDF salt is RFC 5869's default — 32 zero bytes, not a zero-length key.",
		"workspace_id":        vectors.UUID(ws),
		"epoch":               epoch,
		"content_key_b64":     b64.EncodeToString(k[:]),
		"hkdf_salt_hex":       hex.EncodeToString(make([]byte, 32)),
		"member_wraps":        published,
		"master_wrap_key_b64": b64.EncodeToString(vectors.MasterWrapKey[:]),
		"escrow_wrap": map[string]any{
			"nonce_b64":       b64.EncodeToString(escrowNonce[:]),
			"info_hex":        hex.EncodeToString(wire.EscrowInfo(ns, ws, epoch)),
			"wrap_len":        len(escrow),
			"escrow_wrap_b64": b64.EncodeToString(escrow),
		},
		"keywrap_digest": map[string]any{
			"note": "Sort key is the raw 16-byte member id then the raw 8-byte key id, " +
				"compared as unsigned bytes — not the UUID text, and not the base64 spelling. " +
				"member_wraps above is published in that order, which here is the reverse of " +
				"the labels: an implementation that sorts by label, by insertion order, or by " +
				"the base64 spelling of either id computes a different digest for this set. " +
				"The value was cross-checked against both input orderings.",
			"member_wrap_count": len(unsorted),
			"digest_b64":        b64.EncodeToString(digest[:]),
			"digest_hex":        hex.EncodeToString(digest[:]),
		},
		"keywrap_digest_ordering": buildOrdering(ns),
	}
}

// buildOrdering is the diagnostic half of the digest vectors. The device fixtures
// above cannot tell the sort orderings apart — their derived ids happen to agree
// under every candidate comparison — so this set uses literal ids chosen to make
// them disagree.
func buildOrdering(ns wire.Namespace) any {
	const epoch = 7

	type row struct {
		Label       string `json:"label"`
		MemberID    string `json:"member_id"`
		KexKeyIDB64 string `json:"kex_key_id_b64"`
		KexKeyIDHex string `json:"kex_key_id_hex"`
		WrapB64     string `json:"wrap_b64"`
	}

	entries := make([]wire.WrapEntry, 0, len(vectors.OrderingSet))
	published := make([]row, 0, len(vectors.OrderingSet))
	for _, e := range vectors.OrderingSet {
		entries = append(entries, wire.WrapEntry{MemberID: e.MemberID, KexKeyID: e.KexKeyID, Wrap: e.Wrap})
		published = append(published, row{
			Label:       e.Label,
			MemberID:    vectors.UUID(e.MemberID),
			KexKeyIDB64: b64.EncodeToString(e.KexKeyID[:]),
			KexKeyIDHex: hex.EncodeToString(e.KexKeyID[:]),
			WrapB64:     b64.EncodeToString(e.Wrap),
		})
	}

	// Supplied in the order above and in reverse; both must give the same value.
	forward, err := wire.KeywrapDigest(ns, epoch, entries, vectors.OrderingEscrow)
	if err != nil {
		log.Fatal(err)
	}
	reversed := make([]wire.WrapEntry, len(entries))
	for i, e := range entries {
		reversed[len(entries)-1-i] = e
	}
	backward, err := wire.KeywrapDigest(ns, epoch, reversed, vectors.OrderingEscrow)
	if err != nil {
		log.Fatal(err)
	}
	if forward != backward {
		log.Fatal("ordering digest depends on input order")
	}

	return map[string]any{
		"note": "A set built so that the correct sort key disagrees with the three an " +
			"implementation might reach for by accident. 0x00 base64-encodes to a leading " +
			"'A' (0x41) and 0xd0 to a leading '0' (0x30), so the base64 spelling inverts " +
			"the pair; 0xd0 sets the top bit, so a UUID type comparing two signed 64-bit " +
			"halves inverts it too. The wraps are filler of the right length — the digest " +
			"hashes each and opens none, so only the ordering is under test here.",
		"epoch":                         epoch,
		"member_wrap_count":             len(entries),
		"entries_in_correct_sort_order": published,
		"orderings": map[string]any{
			"raw_unsigned_bytes_correct": []string{"m1/k1", "m1/k2", "m2/k1"},
			"base64_spelling_wrong":      []string{"m2/k1", "m1/k2", "m1/k1"},
			"signed_64bit_halves_wrong":  []string{"m2/k1", "m1/k1", "m1/k2"},
		},
		"escrow_wrap_b64": b64.EncodeToString(vectors.OrderingEscrow),
		"digest_b64":      b64.EncodeToString(forward[:]),
		"digest_hex":      hex.EncodeToString(forward[:]),
	}
}

// ── auth and vault ───────────────────────────────────────────────────────────

func buildAuth(ns wire.Namespace) any {
	nonce := vectors.Bytes32("challenge/nonce/1")
	input := ns.AuthChallengeInput(vectors.MemberA, nonce[:])
	sig := ed25519.Sign(vectors.SignPriv(vectors.LabelDeviceAControl), input)

	locator := vectors.Bytes32("vault/locator/1")
	blob := vectors.Filler(64) // Root secret 32B || master wrap key 32B, sealed by the client
	const version = 1
	vinput := ns.VaultInput(locator, version, blob)
	vsig := ed25519.Sign(vectors.SignPriv(vectors.LabelRoot), vinput)

	certBytes := []byte(vectors.GrantCert)
	cinput := ns.CertSigningInput(wire.DocGrant, certBytes)
	csig := ed25519.Sign(vectors.SignPriv(vectors.LabelRoot), cinput)

	sum := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

	return map[string]any{
		"auth_challenge": map[string]any{
			"note": "framed(<ns>/auth-challenge/v1, member_id || nonce), where member_id is " +
				"the 16 RAW bytes of the id — never a textual spelling. Signed by the " +
				"device's control key.",
			"member_id":              vectors.UUID(vectors.MemberA),
			"member_id_raw_hex":      hex.EncodeToString(vectors.MemberA[:]),
			"nonce_b64":              b64.EncodeToString(nonce[:]),
			"signing_input_hex":      hex.EncodeToString(input),
			"control_public_key_b64": b64.EncodeToString(vectors.SignPub(vectors.LabelDeviceAControl)),
			"signature_b64":          b64.EncodeToString(sig),
		},
		"vault": map[string]any{
			"note": "framed(<ns>/vault/v1, locator || version || blob). version is u64 " +
				"big-endian. The locator is inside the signed bytes, so a record signed for " +
				"one slot can never be replayed into another. The blob is opaque: the server " +
				"stores it verbatim and MUST NOT even length-check it.",
			"locator_hex":          hex.EncodeToString(locator[:]),
			"version":              version,
			"blob_b64":             b64.EncodeToString(blob),
			"signing_input_sha256": sum(vinput),
			"root_public_key_b64":  b64.EncodeToString(vectors.SignPub(vectors.LabelRoot)),
			"root_sig_b64":         b64.EncodeToString(vsig),
		},
		"certificate": map[string]any{
			"note": "framed(<ns>/grant/v1, the LITERAL certificate bytes). Never " +
				"re-serialised JSON: a verifier that re-encodes what it parsed is verifying " +
				"a document nobody signed. The bytes below include their exact whitespace.",
			"document":             wire.DocGrant,
			"domain":               ns.V1(wire.DocGrant),
			"cert_bytes_b64":       b64.EncodeToString(certBytes),
			"cert_bytes_utf8":      string(certBytes),
			"signing_input_sha256": sum(cinput),
			"root_public_key_b64":  b64.EncodeToString(vectors.SignPub(vectors.LabelRoot)),
			"cert_sig_b64":         b64.EncodeToString(csig),
		},
	}
}
