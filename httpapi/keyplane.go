package httpapi

import (
	"io"
	"net/http"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/keyplane"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/strictjson"
)

// KeyplaneHandler serves the three Workspace-scoped key-plane routes.
type KeyplaneHandler struct {
	Auth      Authenticator
	Store     oplog.Store
	Profile   *profile.Profile
	Authority Bar1
	Publisher *keyplane.Publisher
	// Bar2 answers "any live grant here", which GET /epoch-keys sits at.
	Bar2 Bar2
}

// Bar2 is the second credential bar: a member holding a live grant.
type Bar2 interface {
	Bar2(tx oplog.ReadTx, member [16]byte) *oplog.Refusal
}

// ServePublish is PUT /v1/w/{workspace_id}/keywraps.
func (h *KeyplaneHandler) ServePublish(w http.ResponseWriter, r *http.Request) {
	device, ok := h.Auth.Device(r.Context(), bearer(r))
	if !ok {
		Refuse(w, codes.InvalidCredential, nil)
		return
	}
	workspace, err := strictjson.ParseUUID(r.PathValue("workspace_id"))
	if err != nil {
		Refuse(w, codes.NotFound, nil)
		return
	}

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		Refuse(w, codes.MalformedRequest, nil)
		return
	}
	body, perr := strictjson.Parse(raw)
	if perr != nil {
		Refuse(w, codes.MalformedRequest, nil)
		return
	}
	o := body.Root()

	up := &keyplane.Upload{}
	// malformed_key_epoch is the epoch's own verdict, so it is read against the
	// epoch range rather than reported as a generic malformed field.
	epochOK := true
	if !o.Has("epoch") {
		epochOK = false
	}
	up.Epoch = uint32(o.In("epoch", strictjson.EpochRange))

	arr := o.Array("wraps")
	for i := range arr.Len() {
		e := arr.Object(i)
		var mw oplog.MemberWrap
		mw.Epoch = up.Epoch
		mw.Member = e.UUID("member_id")
		copy(mw.KexKeyID[:], e.Bytes("kex_key_id_b64", 8))
		mw.Wrap = e.BytesAny("wrap_b64")
		up.Wraps = append(up.Wraps, mw)
	}
	up.EscrowWrap = o.BytesAny("escrow_wrap_b64")
	if o.Has("keywrap_digest_b64") {
		copy(up.Digest[:], o.Bytes("keywrap_digest_b64", 32))
		up.HasDigest = true
	}

	if err := body.Err(); err != nil {
		if !epochOK || namesEpoch(err) {
			Refuse(w, codes.MalformedKeyEpoch, nil)
			return
		}
		if RefuseDecode(w, err) {
			return
		}
	}

	tx, err := h.Store.BeginAppend(r.Context(), workspace)
	if err != nil {
		Refuse(w, codes.StoreUnavailable, nil)
		return
	}
	defer tx.Rollback()

	mine, refusal := h.Publisher.Publish(r.Context(), tx, device, up)
	if refusal != nil {
		writeRefusal(w, refusal)
		return
	}
	if err := tx.Commit(); err != nil {
		Refuse(w, codes.StoreUnavailable, nil)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"wraps": wrapsJSON(mine, true)})
}

// namesEpoch reports whether a decode failure was the epoch's.
func namesEpoch(err error) bool {
	m, ok := err.(*strictjson.Malformed)
	if !ok {
		return false
	}
	for _, f := range m.Fields {
		if f == "epoch" {
			return true
		}
	}
	return false
}

func wrapsJSON(wraps []oplog.MemberWrap, withEpoch bool) []map[string]any {
	out := make([]map[string]any, 0, len(wraps))
	for _, w := range wraps {
		e := map[string]any{
			"member_id":      strictjson.FormatUUID(w.Member),
			"kex_key_id_b64": wireB64.EncodeToString(w.KexKeyID[:]),
			"wrap_b64":       wireB64.EncodeToString(w.Wrap),
		}
		if withEpoch {
			e["epoch"] = w.Epoch
		}
		out = append(out, e)
	}
	return out
}

// afterEpoch reads the cursor the two paged key-plane routes share.
//
// It has no default value: absent, the page begins at the start, and
// after_epoch=0 is a different request that skips epoch 0 — which a Workspace
// keyed at genesis has. Unlike `since` on the op log, where position 0 is below
// every op and so is a safe default, epochs start at 0, so no in-range value
// means "before everything" and absence has to carry it.
func afterEpoch(q *strictjson.Query) *uint32 {
	n, present := q.Int("after_epoch", strictjson.EpochRange)
	if !present {
		return nil
	}
	e := uint32(n)
	return &e
}

func (h *KeyplaneHandler) pageLimit(q *strictjson.Query) int {
	limit, ok := q.Int("limit", strictjson.Range{Lo: 1, Hi: int64(h.Profile.Limits.MaxPageSize)})
	if !ok {
		return h.Profile.Limits.DefaultPageSize
	}
	return int(limit)
}

// ServeMyWraps is GET /v1/w/{workspace_id}/keywraps/me.
//
// Scoped to the calling device, and the route has nowhere to put a member id —
// so there is nothing to get wrong.
func (h *KeyplaneHandler) ServeMyWraps(w http.ResponseWriter, r *http.Request) {
	q := strictjson.NewQuery(r.URL.Query())
	after := afterEpoch(q)
	limit := h.pageLimit(q)
	if RefuseDecode(w, q.Err()) {
		return
	}
	device, tx, ok := h.begin(w, r, false)
	if !ok {
		return
	}
	defer tx.Close()

	page, err := tx.ReadMemberWraps(device, after, limit)
	if err != nil {
		Refuse(w, codes.StoreUnavailable, nil)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"wraps": wrapsJSON(page.Wraps, true), "has_more": page.HasMore,
	})
}

// ServeEpochKeys is GET /v1/w/{workspace_id}/epoch-keys.
//
// Useless without the wrapping secret: an escrow wrap opens only under the
// master wrap key, which exists only inside the vault record. Anyone who can
// already open these can already open Root, which is why the bar is deliberately
// low and why this route is neither rate-limited nor audited the way the vault
// fetch is.
func (h *KeyplaneHandler) ServeEpochKeys(w http.ResponseWriter, r *http.Request) {
	q := strictjson.NewQuery(r.URL.Query())
	after := afterEpoch(q)
	limit := h.pageLimit(q)
	if RefuseDecode(w, q.Err()) {
		return
	}
	_, tx, ok := h.begin(w, r, true)
	if !ok {
		return
	}
	defer tx.Close()

	page, err := tx.ReadEpochKeys(after, limit)
	if err != nil {
		Refuse(w, codes.StoreUnavailable, nil)
		return
	}
	out := make([]map[string]any, 0, len(page.Epochs))
	for _, e := range page.Epochs {
		out = append(out, map[string]any{
			"epoch":              e.Epoch,
			"escrow_wrap_b64":    wireB64.EncodeToString(e.EscrowWrap),
			"keywrap_digest_b64": wireB64.EncodeToString(e.Digest[:]),
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"epochs": out, "has_more": page.HasMore})
}

func (h *KeyplaneHandler) begin(w http.ResponseWriter, r *http.Request, needGrant bool) ([16]byte, oplog.ReadTx, bool) {
	device, ok := h.Auth.Device(r.Context(), bearer(r))
	if !ok {
		Refuse(w, codes.InvalidCredential, nil)
		return device, nil, false
	}
	workspace, err := strictjson.ParseUUID(r.PathValue("workspace_id"))
	if err != nil {
		Refuse(w, codes.NotFound, nil)
		return device, nil, false
	}
	tx, err := h.Store.BeginRead(r.Context(), workspace)
	if err != nil {
		Refuse(w, codes.StoreUnavailable, nil)
		return device, nil, false
	}
	var refusal *oplog.Refusal
	if needGrant {
		refusal = h.Bar2.Bar2(tx, device)
	} else {
		refusal = h.Authority.Bar1(tx, device)
	}
	if refusal != nil {
		tx.Close()
		writeRefusal(w, refusal)
		return device, nil, false
	}
	return device, tx, true
}

// VaultHandler serves the two unauthenticated vault routes.
type VaultHandler struct{ Vault *keyplane.Vault }

// ServeWrite is PUT /v1/vault/{locator}.
func (h *VaultHandler) ServeWrite(w http.ResponseWriter, r *http.Request) {
	locator, ok := pathLocator(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		Refuse(w, codes.MalformedRequest, nil)
		return
	}
	body, perr := strictjson.Parse(raw)
	if perr != nil {
		Refuse(w, codes.MalformedRequest, nil)
		return
	}
	o := body.Root()

	var req keyplane.VaultWrite
	req.Version = o.In("version", strictjson.VersionRange)
	// The blob is never length-checked: it is written and read by the same
	// client, and the only thing that must agree is what falls out of it.
	req.Blob = o.BytesAny("blob_b64")
	copy(req.Sig[:], o.Bytes("root_sig_b64", 64))
	copy(req.RootPK[:], o.Bytes("root_pk_b64", 32))

	if err := body.Err(); err != nil {
		writeRefusal(w, vaultFieldRefusal(err))
		return
	}

	slot, refusal := h.Vault.Write(r.Context(), locator, &req)
	if refusal != nil {
		writeRefusal(w, refusal)
		return
	}
	WriteJSON(w, http.StatusOK, slotJSON(slot))
}

// vaultFieldRefusal maps a decode failure onto the vault's own field codes,
// which are finer than the generic one because each names a different repair.
func vaultFieldRefusal(err error) *oplog.Refusal {
	m, ok := err.(*strictjson.Malformed)
	if !ok {
		return &oplog.Refusal{Status: http.StatusUnprocessableEntity, Code: codes.UnknownRequestField,
			Fields: map[string]any{"fields": fieldsOf(err)}}
	}
	for _, f := range m.Fields {
		switch f {
		case "version":
			return &oplog.Refusal{Status: http.StatusUnprocessableEntity, Code: codes.MalformedVaultVersion}
		case "blob_b64":
			return &oplog.Refusal{Status: http.StatusUnprocessableEntity, Code: codes.MalformedVaultBlob}
		case "root_sig_b64":
			return &oplog.Refusal{Status: http.StatusUnprocessableEntity, Code: codes.MalformedVaultSignature}
		case "root_pk_b64":
			return &oplog.Refusal{Status: http.StatusUnprocessableEntity, Code: codes.MalformedRootPk}
		}
	}
	return &oplog.Refusal{Status: http.StatusUnprocessableEntity, Code: codes.MalformedRequest,
		Fields: map[string]any{"fields": m.Fields}}
}

func fieldsOf(err error) []string {
	if u, ok := err.(*strictjson.UnknownFields); ok {
		return u.Fields
	}
	return nil
}

// ServeRead is GET /v1/vault/{locator}.
func (h *VaultHandler) ServeRead(w http.ResponseWriter, r *http.Request) {
	locator, ok := pathLocator(w, r)
	if !ok {
		return
	}
	slot, refusal := h.Vault.Read(r.Context(), locator)
	if refusal != nil {
		writeRefusal(w, refusal)
		return
	}
	WriteJSON(w, http.StatusOK, slotJSON(slot))
}

func slotJSON(s *keyplane.Slot) map[string]any {
	return map[string]any{
		"version":      s.Version,
		"blob_b64":     wireB64.EncodeToString(s.Blob),
		"root_sig_b64": wireB64.EncodeToString(s.Sig[:]),
		"root_pk_b64":  wireB64.EncodeToString(s.PinnedRoot[:]),
	}
}

// pathLocator reads the 32-byte lowercase-hex locator. Anything else is an
// unrouted path.
func pathLocator(w http.ResponseWriter, r *http.Request) ([32]byte, bool) {
	var out [32]byte
	raw, err := hexExact32(r.PathValue("locator"))
	if err != nil {
		Refuse(w, codes.NotFound, nil)
		return out, false
	}
	copy(out[:], raw)
	return out, true
}
