package httpapi

import (
	"encoding/base64"
	"net/http"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/strictjson"
	"github.com/loonybin/roundelay/wire"
)

var wireB64 = base64.StdEncoding

// Bar1 is the credential bar the read routes sit at.
type Bar1 interface {
	Bar1(tx oplog.ReadTx, member [16]byte) *oplog.Refusal
}

// ReadHandler serves the two bar-1 reads: the op log and the member list.
type ReadHandler struct {
	Auth      Authenticator
	Store     oplog.Store
	Profile   *profile.Profile
	Authority Bar1
}

// begin resolves the credential, the Workspace and the read transaction, and
// applies the bar.
//
// A Workspace with no accepted genesis is not gated: reads answer as an empty
// Workspace does. The caller distinguishes that case by the returned bool.
func (h *ReadHandler) begin(w http.ResponseWriter, r *http.Request) (oplog.ReadTx, bool) {
	device, ok := h.Auth.Device(r.Context(), bearer(r))
	if !ok {
		Refuse(w, codes.InvalidCredential, nil)
		return nil, false
	}
	workspace, err := strictjson.ParseUUID(r.PathValue("workspace_id"))
	if err != nil {
		Refuse(w, codes.NotFound, nil)
		return nil, false
	}
	tx, err := h.Store.BeginRead(r.Context(), workspace)
	if err != nil {
		Refuse(w, codes.StoreUnavailable, nil)
		return nil, false
	}
	exists, err := tx.WorkspaceExists()
	if err != nil {
		tx.Close()
		Refuse(w, codes.StoreUnavailable, nil)
		return nil, false
	}
	if !exists {
		return tx, true
	}
	if refusal := h.Authority.Bar1(tx, device); refusal != nil {
		tx.Close()
		RefuseStatus(w, refusal.Status, refusal.Code, refusal.Fields)
		return nil, false
	}
	return tx, true
}

// page reads the two ceilings every paged route shares. One advertised pair, for
// every paged route, so a client discovers no ceiling per route.
func (h *ReadHandler) page(q *strictjson.Query) int {
	limit, ok := q.Int("limit", strictjson.Range{Lo: 1, Hi: int64(h.Profile.Limits.MaxPageSize)})
	if !ok {
		return h.Profile.Limits.DefaultPageSize
	}
	return int(limit)
}

// ServeOps is GET /v1/w/{workspace_id}/ops.
//
// `since` is purely the client's: the server stores no cursor and remembers
// nothing about who has read what.
func (h *ReadHandler) ServeOps(w http.ResponseWriter, r *http.Request) {
	q := strictjson.NewQuery(r.URL.Query())
	since, _ := q.Int("since", strictjson.SinceRange)
	limit := h.page(q)
	includeReprised, _ := q.Bool("include_reprised")
	if RefuseDecode(w, q.Err()) {
		return
	}

	tx, ok := h.begin(w, r)
	if !ok {
		return
	}
	defer tx.Close()

	page, err := tx.ReadOps(since, limit, includeReprised)
	if err != nil {
		Refuse(w, codes.StoreUnavailable, nil)
		return
	}
	out := make([]map[string]any, 0, len(page.Ops))
	for _, op := range page.Ops {
		// Served back byte-identical. The envelope is the truth; every field the
		// server parsed out of it is an index.
		out = append(out, map[string]any{
			"seq":      op.Seq,
			"envelope": wireB64.EncodeToString(op.Envelope),
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"ops": out, "has_more": page.HasMore})
}

// ServeMembers is GET /v1/w/{workspace_id}/members.
//
// A bootstrap hint that no verification reads: a device's key is learned from
// its own registration in the log, signed under this Workspace's root
// authority, so poisoning this list achieves nothing.
func (h *ReadHandler) ServeMembers(w http.ResponseWriter, r *http.Request) {
	q := strictjson.NewQuery(r.URL.Query())
	var after *[16]byte
	// `after` is a position, not a lookup: every 16-byte value names a place in
	// the ordering whether a member sits there or not, so it is refused only for
	// being misshapen.
	if id, present := q.UUID("after"); present {
		after = &id
	}
	limit := h.page(q)
	if RefuseDecode(w, q.Err()) {
		return
	}

	tx, ok := h.begin(w, r)
	if !ok {
		return
	}
	defer tx.Close()

	page, err := tx.ReadMembers(after, limit)
	if err != nil {
		Refuse(w, codes.StoreUnavailable, nil)
		return
	}
	out := make([]map[string]any, 0, len(page.Members))
	for _, m := range page.Members {
		control, content, kex := wire.KeyID(m.ControlPK[:]), wire.KeyID(m.ContentPK[:]), wire.KeyID(m.KexPK[:])
		out = append(out, map[string]any{
			"member_id": strictjson.FormatUUID(m.MemberID),
			// The registration's own kind, served as stored: the profile's token,
			// neither interpreted nor re-checked here.
			"member_kind": m.Kind,
			// Grouping is by equality within this Workspace and nothing more.
			"holder_ref": wireB64.EncodeToString(m.HolderRef[:]),
			"control_pk": wireB64.EncodeToString(m.ControlPK[:]),
			"content_pk": wireB64.EncodeToString(m.ContentPK[:]),
			"kex_pk":     wireB64.EncodeToString(m.KexPK[:]),
			"key_ids": map[string]any{
				"control_key_id": wireB64.EncodeToString(control[:]),
				"content_key_id": wireB64.EncodeToString(content[:]),
				"kex_key_id":     wireB64.EncodeToString(kex[:]),
			},
		})
	}
	// No `chained` flag: presence in this list is the chaining.
	WriteJSON(w, http.StatusOK, map[string]any{"members": out, "has_more": page.HasMore})
}
