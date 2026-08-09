package httpapi

import (
	"context"
	"io"
	"net/http"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/strictjson"
)

// Authenticator resolves a bearer credential to the device it speaks for.
//
// An access token is an opaque bearer string whose internal format is the
// server's own business — it mints and consumes them — but it must name the
// device it speaks for, and it must expire.
type Authenticator interface {
	Device(ctx context.Context, bearer string) (device [16]byte, ok bool)
}

// OpsHandler serves POST /v1/w/{workspace_id}/ops.
type OpsHandler struct {
	Auth     Authenticator
	Pipeline *oplog.Pipeline
}

// ServeHTTP runs the route's own three steps before the pipeline's six: resolve
// the credential, refuse an unrecognised field, then append.
//
// The order matters in both directions. Before authentication the unknown-field
// check is a free oracle for enumerating a route's accepted fields; after
// authorisation a caller with both a malformed request and no access is told
// only that they lack access, and fixes the wrong thing.
func (h *OpsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	device, ok := h.Auth.Device(r.Context(), bearer(r))
	if !ok {
		Refuse(w, codes.InvalidCredential, nil)
		return
	}

	// A path segment that is not a canonical UUID names no Workspace that could
	// exist. Nothing specifies this case; "no such thing" is the closest thing in
	// a closed vocabulary that carries no 405 and no path-parameter code.
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
	body, err := strictjson.Parse(raw)
	if err != nil {
		Refuse(w, codes.MalformedRequest, nil)
		return
	}
	arr := body.Root().Array("ops")
	encoded := make([]string, arr.Len())
	for i := range arr.Len() {
		encoded[i] = arr.String(i)
	}
	if RefuseDecode(w, body.Err()) {
		return
	}

	results, refusal := h.Pipeline.Append(r.Context(), workspace, device, encoded)
	if refusal != nil {
		RefuseStatus(w, refusal.Status, refusal.Code, refusal.Fields)
		return
	}

	// results is positional — one entry per submitted op, in order.
	out := make([]map[string]any, 0, len(results))
	for _, res := range results {
		out = append(out, map[string]any{
			"op_id":     strictjson.FormatUUID(res.OpID),
			"seq":       res.Seq,
			"duplicate": res.Duplicate,
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"results": out})
}

// bearer extracts the credential from an Authorization header. Tokens ride
// Authorization, never cookies, which is why a deployment with no browser client
// may omit CORS entirely.
func bearer(r *http.Request) string {
	const prefix = "Bearer "
	v := r.Header.Get("Authorization")
	if len(v) <= len(prefix) || v[:len(prefix)] != prefix {
		return ""
	}
	return v[len(prefix):]
}
