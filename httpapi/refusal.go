package httpapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"regexp"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/strictjson"
)

// ContentType is the one media type this surface speaks.
const ContentType = "application/json"

// Refuse writes a refusal under the one shape every route shares:
//
//	{"detail": {"code": "author_member_mismatch", "index": 3}}
//
// There is no second error shape, so a client that branches on detail.code never
// meets a bare string.
//
// The status comes from the code, because the document fixes it. Two codes carry
// more than one status; those callers use RefuseStatus, which is the only way to
// name a status here at all.
func Refuse(w http.ResponseWriter, code codes.Code, extra map[string]any) {
	status, ok := codes.Status(code)
	if !ok {
		// Unreachable through the generated constants unless the code genuinely
		// has several statuses, in which case the caller owes us the choice.
		panic(fmt.Sprintf("httpapi: %q has no single status; use RefuseStatus", code))
	}
	RefuseStatus(w, status, code, extra)
}

// RefuseStatus writes a refusal at a named status, for the codes the document
// raises under more than one.
func RefuseStatus(w http.ResponseWriter, status int, code codes.Code, extra map[string]any) {
	detail := map[string]any{"code": string(code)}
	maps.Copy(detail, extra)
	// detail.code is the code, whatever a caller passed alongside it.
	detail["code"] = string(code)

	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	WriteJSON(w, status, map[string]any{"detail": detail})
}

// WriteJSON writes a response body.
//
// A client ignores members of a response it does not recognise, so a field added
// here later costs nothing — which is the one evolution channel that must stay
// free for ever, and the reason responses run the opposite way to requests.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		// A response this server built and cannot serialise is a bug, not a state.
		panic(fmt.Sprintf("httpapi: marshalling a %T: %v", v, err))
	}
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// RefuseDecode maps a strictjson failure onto the versioned surface's own two
// codes.
//
// The same structural rule is spelled differently inside a signed payload —
// malformed_control_payload, malformed_prune_payload,
// malformed_ext_binding_payload — which is why strictjson names no code and the
// door that received the bytes chooses. This is the request-body door.
//
// It reports whether it wrote anything, so a caller can pass a nil error
// through.
func RefuseDecode(w http.ResponseWriter, err error) bool {
	switch e := err.(type) {
	case nil:
		return false
	case *strictjson.UnknownFields:
		Refuse(w, codes.UnknownRequestField, map[string]any{"fields": e.Fields})
	case *strictjson.Malformed:
		Refuse(w, codes.MalformedRequest, map[string]any{"fields": e.Fields})
	default:
		// Bytes that are not one well-formed JSON value. Nothing was decoded, so
		// there is no path to name and the refusal carries no fields.
		Refuse(w, codes.MalformedRequest, nil)
	}
	return true
}

var lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// hexExact32 decodes a 64-character lowercase hex string to 32 bytes.
func hexExact32(s string) ([]byte, error) {
	if !lowerHex64.MatchString(s) {
		return nil, errors.New("httpapi: not 64 lowercase hex characters")
	}
	return hex.DecodeString(s)
}
