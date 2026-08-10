package httpapi

import (
	"context"
	"io"
	"net/http"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/identity"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/strictjson"
	"github.com/loonybin/roundelay/wire"
)

// AdmissionHeader is the carrier the core defines for a mechanism it does not.
//
// The value is an opaque string the server minted or recognises — a capability
// token, a signed grant, an invite code, a proof of work, whatever the
// deployment chose. A client treats it as bytes it was handed and echoes it
// unmodified.
//
// It is meaningful only where admission is evaluated. A server MUST ignore it
// everywhere else and MUST NOT accept it in place of a device credential on any
// route — otherwise it becomes a second session mechanism by accretion.
const AdmissionHeader = "Roundelay-Admission"

// IdentityHandler serves the four routes that answer "who are you".
type IdentityHandler struct {
	Registrar *identity.Registrar
	Sessions  *identity.Sessions
}

func writeRefusal(w http.ResponseWriter, r *oplog.Refusal) {
	RefuseStatus(w, r.Status, r.Code, r.Fields)
}

// ServeRegister is POST /v1/members.
//
// It evaluates neither bar: the bars describe credentials, and this route
// presents none. It is gated by the certificate in its body.
func (h *IdentityHandler) ServeRegister(w http.ResponseWriter, r *http.Request) {
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
	o := body.Root()

	var req identity.Registration
	req.MemberID = o.UUID("member_id")
	copy(req.ControlPK[:], o.Bytes("control_pk", 32))
	copy(req.ContentPK[:], o.Bytes("content_pk", 32))
	copy(req.KexPK[:], o.Bytes("kex_pk", 32))
	// Optional as a whole, never member by member: sent, all three must be
	// present, and an unrecognised member is reported as key_ids.<name>.
	if ids, present := o.OptionalObject("key_ids"); present {
		var claimed identity.ClaimedKeyIDs
		copy(claimed.Control[:], ids.Bytes("control_key_id", 8))
		copy(claimed.Content[:], ids.Bytes("content_key_id", 8))
		copy(claimed.Kex[:], ids.Bytes("kex_key_id", 8))
		req.ClaimedIDs = &claimed
	}
	req.Cert = o.BytesAny("cert_b64")
	copy(req.CertSig[:], o.Bytes("cert_sig_b64", 64))
	copy(req.RootPK[:], o.Bytes("root_pk_b64", 32))
	if err := body.Err(); err != nil {
		// The key fields have codes of their own, and each names a different
		// repair: a 31-byte signing key, a kex key that is not a key, a claimed
		// id of the wrong width. Collapsing all three into malformed_request
		// would make where the failure was caught — the decoder here, or the
		// length check inside Register — decide what the caller is told.
		if r := registerFieldRefusal(err); r != nil {
			writeRefusal(w, r)
			return
		}
		if RefuseDecode(w, err) {
			return
		}
	}

	res, refusal := h.Registrar.Register(r.Context(), &req, r.Header.Get(AdmissionHeader))
	if refusal != nil {
		writeRefusal(w, refusal)
		return
	}

	status := http.StatusOK // an identical repeat
	if res.Created {
		status = http.StatusCreated
	}
	control := wire.KeyID(res.Device.ControlPK[:])
	content := wire.KeyID(res.Device.ContentPK[:])
	kex := wire.KeyID(res.Device.KexPK[:])
	WriteJSON(w, status, map[string]any{
		"member_id":  strictjson.FormatUUID(res.Device.MemberID),
		"control_pk": wireB64.EncodeToString(res.Device.ControlPK[:]),
		"content_pk": wireB64.EncodeToString(res.Device.ContentPK[:]),
		"kex_pk":     wireB64.EncodeToString(res.Device.KexPK[:]),
		"key_ids": map[string]any{
			"control_key_id": wireB64.EncodeToString(control[:]),
			"content_key_id": wireB64.EncodeToString(content[:]),
			"kex_key_id":     wireB64.EncodeToString(kex[:]),
		},
		// A bootstrap hint that no verification reads. This is the one place it
		// is informative: it separates a shell from a registered device.
		"chained": res.Chained,
	})
}

// registerFieldRefusal maps a decode failure onto the registration's own field
// codes. nil means "not one of ours", and the generic refusal answers.
//
// key_ids is the exception that proves the shape: a *missing* member is
// malformed_request naming the path, because the object is optional as a whole
// and never member by member — the caller's mistake is the object, not the key.
func registerFieldRefusal(err error) *oplog.Refusal {
	m, ok := err.(*strictjson.Malformed)
	if !ok {
		return nil
	}
	unproc := http.StatusUnprocessableEntity
	for _, f := range m.Fields {
		switch f {
		case "control_pk", "content_pk":
			return &oplog.Refusal{Status: unproc, Code: codes.MalformedSignPk}
		case "kex_pk":
			return &oplog.Refusal{Status: unproc, Code: codes.MalformedKexPk}
		case "root_pk_b64":
			return &oplog.Refusal{Status: unproc, Code: codes.MalformedRootPk}
		case "key_ids.control_key_id", "key_ids.content_key_id", "key_ids.kex_key_id":
			if m.Missing(f) {
				return nil
			}
			return &oplog.Refusal{Status: unproc, Code: codes.MalformedKeyId}
		}
	}
	return nil
}

// ServeChallenge is POST /v1/members/{member_id}/challenge.
func (h *IdentityHandler) ServeChallenge(w http.ResponseWriter, r *http.Request) {
	member, ok := pathMember(w, r)
	if !ok {
		return
	}
	nonce, refusal := h.Sessions.Challenge(r.Context(), member)
	if refusal != nil {
		writeRefusal(w, refusal)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"nonce": wireB64.EncodeToString(nonce[:])})
}

// ServeToken is POST /v1/members/{member_id}/token.
//
// The signature is the credential.
func (h *IdentityHandler) ServeToken(w http.ResponseWriter, r *http.Request) {
	member, ok := pathMember(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		Refuse(w, codes.MalformedRequest, nil)
		return
	}

	// The body is read leniently on purpose: a request whose base64 does not
	// decode still spends the challenge, so it cannot be the one shape that
	// leaves the nonce alive to try again. Only the field set is strict.
	in := identity.ExchangeInput{Decoded: true}
	body, perr := strictjson.Parse(raw)
	if perr != nil {
		in.Decoded = false
	} else {
		o := body.Root()
		nonce := o.String("nonce")
		sig := o.String("signature")
		if err := body.Err(); err != nil {
			if _, unknown := err.(*strictjson.UnknownFields); unknown {
				RefuseDecode(w, err)
				return
			}
			in.Decoded = false
		} else {
			n, e1 := wireB64.DecodeString(nonce)
			s, e2 := wireB64.DecodeString(sig)
			in.NonceRaw, in.SignatureRaw = n, s
			in.Decoded = e1 == nil && e2 == nil
		}
	}

	pair, refusal := h.Sessions.Exchange(r.Context(), member, in)
	if refusal != nil {
		writeRefusal(w, refusal)
		return
	}
	writePair(w, pair)
}

// ServeRefresh is POST /v1/members/{member_id}/token/refresh.
func (h *IdentityHandler) ServeRefresh(w http.ResponseWriter, r *http.Request) {
	member, ok := pathMember(w, r)
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
	token := body.Root().String("refresh_token")
	if RefuseDecode(w, body.Err()) {
		return
	}
	pair, refusal := h.Sessions.Refresh(r.Context(), member, token)
	if refusal != nil {
		writeRefusal(w, refusal)
		return
	}
	writePair(w, pair)
}

func writePair(w http.ResponseWriter, p *identity.Pair) {
	WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  p.Access,
		"refresh_token": p.Refresh,
		"token_type":    "bearer",
	})
}

func pathMember(w http.ResponseWriter, r *http.Request) ([16]byte, bool) {
	id, err := strictjson.ParseUUID(r.PathValue("member_id"))
	if err != nil {
		Refuse(w, codes.NotFound, nil)
		return [16]byte{}, false
	}
	return id, true
}

// TokenAuth is the Authenticator every credentialled route resolves through.
type TokenAuth struct{ Tokens *identity.Tokens }

// Device resolves a bearer credential to the device it speaks for.
func (a TokenAuth) Device(_ context.Context, bearer string) ([16]byte, bool) {
	return a.Tokens.ParseAccess(bearer)
}
