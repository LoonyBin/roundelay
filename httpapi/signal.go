package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/signal"
	"github.com/loonybin/roundelay/strictjson"
)

// Keepalive is the payload of the idle frame.
//
// It is an application-level text frame rather than a protocol ping, because
// protocol pings are invisible to browser clients.
const Keepalive = "ping"

// SignalHandler serves WS /v1/w/{workspace_id}/signal.
type SignalHandler struct {
	Auth      Authenticator
	Store     oplog.Store
	Profile   *profile.Profile
	Authority Bar1
	Broker    signal.Broker

	// AcceptOptions is passed to the upgrade. A deployment serving browsers sets
	// its origin allow-list here.
	AcceptOptions *websocket.AcceptOptions
}

// ServeHTTP runs the handshake and then the feed.
func (h *SignalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The connection is accepted before anything is checked, which is why a
	// client MUST NOT treat a successful connection as authentication success.
	// The immediate empty frame below is the acknowledgement.
	conn, err := websocket.Accept(w, r, h.AcceptOptions)
	if err != nil {
		return
	}
	defer conn.CloseNow()

	member, sub, ok := h.handshake(r, conn)
	if !ok {
		return
	}
	defer sub.Close()

	// The empty frame is both the auth acknowledgement and a "go sync": a
	// subscriber that connects mid-stream has no idea what it missed.
	if err := conn.Write(r.Context(), websocket.MessageText, nil); err != nil {
		return
	}
	h.feed(r.Context(), conn, sub, member)
}

// handshake reads the token frame and applies the bar.
func (h *SignalHandler) handshake(r *http.Request, conn *websocket.Conn) ([16]byte, *signal.Subscription, bool) {
	var member [16]byte

	workspace, err := strictjson.ParseUUID(r.PathValue("workspace_id"))
	if err != nil {
		// A path that names no Workspace that could exist is a protocol error the
		// client must fix, which is what 4400 says.
		conn.Close(websocket.StatusCode(codes.CloseProtocolError), "")
		return member, nil, false
	}

	// The token arrives as the first frame, not a header: a browser cannot set
	// Authorization on a WebSocket, and a query string would write the token
	// into every proxy log along the path.
	//
	// The deadline is a timer beside the read rather than a context on it. A read
	// whose own context expires takes the connection down with it, and a socket
	// already gone cannot send the close frame that says why — which would turn
	// "no token in time" into an abnormal closure carrying no code at all.
	type first struct {
		kind websocket.MessageType
		data []byte
		err  error
	}
	frames := make(chan first, 1)
	go func() {
		kind, data, err := conn.Read(r.Context())
		frames <- first{kind, data, err}
	}()

	deadline := time.NewTimer(h.Profile.Limits.SignalAuthDeadline)
	defer deadline.Stop()

	var f first
	select {
	case <-deadline.C:
		conn.Close(websocket.StatusCode(codes.CloseProtocolError), "")
		return member, nil, false
	case f = <-frames:
	}
	if f.err != nil || f.kind != websocket.MessageText {
		// No token in time, or a binary first frame.
		conn.Close(websocket.StatusCode(codes.CloseProtocolError), "")
		return member, nil, false
	}
	raw := f.data

	member, resolved := h.Auth.Device(r.Context(), string(raw))
	if !resolved {
		// Invalid, or not a device token: park until the token refreshes.
		conn.Close(websocket.StatusCode(codes.CloseInvalidToken), "")
		return member, nil, false
	}

	tx, err := h.Store.BeginRead(r.Context(), workspace)
	if err != nil {
		conn.Close(websocket.StatusInternalError, "")
		return member, nil, false
	}
	exists, err := tx.WorkspaceExists()
	if err != nil {
		tx.Close()
		conn.Close(websocket.StatusInternalError, "")
		return member, nil, false
	}
	// Before a genesis there is nothing to be registered in, so the socket is
	// accepted and behaves as a subscription to an empty Workspace — its first
	// poke arriving when the genesis does.
	if exists {
		refusal := h.Authority.Bar1(tx, member)
		tx.Close()
		if refusal != nil {
			// 4403 merges two causes the HTTP surface keeps apart. It is the one
			// sanctioned exception to "codes are never merged", because a close
			// frame carries no body to disambiguate with and the client's
			// response is identical either way.
			conn.Close(websocket.StatusCode(codes.CloseNoMembership), "")
			return member, nil, false
		}
	} else {
		tx.Close()
	}

	return member, h.Broker.Subscribe(workspace, member), true
}

// feed writes pokes and keepalives until the socket goes.
func (h *SignalHandler) feed(ctx context.Context, conn *websocket.Conn, sub *signal.Subscription, _ [16]byte) {
	// Inbound frames after the handshake are ignored — but the read has to keep
	// running, or a client's close never arrives.
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}()

	idle := time.NewTimer(h.Profile.Limits.SignalKeepalive)
	defer idle.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-gone:
			return

		case e := <-sub.C:
			if e == signal.Evict {
				// A socket is authenticated once and never re-checked. Token
				// expiry does not close it; revocation does — an expired token
				// means the device should refresh before its next HTTP call, and
				// does not mean this subscription became illegitimate.
				conn.Close(websocket.StatusCode(codes.CloseNoMembership), "")
				return
			}
			if err := conn.Write(ctx, websocket.MessageText, nil); err != nil {
				return
			}
			resetTimer(idle, h.Profile.Limits.SignalKeepalive)

		case <-idle.C:
			// Sent only while idle, so it is the exact complement of a poke.
			if err := conn.Write(ctx, websocket.MessageText, []byte(Keepalive)); err != nil {
				return
			}
			idle.Reset(h.Profile.Limits.SignalKeepalive)
		}
	}
}

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// ErrNoBroker reports a handler with nothing behind its fan-out.
var ErrNoBroker = errors.New("httpapi: signal handler has no broker")

// Validate refuses a handler that would silently drop pokes.
func (h *SignalHandler) Validate() error {
	if h.Broker == nil {
		return ErrNoBroker
	}
	return nil
}
