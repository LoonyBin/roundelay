// Package identity answers authentication only — who are you. What a device is
// then allowed to write is Authority's.
//
// There is no identity provider and no user record here. Root is a keypair, a
// device is a keypair, and the only session credential is a device token.
package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

var b64 = base64.RawURLEncoding

// Device is the registry record: a device's three public keys, held once and
// never replaced in place.
//
// The server retains no Root beside it. Which Workspaces a device may address is
// answered by its accepted registrations — a device joining two Workspaces owned
// by two identities is certified by two different keys, so anything stored per
// device would be wrong for one of them.
type Device struct {
	MemberID  [16]byte
	ControlPK [32]byte
	ContentPK [32]byte
	KexPK     [32]byte
}

// Store is the state authentication needs. None of it is in the log, and none of
// it is authoritative for anything: a replacement rebuilt from the log is
// complete without the sessions and the counters.
type Store interface {
	// Device reads the registry record.
	Device(ctx context.Context, id [16]byte) (*Device, bool, error)
	// PutDevice creates a record. A stored key is never replaced in place, so
	// this only ever creates.
	PutDevice(ctx context.Context, d Device) error

	// ChainedAnywhere reports whether an accepted registration exists for this
	// device in the log anywhere. It is a bootstrap hint that no verification
	// reads — the one place it is informative is separating a shell from a
	// registered device.
	ChainedAnywhere(ctx context.Context, id [16]byte) (bool, error)

	// ControlKeysInForce is the union of the control keys in force for this
	// device across every Workspace it is registered in.
	//
	// The auth challenge has no Workspace in its route and no position to be
	// judged at, so it asks the only question it can. A key amended away in every
	// one of them stops obtaining tokens; until then the retired key still buys a
	// token somewhere, and that token speaks for the device everywhere.
	ControlKeysInForce(ctx context.Context, id [16]byte) ([][32]byte, error)

	// PutChallenge records a nonce for a device.
	PutChallenge(ctx context.Context, member [16]byte, nonce [32]byte, expires time.Time) error
	// TakeChallenge consumes this device's pending challenge and returns it.
	//
	// Keyed by device rather than by nonce, which is what makes "spent by the
	// attempt, win or lose, and spent before either field is decoded"
	// implementable: a request whose bytes the server cannot parse still spends
	// it, so an unparseable body is not the one shape that leaves the nonce
	// alive to try again.
	TakeChallenge(ctx context.Context, member [16]byte, now time.Time) ([32]byte, bool, error)

	// CountChallenge is the fixed-window rate limiter. It returns the remaining
	// lifetime of the current window when the limit is spent.
	CountChallenge(ctx context.Context, member [16]byte, now time.Time, window time.Duration, limit int) (bool, time.Duration, error)

	// PutRefresh stores a refresh token by its irreversible hash. A server must
	// not be able to reconstruct a live refresh token from its own storage.
	PutRefresh(ctx context.Context, hash [32]byte, member [16]byte, expires time.Time) error
	// TakeRefresh consumes a token iff it is live and scoped to this device.
	//
	// Only a *successful* refresh revokes the presented token, which is the
	// opposite of the challenge rule — that one is spent by the attempt, win or
	// lose. The asymmetry is in the specification and it is load-bearing: a
	// challenge is a guessing surface and burning it bounds the guesses, while a
	// refresh token is the device's own credential and a failed attempt against
	// somebody else's endpoint must not destroy it.
	TakeRefresh(ctx context.Context, hash [32]byte, member [16]byte, now time.Time) (bool, error)
	// RevokeRefreshFor kills every refresh token scoped to a device. Two events
	// in the log trigger it: losing the last live grant in a Workspace, and a
	// member_amend of that device's control key.
	RevokeRefreshFor(ctx context.Context, member [16]byte) error
}

// Tokens mints and consumes the two credentials.
//
// An access token's internal format is the server's own business — it mints and
// consumes them — but it must name the device it speaks for and it must expire.
// This one is stateless and authenticated, which is what lets an unexpired
// access token outlive a revoke while every route re-tests the bar, exactly as
// the specification describes.
type Tokens struct {
	// Secret is the server's own. It never appears on the wire.
	Secret     []byte
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	// Now is injectable so a test can move the clock. The server needs a wall
	// clock for token expiry, nonce lifetimes and rate windows, and for nothing
	// else: it MUST NOT use its own clock to order, judge or reject ops.
	Now func() time.Time
}

func (t *Tokens) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// accessDomain separates the access-token MAC from every other construction this
// server computes. It is not one of the protocol's fifteen domains — nothing
// off-server ever verifies it — but it must not collide with one either.
const accessDomain = "roundelay/internal/access-token/v1"

// MintAccess returns an opaque bearer string naming a device and an expiry.
func (t *Tokens) MintAccess(member [16]byte) string {
	raw := make([]byte, 0, 24)
	raw = append(raw, member[:]...)
	raw = binary.BigEndian.AppendUint64(raw, uint64(t.now().Add(t.AccessTTL).Unix()))
	mac := hmac.New(sha256.New, t.Secret)
	mac.Write([]byte(accessDomain))
	mac.Write(raw)
	return b64.EncodeToString(append(raw, mac.Sum(nil)...))
}

// ParseAccess recovers the device a token speaks for, or reports that it does
// not speak for one.
func (t *Tokens) ParseAccess(token string) ([16]byte, bool) {
	var member [16]byte
	raw, err := b64.DecodeString(token)
	if err != nil || len(raw) != 24+sha256.Size {
		return member, false
	}
	mac := hmac.New(sha256.New, t.Secret)
	mac.Write([]byte(accessDomain))
	mac.Write(raw[:24])
	if subtle.ConstantTimeCompare(mac.Sum(nil), raw[24:]) != 1 {
		return member, false
	}
	if t.now().Unix() >= int64(binary.BigEndian.Uint64(raw[16:24])) {
		return member, false
	}
	copy(member[:], raw[:16])
	return member, true
}

// MintRefresh returns a high-entropy token and the irreversible hash to store.
// It is returned exactly once.
func (t *Tokens) MintRefresh() (string, [32]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", [32]byte{}, err
	}
	token := b64.EncodeToString(raw)
	return token, RefreshHash(token), nil
}

// RefreshHash is what the store holds. The token itself is never stored.
func RefreshHash(token string) [32]byte { return sha256.Sum256([]byte(token)) }

// Nonce is a fresh 32-byte challenge. It discloses nothing, which is why the
// route that hands it out needs no credential: possession of the device's
// signing key is the credential being proved.
func Nonce() ([32]byte, error) {
	var n [32]byte
	if _, err := rand.Read(n[:]); err != nil {
		return n, err
	}
	return n, nil
}

// ErrNoSecret reports a Tokens with nothing to sign with.
var ErrNoSecret = errors.New("identity: token secret is unset")

// Validate refuses a token minter that would produce forgeable credentials.
func (t *Tokens) Validate() error {
	if len(t.Secret) < 32 {
		return ErrNoSecret
	}
	if t.AccessTTL <= 0 || t.RefreshTTL <= 0 {
		return errors.New("identity: access and refresh lifetimes must be positive")
	}
	return nil
}
