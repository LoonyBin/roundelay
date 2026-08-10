package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
)

// Sessions issues and rotates device credentials.
type Sessions struct {
	Profile *profile.Profile
	Store   Store
	Tokens  *Tokens
	// Namespace frames the auth-challenge preimage.
	Namespace string
}

// Pair is what the two token routes answer with.
type Pair struct {
	Access  string
	Refresh string
}

// Challenge issues a nonce for a device.
//
// Unauthenticated on purpose: possession of the device's signing key is the
// credential being proved, and a random nonce discloses nothing. Requiring a
// credential to get one would defeat the point.
func (s *Sessions) Challenge(ctx context.Context, member [16]byte) ([32]byte, *oplog.Refusal) {
	var zero [32]byte

	// The existence check runs first, so sweeping through invented ids creates
	// no counters.
	if _, found, err := s.Store.Device(ctx, member); err != nil {
		return zero, storeDown()
	} else if !found {
		return zero, refuse(http.StatusNotFound, codes.UnknownMember, nil)
	}

	now := s.Tokens.now()
	ok, retry, err := s.Store.CountChallenge(ctx, member, now,
		s.Profile.Limits.ChallengeWindow, s.Profile.Limits.ChallengesPerWindow)
	if err != nil {
		return zero, storeDown()
	}
	if !ok {
		// The remaining lifetime of the current window, rounded up.
		return zero, refuse(http.StatusTooManyRequests, codes.MemberChallengeRateLimited,
			map[string]any{"retry_after_seconds": int(retry.Round(time.Second).Seconds())})
	}

	nonce, err := Nonce()
	if err != nil {
		return zero, storeDown()
	}
	if err := s.Store.PutChallenge(ctx, member, nonce, now.Add(s.Profile.Limits.ChallengeLifetime)); err != nil {
		return zero, storeDown()
	}
	return nonce, nil
}

// ExchangeInput is the token route's decoded body, before either field has been
// judged.
type ExchangeInput struct {
	// NonceRaw and SignatureRaw are the decoded bytes; Decoded reports whether
	// both were valid base64.
	NonceRaw     []byte
	SignatureRaw []byte
	Decoded      bool
}

// Exchange turns a signed challenge into a token pair.
//
// The challenge is spent by the attempt, win or lose — and spent before either
// field is decoded. So a signature-guessing loop needs a fresh round trip per
// guess, and a request the server cannot even parse must not be the one shape
// that leaves the nonce alive to try again.
func (s *Sessions) Exchange(ctx context.Context, member [16]byte, in ExchangeInput) (*Pair, *oplog.Refusal) {
	// Same code for both statuses, deliberately: the distinction leaks nothing
	// about the device or its key, only that the bytes were not base64.
	bad := func(status int) *oplog.Refusal { return refuse(status, codes.BadMemberChallenge, nil) }

	// Spent by the attempt, win or lose, and before either field is decoded. So
	// a signature-guessing loop needs a fresh round trip per guess.
	pending, live, err := s.Store.TakeChallenge(ctx, member, s.Tokens.now())
	if err != nil {
		return nil, storeDown()
	}

	if !in.Decoded {
		return nil, bad(unproc)
	}
	// An unknown device, an unknown, expired or wrong-device nonce, a wrong
	// nonce length and a bad signature are one code and one status.
	if !live || len(in.NonceRaw) != len(pending) ||
		subtle.ConstantTimeCompare(pending[:], in.NonceRaw) != 1 {
		return nil, bad(http.StatusUnauthorized)
	}
	nonce := pending

	keys, err := s.Store.ControlKeysInForce(ctx, member)
	if err != nil {
		return nil, storeDown()
	}
	if len(keys) == 0 {
		return nil, bad(http.StatusUnauthorized)
	}

	ns := s.Profile.Namespace
	input := ns.AuthChallengeInput(member, nonce[:])
	verified := false
	for _, k := range keys {
		if ed25519.Verify(ed25519.PublicKey(k[:]), input, in.SignatureRaw) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, bad(http.StatusUnauthorized)
	}
	return s.issue(ctx, member)
}

// Refresh rotates a pair: the presented token is revoked and a fresh pair
// issued.
func (s *Sessions) Refresh(ctx context.Context, member [16]byte, token string) (*Pair, *oplog.Refusal) {
	invalid := refuse(http.StatusUnauthorized, codes.InvalidRefreshToken, nil)

	// Unknown, revoked, expired, scoped to a different device, or naming a
	// device that does not exist — one code for all of them, and the token
	// survives every one.
	if _, found, err := s.Store.Device(ctx, member); err != nil {
		return nil, storeDown()
	} else if !found {
		return nil, invalid
	}
	ok, err := s.Store.TakeRefresh(ctx, RefreshHash(token), member, s.Tokens.now())
	if err != nil {
		return nil, storeDown()
	}
	if !ok {
		return nil, invalid
	}
	return s.issue(ctx, member)
}

func (s *Sessions) issue(ctx context.Context, member [16]byte) (*Pair, *oplog.Refusal) {
	refresh, hash, err := s.Tokens.MintRefresh()
	if err != nil {
		return nil, storeDown()
	}
	if err := s.Store.PutRefresh(ctx, hash, member, s.Tokens.now().Add(s.Tokens.RefreshTTL)); err != nil {
		return nil, storeDown()
	}
	return &Pair{Access: s.Tokens.MintAccess(member), Refresh: refresh}, nil
}
