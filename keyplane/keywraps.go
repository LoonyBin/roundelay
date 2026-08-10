// Package keyplane holds the wraps the server cannot open and the vault it
// cannot read.
//
// Its job here is storage and arithmetic: it holds wraps it has no key for, and
// checks one hash it was told to check. Every cryptographic decision was made on
// a device before the bytes arrived.
package keyplane

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/wire"
)

const unproc = http.StatusUnprocessableEntity

func refuse(status int, code codes.Code, fields map[string]any) *oplog.Refusal {
	return &oplog.Refusal{Status: status, Code: code, Fields: fields}
}

func storeDown() *oplog.Refusal {
	return refuse(http.StatusServiceUnavailable, codes.StoreUnavailable, nil)
}

// Upload is the decoded PUT .../keywraps body.
type Upload struct {
	Epoch      uint32
	Wraps      []oplog.MemberWrap
	EscrowWrap []byte
	// Digest is the request's own commitment. Present only where the body
	// carried one — at epoch 0 with no record stored it is required and becomes
	// the commitment; once a record exists it is optional and ignored.
	Digest    [32]byte
	HasDigest bool
}

// Publisher serves PUT /v1/w/{workspace_id}/keywraps.
type Publisher struct {
	Profile *profile.Profile
	// Owner reports whether a device holds the authority role here. The upload
	// is gated by it before any digest is looked at.
	Owner OwnerCheck
}

// OwnerCheck answers the authority-role question at the position an upload sees.
type OwnerCheck interface {
	// Registered reports an accepted registration; LiveRoles reports the roles
	// live now, sorted.
	IsOwner(tx oplog.Tx, member [16]byte) (registered bool, anyGrant bool, owner bool, err error)
}

// Publish applies the rules in the order §8 fixes.
//
// This route is never refused for consumption: a rotation whose wrap set cannot
// land never completes, and gating the upload would leave the new epoch existing
// with nobody able to be given its key.
func (p *Publisher) Publish(_ context.Context, tx oplog.Tx, caller [16]byte, up *Upload) ([]oplog.MemberWrap, *oplog.Refusal) {
	registered, anyGrant, owner, err := p.Owner.IsOwner(tx, caller)
	if err != nil {
		return nil, storeDown()
	}
	if !registered {
		return nil, refuse(http.StatusForbidden, codes.NoRegistration, nil)
	}
	// malformed_key_epoch sits between the two access checks, which is where the
	// sequence puts it: the epoch is the request's own shape and needs no log.
	if !anyGrant {
		return nil, refuse(http.StatusForbidden, codes.NoLiveGrant, nil)
	}
	if !owner {
		// The code table gives this refusal a revoked field; nothing states what
		// it means. The only definition the vocabulary offers is no_live_grant's
		// — "had grants once and has none live" — and under the sequence above
		// that state is unreachable here, because a caller in it was already
		// answered no_live_grant two checks ago. So the field is present, because
		// the table says it is, and constant, because its only stated meaning
		// cannot vary at this point.
		//
		// The reading that would carry information is "held an authority grant
		// and lost it", which is a different fact from the one no_live_grant
		// reports and the only one no rule in either layer needs.
		return nil, refuse(http.StatusForbidden, codes.KeywrapRequiresOwner,
			map[string]any{"revoked": false})
	}
	if len(up.EscrowWrap) != wire.EscrowWrapLen {
		return nil, refuse(unproc, codes.MalformedEscrowWrap,
			map[string]any{"expected_bytes": wire.EscrowWrapLen})
	}

	// Per entry, in the order the sequence gives.
	seen := map[[16]byte]bool{}
	for i, w := range up.Wraps {
		// index, on every one of them. A set is as large as the Workspace has
		// members, and "one of these two hundred wraps is wrong" is a bisection
		// exercise rather than a refusal.
		at := func(f map[string]any) map[string]any {
			if f == nil {
				f = map[string]any{}
			}
			f["index"] = i
			return f
		}
		if len(w.Wrap) != wire.MemberWrapLen {
			return nil, refuse(unproc, codes.MalformedKeywrap,
				at(map[string]any{"expected_bytes": wire.MemberWrapLen}))
		}
		inForce, ok, err := tx.KexKeyIDInForce(w.Member)
		if err != nil {
			return nil, storeDown()
		}
		if !ok {
			return nil, refuse(unproc, codes.UnknownKeywrapMember, at(nil))
		}
		if w.KexKeyID != inForce {
			// Materialised state is the honest answer here: a set is minted for
			// the epoch about to be published, so the key a member should be
			// sealed to is the one it holds now. An amend that lands mid-upload
			// refuses the set, and the remedy is to rebuild it against the log.
			return nil, refuse(unproc, codes.KexKeyIdNotRegistered, at(nil))
		}
		if seen[w.Member] {
			// The digest sorts by (member_id, kex_key_id), so a duplicate would
			// make the commitment depend on which copy the server kept.
			return nil, refuse(unproc, codes.DuplicateKeywrapMember, at(nil))
		}
		seen[w.Member] = true
	}

	record, stored, err := tx.EpochRecord(up.Epoch)
	if err != nil {
		return nil, storeDown()
	}

	// A published set is final, and which refusal a different one meets depends
	// on the epoch.
	//
	// For epoch >= 1 the log committed a digest, so a different set fails that
	// first. At epoch 0 the request's digest is optional and ignored once a
	// record exists — the stored commitment is authoritative — so there is no
	// digest to catch it, and the comparison against what is stored is the only
	// thing left. That is where the split comes from, and it is why this reads as
	// two branches rather than one.
	published := stored && record.Published

	if up.Epoch == 0 && published {
		same, err := p.sameSet(tx, up)
		if err != nil {
			return nil, storeDown()
		}
		if !same {
			return nil, refuse(http.StatusConflict, codes.KeywrapAlreadyWritten,
				map[string]any{"epoch": up.Epoch})
		}
		return p.echo(tx, caller, up.Epoch)
	}

	// Epoch 0 is the one case with no rotate behind it: with no record stored the
	// request's digest is required and becomes the commitment.
	commitment := up.Digest
	if up.Epoch == 0 {
		if !up.HasDigest {
			return nil, refuse(unproc, codes.MissingKeywrapDigest,
				map[string]any{"epoch": up.Epoch})
		}
	} else {
		// Ordering is the client's to get right: author the rotate, let it land,
		// then upload. A set arriving first is refused rather than trusted,
		// because a digest the log has not committed to is just a number the
		// uploader chose.
		if !stored {
			return nil, refuse(http.StatusConflict, codes.RotateNotMaterialised,
				map[string]any{"epoch": up.Epoch})
		}
		commitment = record.Digest
	}

	computed, derr := wire.KeywrapDigest(p.Profile.Namespace, up.Epoch, toEntries(up.Wraps), up.EscrowWrap)
	if derr != nil {
		// Only a duplicate reaches this, and the loop above already refused one.
		return nil, refuse(unproc, codes.DuplicateKeywrapMember, nil)
	}
	if computed != commitment {
		// The wraps an epoch was published with are not a later caller's to
		// replace: allowing it would let a stolen authority credential swap the
		// key set out from under devices that already read it.
		// expected_digest is what the log committed to, so an uploader that built
		// the set against a stale view can see which one it missed rather than
		// guessing at which member it got wrong.
		return nil, refuse(unproc, codes.KeywrapDigestMismatch, map[string]any{
			"epoch":           up.Epoch,
			"expected_digest": base64.StdEncoding.EncodeToString(commitment[:]),
		})
	}

	// A byte-identical replay at epoch >= 1 matched the committed digest and is
	// idempotent.
	if published {
		return p.echo(tx, caller, up.Epoch)
	}

	if err := tx.PublishWraps(up.Epoch, commitment, up.EscrowWrap, up.Wraps); err != nil {
		return nil, storeDown()
	}
	return p.echo(tx, caller, up.Epoch)
}

// sameSet reports whether an upload is byte-identical to what is stored.
func (p *Publisher) sameSet(tx oplog.Tx, up *Upload) (bool, error) {
	existing, err := tx.MemberWrapsAt(up.Epoch)
	if err != nil {
		return false, err
	}
	if len(existing) != len(up.Wraps) {
		return false, nil
	}
	index := make(map[[16]byte]oplog.MemberWrap, len(existing))
	for _, w := range existing {
		index[w.Member] = w
	}
	for _, w := range up.Wraps {
		got, ok := index[w.Member]
		if !ok || got.KexKeyID != w.KexKeyID || string(got.Wrap) != string(w.Wrap) {
			return false, nil
		}
	}
	return true, nil
}

// echo returns the caller's own wrap for the epoch just published, and nothing
// else. The write's answer carries only what the write established; the full
// history lives behind the paged route.
func (p *Publisher) echo(tx oplog.Tx, caller [16]byte, epoch uint32) ([]oplog.MemberWrap, *oplog.Refusal) {
	all, err := tx.MemberWrapsAt(epoch)
	if err != nil {
		return nil, storeDown()
	}
	out := []oplog.MemberWrap{}
	for _, w := range all {
		if w.Member == caller {
			out = append(out, w)
		}
	}
	return out, nil
}

func toEntries(wraps []oplog.MemberWrap) []wire.WrapEntry {
	out := make([]wire.WrapEntry, 0, len(wraps))
	for _, w := range wraps {
		out = append(out, wire.WrapEntry{MemberID: w.Member, KexKeyID: w.KexKeyID, Wrap: w.Wrap})
	}
	return out
}
