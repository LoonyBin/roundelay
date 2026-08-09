package oplog

import (
	"context"
	"net/http"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/wire"
)

const unproc = http.StatusUnprocessableEntity

// stage3Prune reads a 0x81 body and checks it.
//
// In order: framing, shape, the role's verdict on this payload type, the named
// reprise, then each target in payload order.
//
// The role verdict sits here rather than in stage 2 because 0x81 is one class
// carrying three payload types, and the type it turns on lives in the body —
// which nothing reads before stage 3. It sits after the shape rules on the
// discipline this layer keeps throughout: shape asks whether the payload is a
// well-formed statement at all, authority asks whether this author may make it,
// and the second question is only worth putting to something that parsed.
func (p *Pipeline) stage3Prune(ctx context.Context, tx Tx, op Op, at int64) *Refusal {
	body, r := p.unpack(op)
	if r != nil {
		return r
	}
	payload, r := ParsePrunePayload(body)
	if r != nil {
		return r
	}
	if r := p.Authority.PermitsPruneType(ctx, tx, op.Header().AuthorMemberID, payload.Type); r != nil {
		return r
	}

	if payload.Type == wire.PruneSoft {
		// A prune vouches for its own reprise; someone else's does not count.
		reprise, found, err := tx.OpByOpID(op.Header().AuthorMemberID, payload.RepriseID)
		if err != nil {
			return storeDown()
		}
		if !found {
			return refuse(unproc, codes.PruneRepriseNotFound, nil)
		}
		payload.repriseSeq = reprise.Seq
	}

	for _, t := range payload.Targets {
		if r := p.checkTarget(tx, payload, t); r != nil {
			return r
		}
	}

	// Every target passed, so the effect lands whole.
	for _, t := range payload.Targets {
		var err error
		if payload.Type == wire.PruneHard {
			// A target whose bytes are already gone is not an error and applies
			// nothing a second time — the concurrent case, two folders reclaiming
			// one span.
			err = tx.DropEnvelope(t.Seq)
		} else {
			err = tx.MarkReprised(t.Seq, at)
		}
		if err != nil {
			return storeDown()
		}
	}
	return nil
}

// checkTarget runs the per-target rules for whichever type is being applied.
func (p *Pipeline) checkTarget(tx Tx, payload *PrunePayload, t Target) *Refusal {
	stored, found, err := tx.OpAt(t.Seq)
	if err != nil {
		return storeDown()
	}
	// Never assigned and already gone are different verdicts. A seq whose
	// tombstone is present is found, and the rules below judge it on the
	// tombstone.
	if !found {
		return refuse(unproc, codes.PruneTargetNotFound, nil)
	}

	if payload.Type == wire.PruneHard {
		// Rule 3 precedes rule 4 deliberately. A soft prune refuses a 0x81 target
		// of its own, so no prune op is ever marked reprised: ask about the mark
		// first and every prune target answers "you skipped a step", while the
		// class rule never fires at all.
		if stored.Class == wire.ClassPrune {
			return refuse(unproc, codes.HardPruneTargetIsPrune, nil)
		}
		if !stored.Reprised() {
			return refuse(unproc, codes.HardPruneTargetNotReprised, nil)
		}
		return p.checkAttestation(stored, t)
	}

	// The three exemptions precede the class check on both remaining types:
	// "this is the record, not a record" deserves a verdict of its own, and
	// folding it into "wrong class" would let a client meet the one rule that
	// protects the archive's own evidence and read it as a typo.
	switch {
	case stored.Class == wire.ClassControl:
		return refuse(unproc, codes.PruneTargetIsControl, nil)
	case stored.Class == wire.ClassPrune:
		return refuse(unproc, codes.PruneTargetIsPrune, nil)
	}

	if payload.Type == wire.PruneExt {
		// Rule 4 excludes 0xBF and every other core-assigned server-read class;
		// the one hole in the bit-7 exemption is the class this payload names.
		if wire.ServerReads(stored.Class) && !wire.IsExtension(stored.Class) {
			return refuse(unproc, codes.PruneTargetIsServerRead, nil)
		}
		// Rule 5 catches everything the four above did not, in both directions:
		// another extension class than the one named, and an opaque class.
		if stored.Class != payload.OpClass {
			return refuse(unproc, codes.PruneExtWrongClass, map[string]any{"seq": t.Seq})
		}
		// The attestation precedes the name check, because the name check reads
		// state belonging to the op actually stored — its author's bindings, not
		// the author the payload claims — so it is only worth asking once the
		// author has proved which op they mean.
		if r := p.checkAttestation(stored, t); r != nil {
			return r
		}
		if r := p.checkExtName(tx, payload, stored, t); r != nil {
			return r
		}
	} else {
		// On a soft prune no op whose class has bit 7 set may be a target.
		if wire.ServerReads(stored.Class) {
			return refuse(unproc, codes.PruneTargetIsServerRead, nil)
		}
		if r := p.checkAttestation(stored, t); r != nil {
			return r
		}
	}

	if stored.Reprised() {
		return refuse(unproc, codes.PruneTargetAlreadyReprised, nil)
	}
	if payload.Type == wire.PruneSoft && stored.Seq == payload.repriseSeq {
		return refuse(unproc, codes.PruneTargetIsItsOwnReprise, nil)
	}
	return nil
}

// checkAttestation compares the four fields a target carries against what is
// held.
//
// The server computes the hash the same way a client does — SHA-256 over the
// complete envelope bytes, unframed — because two implementations hashing
// different bytes refuse each other's honest prunes under a code that means
// forgery, and the author is given nothing to tell the two apart.
//
// Where the bytes are gone it compares against the hash the tombstone retains.
// Thirty-two bytes per destroyed op is what keeps "checked" from quietly meaning
// "checked while the bytes happened to still be there".
func (p *Pipeline) checkAttestation(stored *StoredOp, t Target) *Refusal {
	if stored.Author != t.Author ||
		int64(stored.AuthorSeq) != t.AuthorSeq ||
		stored.EnvelopeHash != t.EnvelopeHash {
		return refuse(unproc, codes.PruneTargetAttestationMismatch, nil)
	}
	return nil
}

// checkExtName resolves the target's author's binding interval whose span
// contains the target's position, and compares the NAME it recorded against the
// payload's, byte for byte.
//
// Meaning is positional, so removal is too: an op is folded under the meaning it
// was written with or not at all. The comparison is against the log, never the
// configuration — a prune_ext naming a class the deployment has since
// reconfigured or disabled is not refused on that ground, which is exactly the
// case the type has to serve.
func (p *Pipeline) checkExtName(tx Tx, payload *PrunePayload, stored *StoredOp, t Target) *Refusal {
	name, ok, err := tx.ExtBindingAt(stored.Author, stored.Class, stored.Seq)
	if err != nil {
		return storeDown()
	}
	if !ok {
		// No live interval is not a case and has no code: an op of an extension
		// class cannot exist outside one of its author's intervals, ops are
		// immutable, and positions never move. A server that finds none has lost
		// the binding record, which is a bug rather than a refusal.
		return refuse(http.StatusInternalServerError, codes.StoreUnavailable, nil)
	}
	if name != payload.Name {
		return refuse(unproc, codes.PruneExtNameMismatch, map[string]any{
			"seq": t.Seq, "expected": name,
		})
	}
	return nil
}

// stage3ExtBinding reads a 0xBF body and checks it.
func (p *Pipeline) stage3ExtBinding(ctx context.Context, tx Tx, op Op, at int64) *Refusal {
	body, r := p.unpack(op)
	if r != nil {
		return r
	}
	payload, r := ParseExtBindingPayload(body)
	if r != nil {
		return r
	}
	author := op.Header().AuthorMemberID

	if payload.Type == wire.ExtUnbind {
		// An unbind is looked up under (Workspace, author, op_class). A member can
		// only unbind its own binding — another member's is not found.
		if _, ok, err := tx.LiveExtBinding(author, payload.OpClass); err != nil {
			return storeDown()
		} else if !ok {
			return refuse(unproc, codes.ExtClassNotBound, map[string]any{"op_class": int(payload.OpClass)})
		}
		if err := tx.CloseExtBinding(author, payload.OpClass, at); err != nil {
			return storeDown()
		}
		return nil
	}

	// ext_class_not_enabled is distinct from unsupported_op_class, which answers
	// about the op's own class. A 0xBF op is always a served class; what it
	// *names* may not be.
	expected, enabled := p.Profile.ExtensionName(payload.OpClass)
	if !enabled {
		return refuse(unproc, codes.ExtClassNotEnabled, map[string]any{"op_class": int(payload.OpClass)})
	}
	// A class is never bound under a name the server does not agree with. The
	// NAME is what turns a silent divergence into a loud one.
	if payload.Name != expected {
		return refuse(unproc, codes.ExtNameMismatch, map[string]any{
			"op_class": int(payload.OpClass), "expected": expected,
		})
	}
	if _, ok, err := tx.LiveExtBinding(author, payload.OpClass); err != nil {
		return storeDown()
	} else if ok {
		return refuse(http.StatusConflict, codes.ExtClassAlreadyBound, map[string]any{
			"op_class": int(payload.OpClass),
		})
	}
	if err := tx.OpenExtBinding(author, payload.OpClass, payload.Name, at); err != nil {
		return storeDown()
	}
	return nil
}

// checkExtensionOp judges an op of an extension class against its author's own
// live binding.
//
// The stage this belongs to is not stated. Stage 2 is "does the Workspace exist,
// does the role allow it, is the epoch current enough" and stage 3 is "prune and
// ext_binding: read the body" — and an extension-class op is neither. It runs
// here, after stage 2 and before the op is stored, because it reads no body and
// must precede any effect the class would cause. Only the verdict is protocol.
//
// Member scoping is what makes the check answerable at all. A Workspace-wide
// binding is a value that can move under an author who has not caught up, and no
// client-side check prevents that, because every client's view of the log is
// stale by construction. A member learns at its own write, synchronously, and
// never needs to have seen another member's op.
func (p *Pipeline) checkExtensionOp(tx Tx, op Op) *Refusal {
	class := op.Header().OpClass
	name, ok, err := tx.LiveExtBinding(op.Header().AuthorMemberID, class)
	if err != nil {
		return storeDown()
	}
	if !ok {
		return refuse(unproc, codes.ExtClassNotActive, map[string]any{"op_class": int(class)})
	}
	// A server MUST NOT reinterpret an op under a meaning its author never agreed
	// to. Checking the name only when the binding lands is not enough: an
	// operator may reconfigure the class in between.
	expected, enabled := p.Profile.ExtensionName(class)
	if !enabled || name != expected {
		return refuse(unproc, codes.ExtNameMismatch, map[string]any{
			"op_class": int(class), "expected": expected,
		})
	}
	return nil
}
