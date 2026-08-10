package authority

import (
	"encoding/hex"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/wire"
)

// CheckLink applies the control chain's two rules to one payload.
//
// Control ops form one chain per Workspace across all authors, and the server
// enforces it. Two ops racing on the same predecessor would both land, the
// stored links would stop forming a chain, and a reader's rule would quarantine
// an entirely honest log. Linearity is the property; refusing the loser is what
// maintains it.
//
// tip is the hash of the control tip's payload at this op's position, and
// hasTip is false where no genesis has landed. The link is checked before any
// type-specific rule, so a misplaced genesis with a non-zero link answers
// control_chain_break rather than genesis_not_first.
func CheckLink(payload *ControlPayload, tip [32]byte, hasTip bool) *oplog.Refusal {
	isGenesis := payload.Type == wire.CtlWorkspaceGenesis

	// The zero-link rule is shape, and is asked either way: an all-zero link is
	// genesis-only, in both directions. A device served a truncated history
	// detects it by this rule, because the only op that may claim to be the
	// beginning is the one that genuinely is.
	if isGenesis {
		if payload.PrevControlHash != ZeroLink {
			// A genesis has no predecessor to name, so there is no expected link
			// to report.
			return refuse(unproc, codes.ControlChainBreak, nil)
		}
		return nil
	}
	if payload.PrevControlHash == ZeroLink {
		return breakAt(tip, hasTip)
	}

	// The tip comparison is asked only of a Workspace with an accepted genesis,
	// because before one there is nothing to compare against. A non-genesis
	// control op arriving there is refused by the rules that already answer it.
	if !hasTip {
		return nil
	}
	if payload.PrevControlHash != tip {
		return breakAt(tip, hasTip)
	}
	return nil
}

// breakAt builds the refusal, carrying the link the op should have named.
//
// The field is absent where there is none to name. It exists for the device that
// cannot read: a joining device's member_register is exempt from the access gate
// but not from the chain, and it holds no read on the Workspace until that very
// op lands — so without the field its first op could never be built at all.
func breakAt(tip [32]byte, hasTip bool) *oplog.Refusal {
	if !hasTip {
		return refuse(unproc, codes.ControlChainBreak, nil)
	}
	return refuse(unproc, codes.ControlChainBreak, map[string]any{
		"expected_prev_control_hash": hex.EncodeToString(tip[:]),
	})
}

// Tip is the hash of a control op's payload — what the next control op's
// prev_control_hash must name.
//
// Computed on demand rather than stored. A stored tip is a cache of a function
// of the log, free to drift from it, and the drift is spelled
// control_chain_break on a request that was correct — or, worse the other way, a
// chain the server stopped enforcing. The bytes it is computed from are always
// there: a control op is never a prune target, so no hard_prune can reach its
// envelope.
func Tip(payload []byte) [32]byte { return wire.PayloadHash(payload) }
