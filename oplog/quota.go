package oplog

import (
	"context"

	"github.com/loonybin/roundelay/wire"
)

// Quota bounds what a Workspace, or one of its members, may add.
//
// The core defines no unit, window or accounting rule, and deliberately so:
// what "consumed" measures is the one part of this that never has to be agreed
// between two implementations, because it changes what an operator charges for
// rather than what any two peers compute. So the measure lives in a deployment
// and this is the whole of the interface to it.
//
// What is protocol, and what the core keeps rather than delegating:
//
//   - the two codes, and that they are distinct — a Workspace out of room and
//     one runaway member are different problems belonging to different people;
//   - that neither carries retry_after_seconds, because waiting is not the
//     remedy, and that neither says anything else at all;
//   - the four routes it may never gate, which is structural here: this is
//     asked on the append path and nowhere else, so reading a log, the vault,
//     authentication and the wrap-set upload cannot be refused for consumption
//     however a deployment answers;
//   - the two exempt classes, which the caller below applies before asking.
type Quota interface {
	// Check is asked once per batch, after every header has been read, and only
	// when the batch is not wholly exempt. A nil refusal admits the batch.
	//
	// member_quota_exhausted carries index, naming the first op at which the
	// bound was crossed. workspace_quota_exhausted carries no index: every op in
	// a batch shares one Workspace, so there is no op for it to name.
	Check(ctx context.Context, workspace, author [16]byte, ops []Op) *Refusal
}

// exemptFromQuota reports whether an op's class is never refused for
// consumption.
//
// 0x80 because revoking a compromised device is a security remedy, and gating
// it on payment makes non-payment a way to keep an attacker's grant alive.
// 0x81 — every payload type, the exemption is stated on the class — because it
// is the remedy *for this refusal*: a Workspace over its allowance gets back
// under it by writing a hard_prune, and a hard_prune is a write. Without the
// exemption the ceiling is terminal rather than recoverable.
func exemptFromQuota(class byte) bool {
	return class == wire.ClassControl || class == wire.ClassPrune
}

// batchIsExempt reports whether every op in the batch is of an exempt class.
//
// Every op, not any: the batch is all-or-nothing, so a hard_prune sent
// alongside a content op is refused with it. That is not a hole in the
// exemption — it is the exemption meeting atomicity, and it means a client with
// recovery to do sends it in a batch of its own.
func batchIsExempt(ops []Op) bool {
	for _, op := range ops {
		if !exemptFromQuota(op.Header().OpClass) {
			return false
		}
	}
	return true
}
