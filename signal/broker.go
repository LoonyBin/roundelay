// Package signal is the subscription that carries no data at all — only the
// fact that something happened.
//
// A poke reveals only that activity happened, which is strictly less than the
// read it provokes already reveals. The keepalive fires only in the absence of
// news, so it is the exact complement of a poke and adds nothing to the leak
// surface.
package signal

import (
	"sync"
)

// Event is what a subscriber can be told. There are two, and neither carries
// anything: no position, no author, no count, no envelope. The Workspace is in
// the URL.
type Event uint8

const (
	// Poke means sync from your cursor now.
	Poke Event = iota
	// Evict means this device's registration or last grant is gone, and the
	// socket must close 4403.
	Evict
)

// Broker fans events out to the sockets a process holds.
//
// A deployment running more than one process MUST put a shared broker behind
// this, or subscribers silently miss pokes delivered to whichever process owns
// the writer's connection. The interface is the seam for that: a Postgres
// LISTEN/NOTIFY implementation delivers on transaction commit, which is exactly
// when the poke is owed.
type Broker interface {
	// Subscribe registers a socket. The returned channel coalesces.
	Subscribe(workspace, member [16]byte) *Subscription
	// Notify pokes every subscriber to a Workspace.
	Notify(workspace [16]byte)
	// Evict closes every socket a device holds in a Workspace.
	Evict(workspace, member [16]byte)
}

// Subscription is one socket's feed.
type Subscription struct {
	// C delivers events. It has room for exactly one pending poke, which is what
	// coalescing means here: N appends before the subscriber wakes deliver one
	// poke, and the following read sweeps up everything.
	C chan Event

	broker *Memory
	key    subKey
	id     uint64
	once   sync.Once
}

// Close unregisters the subscription. It is safe to call more than once.
func (s *Subscription) Close() {
	s.once.Do(func() {
		if s.broker != nil {
			s.broker.remove(s.key, s.id)
		}
	})
}

type subKey struct {
	workspace [16]byte
	member    [16]byte
}

// Memory is an in-process broker: the whole fan-out for a single-process
// deployment, and the local half of a multi-process one.
//
// It keeps no per-subscriber state beyond the channel — no cursor, no memory of
// who saw what — because there is none to keep: a poke says only that there is
// news, and the reader's own cursor says what it has not fetched.
type Memory struct {
	mu   sync.Mutex
	subs map[subKey]map[uint64]*Subscription
	next uint64
}

// NewMemory returns an empty broker.
func NewMemory() *Memory { return &Memory{subs: map[subKey]map[uint64]*Subscription{}} }

var _ Broker = (*Memory)(nil)

func (m *Memory) Subscribe(workspace, member [16]byte) *Subscription {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := subKey{workspace, member}
	if m.subs[key] == nil {
		m.subs[key] = map[uint64]*Subscription{}
	}
	m.next++
	s := &Subscription{C: make(chan Event, 1), broker: m, key: key, id: m.next}
	m.subs[key][s.id] = s
	return s
}

func (m *Memory) remove(key subKey, id uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if set := m.subs[key]; set != nil {
		delete(set, id)
		if len(set) == 0 {
			delete(m.subs, key)
		}
	}
}

// Notify pokes every subscriber to a Workspace, whichever device holds it.
func (m *Memory) Notify(workspace [16]byte) {
	m.mu.Lock()
	targets := make([]*Subscription, 0, 8)
	for key, set := range m.subs {
		if key.workspace != workspace {
			continue
		}
		for _, s := range set {
			targets = append(targets, s)
		}
	}
	m.mu.Unlock()

	for _, s := range targets {
		send(s, Poke)
	}
}

// Evict closes every socket a device holds in a Workspace.
func (m *Memory) Evict(workspace, member [16]byte) {
	m.mu.Lock()
	set := m.subs[subKey{workspace, member}]
	targets := make([]*Subscription, 0, len(set))
	for _, s := range set {
		targets = append(targets, s)
	}
	m.mu.Unlock()

	for _, s := range targets {
		send(s, Evict)
	}
}

// send never blocks. A pending poke absorbs another, which is the coalescing
// rule; an eviction displaces a pending poke, because a socket about to close
// has nothing to sync.
func send(s *Subscription, e Event) {
	if e == Evict {
		select {
		case <-s.C:
		default:
		}
	}
	select {
	case s.C <- e:
	default:
	}
}

// EvictAll closes a device's sockets in every Workspace.
//
// The cascade a lost last grant runs is per Workspace — it closes the sockets
// the device holds where the revoke landed — but a control-key amend's is not
// scoped any more narrowly by anything the broker can see, so a caller that
// means "everywhere" says so.
func (m *Memory) EvictAll(member [16]byte) {
	m.mu.Lock()
	targets := make([]*Subscription, 0, 8)
	for key, set := range m.subs {
		if key.member != member {
			continue
		}
		for _, s := range set {
			targets = append(targets, s)
		}
	}
	m.mu.Unlock()

	for _, s := range targets {
		send(s, Evict)
	}
}
