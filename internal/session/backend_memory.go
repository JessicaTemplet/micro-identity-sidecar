package session

import (
	"sync"
	"time"
)

// MemoryBackend is a mutex-guarded in-process table. Nothing survives a
// restart; that's the trade Sidecars co-located with a single app instance
// usually happily make in exchange for zero latency and zero moving parts.
type MemoryBackend struct {
	mu   sync.RWMutex
	rows map[string]row
}

func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{rows: make(map[string]row)}
}

func (b *MemoryBackend) Put(tokenHash string, s Session) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rows[tokenHash] = row{Session: s, CreatedAt: time.Now()}
	return nil
}

func (b *MemoryBackend) Get(tokenHash string) (Session, bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	r, ok := b.rows[tokenHash]
	if !ok {
		return Session{}, false, nil
	}
	if r.expired(time.Now()) {
		return Session{}, false, nil
	}
	return r.Session, true, nil
}

func (b *MemoryBackend) Delete(tokenHash string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.rows, tokenHash)
	return nil
}

func (b *MemoryBackend) DeleteWhereSubject(subject string) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for k, r := range b.rows {
		if r.Subject == subject {
			delete(b.rows, k)
			n++
		}
	}
	return n, nil
}

func (b *MemoryBackend) Sweep(now time.Time) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for k, r := range b.rows {
		if r.expired(now) {
			delete(b.rows, k)
			n++
		}
	}
	return n, nil
}

func (b *MemoryBackend) Close() error { return nil }
