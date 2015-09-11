package session

import (
	"encoding/gob"
	"fmt"
	"os"
	"sync"
	"time"
)

// FileBackend persists the session table to a single local file so it
// survives a daemon restart, without requiring a cgo SQLite driver. Every
// mutation rewrites a full snapshot under a lock; for a sidecar's expected
// row counts (thousands, not millions, of live sessions) this is simpler
// and plenty fast, and it keeps the whole build dependency-free. For higher
// throughput or multi-writer access, implement Backend against
// database/sql + a pure-Go SQLite driver instead — see backend.go.
type FileBackend struct {
	mu   sync.Mutex
	path string
	rows map[string]row
}

func NewFileBackend(path string) (*FileBackend, error) {
	b := &FileBackend{path: path, rows: make(map[string]row)}
	if err := b.load(); err != nil {
		return nil, fmt.Errorf("load session file %s: %w", path, err)
	}
	return b, nil
}

func (b *FileBackend) load() error {
	f, err := os.Open(b.path)
	if os.IsNotExist(err) {
		return nil // fresh table
	}
	if err != nil {
		return err
	}
	defer f.Close()
	dec := gob.NewDecoder(f)
	var rows map[string]row
	if err := dec.Decode(&rows); err != nil {
		return err
	}
	b.rows = rows
	return nil
}

// snapshot must be called with b.mu held.
func (b *FileBackend) snapshot() error {
	tmp := b.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := gob.NewEncoder(f)
	if err := enc.Encode(b.rows); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, b.path) // atomic on the same filesystem
}

func (b *FileBackend) Put(tokenHash string, s Session) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rows[tokenHash] = row{Session: s, CreatedAt: time.Now()}
	return b.snapshot()
}

func (b *FileBackend) Get(tokenHash string) (Session, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.rows[tokenHash]
	if !ok || r.expired(time.Now()) {
		return Session{}, false, nil
	}
	return r.Session, true, nil
}

func (b *FileBackend) Delete(tokenHash string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.rows[tokenHash]; !ok {
		return nil
	}
	delete(b.rows, tokenHash)
	return b.snapshot()
}

func (b *FileBackend) DeleteWhereSubject(subject string) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for k, r := range b.rows {
		if r.Subject == subject {
			delete(b.rows, k)
			n++
		}
	}
	if n > 0 {
		if err := b.snapshot(); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (b *FileBackend) Sweep(now time.Time) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for k, r := range b.rows {
		if r.expired(now) {
			delete(b.rows, k)
			n++
		}
	}
	if n > 0 {
		if err := b.snapshot(); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (b *FileBackend) Close() error { return nil }
