package session

import "time"

// row is what a Backend actually stores per opaque token: the session plus
// the hashed lookup key, kept separate from the public Session type so
// backends don't need to know about JWT-vs-opaque semantics.
type row struct {
	Session
	CreatedAt time.Time
}

// Backend is the storage contract for the stateful session table. Swapping
// backends changes nothing about OpaqueStore's revocation semantics; it
// only changes where the rows live.
//
// Two implementations ship in this package:
//   - MemoryBackend: sync-map-backed, in-process only, fastest, lost on
//     restart. Good default for a sidecar co-located with one app instance.
//   - FileBackend: an append-only journal + periodic snapshot on local
//     disk, so sessions survive a daemon restart without an external DB.
//
// A real SQLite-backed implementation (recommended for multi-process /
// multi-container deployments sharing one sidecar volume) drops in the same
// way — see the "Swapping in real SQLite" section of the README. It isn't
// compiled into this build because the sandbox this was built in can't
// fetch the driver module, but the Backend interface is exactly what a
// `database/sql` + `modernc.org/sqlite` implementation would satisfy:
// CREATE TABLE sessions(token_hash TEXT PRIMARY KEY, subject TEXT,
// client_id TEXT, scope TEXT, issued_at INTEGER, expires_at INTEGER,
// extra_json TEXT), with Put/Get/Delete as parameterized statements and
// DeleteWhere as `DELETE FROM sessions WHERE subject = ?`.
type Backend interface {
	// Put stores or overwrites the row for tokenHash.
	Put(tokenHash string, s Session) error
	// Get returns the row for tokenHash, or found=false if absent/expired.
	Get(tokenHash string) (s Session, found bool, err error)
	// Delete removes a single row. No error if it's already gone.
	Delete(tokenHash string) error
	// DeleteWhereSubject removes every row for a subject, returning the count.
	DeleteWhereSubject(subject string) (count int, err error)
	// Sweep removes every row whose ExpiresAt is before now, returning the count.
	Sweep(now time.Time) (count int, err error)
	// Close releases any resources (file handles, etc).
	Close() error
}
