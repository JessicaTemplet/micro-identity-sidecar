// Package session implements the "Stateful vs. Stateless Session Bridge":
// a single Store interface with two interchangeable implementations.
//
//   - Stateless (JWTStore): sessions are self-contained, crypto-signed JWTs.
//     Validation is a pure signature/expiry check with no I/O, which is why
//     it scales well — but a token can't be un-issued: it's valid until it
//     expires no matter what happens server-side. Keep TTLs short.
//
//   - Stateful (OpaqueStore): sessions are unguessable random strings that
//     are meaningless on their own; every validation looks the row up in a
//     backing table. That lookup is what makes instant, global revocation
//     possible — delete the row and the session is dead everywhere, on the
//     very next request.
//
// Callers pick per session (e.g. "high value" actions get a stateful
// session; routine API traffic gets a stateless one) via the Bridge type in
// bridge.go, or a caller can talk to either Store directly.
package session

import (
	"errors"
	"time"
)

// ErrNotFound is returned when a token doesn't resolve to a live session
// (never existed, expired, or was revoked).
var ErrNotFound = errors.New("session: not found, expired, or revoked")

// ErrRevocationUnsupported is returned by the stateless store's Revoke,
// which cannot honor single-token revocation by design.
var ErrRevocationUnsupported = errors.New("session: stateless (JWT) sessions cannot be individually revoked before expiry; use short TTLs or switch this session to the stateful backend")

// Session is the backend-agnostic view of a live session, regardless of
// whether it's materialized as a JWT or an opaque-token row.
type Session struct {
	ID        string // stable session identifier (jti for JWT, row key for opaque)
	Subject   string // end-user / principal identifier
	ClientID  string // OAuth client this session was minted for
	Scope     string // space-delimited granted scopes
	IssuedAt  time.Time
	ExpiresAt time.Time
	Extra     map[string]string // arbitrary extra claims/metadata (e.g. amr, auth_time)
}

func (s Session) expired(now time.Time) bool {
	return now.After(s.ExpiresAt)
}

// Store is implemented by both the stateless and stateful backends.
type Store interface {
	// Kind identifies the backend for logging/diagnostics ("stateless-jwt"
	// or "stateful-opaque").
	Kind() string

	// Create mints a new session and returns its bearer token — a JWT for
	// the stateless backend, an opaque string for the stateful one.
	Create(s Session) (token string, err error)

	// Validate resolves a bearer token back to the live Session. Returns
	// ErrNotFound if the token is invalid, expired, or revoked.
	Validate(token string) (*Session, error)

	// Revoke invalidates a single token immediately. The stateless backend
	// always returns ErrRevocationUnsupported.
	Revoke(token string) error

	// RevokeAllForSubject invalidates every live session for a subject —
	// e.g. "log this user out everywhere". Returns the count revoked.
	// The stateless backend always returns ErrRevocationUnsupported.
	RevokeAllForSubject(subject string) (int, error)
}
