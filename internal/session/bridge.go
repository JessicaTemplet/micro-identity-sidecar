package session

import "fmt"

// Mode is the session backend an application asks for, typically via an
// `?mode=` param or a per-client default in the client registry.
type Mode string

const (
	ModeStateless Mode = "stateless" // JWT
	ModeStateful  Mode = "stateful"  // opaque token, revocable table
)

// Bridge routes session creation/validation to the right Store by Mode,
// and is what lets an application pick "fast, non-revocable" vs
// "revocable, one table lookup" per session without the caller needing to
// know which concrete Store type is behind either choice.
type Bridge struct {
	stateless Store
	stateful  Store
}

func NewBridge(stateless, stateful Store) *Bridge {
	return &Bridge{stateless: stateless, stateful: stateful}
}

func (br *Bridge) storeFor(mode Mode) (Store, error) {
	switch mode {
	case ModeStateless:
		return br.stateless, nil
	case ModeStateful:
		return br.stateful, nil
	default:
		return nil, fmt.Errorf("unknown session mode %q: want %q or %q", mode, ModeStateless, ModeStateful)
	}
}

// Create mints a session token under the requested mode.
func (br *Bridge) Create(mode Mode, s Session) (token string, err error) {
	store, err := br.storeFor(mode)
	if err != nil {
		return "", err
	}
	return store.Create(s)
}

// Validate tries the requested mode's store. Handlers that don't know a
// token's mode ahead of time should use ValidateAny instead.
func (br *Bridge) Validate(mode Mode, token string) (*Session, error) {
	store, err := br.storeFor(mode)
	if err != nil {
		return nil, err
	}
	return store.Validate(token)
}

// ValidateAny tries both backends, stateful first (a table lookup is cheap
// and authoritative), falling back to stateless JWT verification. This is
// what a resource server's auth middleware should call when it accepts
// either token shape on the same endpoint.
func (br *Bridge) ValidateAny(token string) (*Session, Mode, error) {
	if sess, err := br.stateful.Validate(token); err == nil {
		return sess, ModeStateful, nil
	}
	if sess, err := br.stateless.Validate(token); err == nil {
		return sess, ModeStateless, nil
	}
	return nil, "", ErrNotFound
}

// Revoke revokes a single token. Only meaningful (and only succeeds)
// against the stateful backend; stateless tokens return
// ErrRevocationUnsupported so callers can decide how to surface that
// (e.g. "can't revoke, but it expires in under 5 minutes").
func (br *Bridge) Revoke(mode Mode, token string) error {
	store, err := br.storeFor(mode)
	if err != nil {
		return err
	}
	return store.Revoke(token)
}

// RevokeAllForSubject logs a subject out of every *stateful* session
// globally and instantly. Stateless sessions for that subject remain valid
// until they individually expire — callers who need a true "kill switch"
// should issue stateful sessions for anything sensitive.
func (br *Bridge) RevokeAllForSubject(subject string) (int, error) {
	return br.stateful.RevokeAllForSubject(subject)
}
