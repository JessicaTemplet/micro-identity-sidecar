package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"time"
)

// OpaqueStore is the stateful backend: tokens are unguessable random
// strings with no embedded meaning. Every Validate call is a table lookup,
// which is the whole point — it's what makes RevokeAllForSubject take
// effect instantly and globally, unlike a JWT that lives on until it
// expires no matter what the server does.
type OpaqueStore struct {
	backend Backend
	ttl     time.Duration
}

// NewOpaqueStore builds a stateful store over the given Backend (Memory,
// File, or a future SQL implementation — see backend.go).
func NewOpaqueStore(backend Backend, ttl time.Duration) *OpaqueStore {
	return &OpaqueStore{backend: backend, ttl: ttl}
}

func (s *OpaqueStore) Kind() string { return "stateful-opaque" }

// StartSweeper launches a background goroutine that periodically purges
// expired rows, so a slow trickle of abandoned sessions doesn't grow the
// table forever between explicit revocations.
func (s *OpaqueStore) StartSweeper(every time.Duration, stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				n, err := s.backend.Sweep(time.Now())
				if err != nil {
					log.Printf("session: sweep error: %v", err)
				} else if n > 0 {
					log.Printf("session: swept %d expired stateful session(s)", n)
				}
			case <-stop:
				return
			}
		}
	}()
}

// Create mints a fresh opaque token (32 bytes of CSPRNG output, base64url
// encoded — 256 bits of entropy, unguessable) and stores the session row
// keyed by a hash of the token rather than the token itself, so reading the
// backing store doesn't hand out live bearer credentials.
func (s *OpaqueStore) Create(sess Session) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate opaque token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	now := time.Now()
	sess.IssuedAt = now
	sess.ExpiresAt = now.Add(s.ttl)
	if sess.ID == "" {
		sess.ID = hashToken(token)[:16]
	}

	if err := s.backend.Put(hashToken(token), sess); err != nil {
		return "", fmt.Errorf("store session: %w", err)
	}
	return token, nil
}

func (s *OpaqueStore) Validate(token string) (*Session, error) {
	sess, found, err := s.backend.Get(hashToken(token))
	if err != nil {
		return nil, fmt.Errorf("lookup session: %w", err)
	}
	if !found {
		return nil, ErrNotFound
	}
	return &sess, nil
}

func (s *OpaqueStore) Revoke(token string) error {
	return s.backend.Delete(hashToken(token))
}

func (s *OpaqueStore) RevokeAllForSubject(subject string) (int, error) {
	return s.backend.DeleteWhereSubject(subject)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
