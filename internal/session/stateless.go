package session

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/example/micro-identity-sidecar/internal/jwtutil"
	"github.com/example/micro-identity-sidecar/internal/keys"
)

// JWTStore is the stateless backend: every session is a signed JWT and
// validation never touches shared state, only the current JWKS.
type JWTStore struct {
	km     *keys.Manager
	issuer string
	ttl    time.Duration
}

// NewJWTStore builds a stateless store. ttl bounds how long a minted
// session token is valid; because it can't be revoked early, keep this
// short (minutes, not days) and pair it with refresh-token rotation at the
// OAuth layer for longer-lived login state.
func NewJWTStore(km *keys.Manager, issuer string, ttl time.Duration) *JWTStore {
	return &JWTStore{km: km, issuer: issuer, ttl: ttl}
}

func (s *JWTStore) Kind() string { return "stateless-jwt" }

func (s *JWTStore) Create(sess Session) (string, error) {
	now := time.Now()
	exp := now.Add(s.ttl)
	sess.IssuedAt = now
	sess.ExpiresAt = exp
	if sess.ID == "" {
		var err error
		sess.ID, err = randomID(16)
		if err != nil {
			return "", err
		}
	}

	claims := jwtutil.Claims{
		Issuer:    s.issuer,
		Subject:   sess.Subject,
		Audience:  []string{sess.ClientID},
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
		JWTID:     sess.ID,
		Scope:     sess.Scope,
	}
	if len(sess.Extra) > 0 {
		claims.Extra = map[string]interface{}{}
		for k, v := range sess.Extra {
			claims.Extra[k] = v
		}
	}

	signer := s.km.ActiveSigner()
	token, err := signer.Sign(claims)
	if err != nil {
		return "", fmt.Errorf("sign session jwt: %w", err)
	}
	return token, nil
}

func (s *JWTStore) Validate(token string) (*Session, error) {
	kid, _, err := jwtutil.PeekKid(token)
	if err != nil {
		return nil, ErrNotFound
	}
	verifier, ok := s.km.Verifier(kid)
	if !ok {
		// Key rotated out of the grace window, or token was forged.
		return nil, ErrNotFound
	}
	claims, err := verifier.Verify(token)
	if err != nil {
		return nil, ErrNotFound
	}

	sess := &Session{
		ID:        claims.JWTID,
		Subject:   claims.Subject,
		Scope:     claims.Scope,
		IssuedAt:  time.Unix(claims.IssuedAt, 0),
		ExpiresAt: time.Unix(claims.ExpiresAt, 0),
	}
	if len(claims.Audience) > 0 {
		sess.ClientID = claims.Audience[0]
	}
	if len(claims.Extra) > 0 {
		sess.Extra = map[string]string{}
		for k, v := range claims.Extra {
			if str, ok := v.(string); ok {
				sess.Extra[k] = str
			}
		}
	}
	return sess, nil
}

func (s *JWTStore) Revoke(token string) error {
	return ErrRevocationUnsupported
}

func (s *JWTStore) RevokeAllForSubject(subject string) (int, error) {
	return 0, ErrRevocationUnsupported
}

func randomID(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
