// Package keys implements the cryptographic session key lifecycle:
// generation, active/retired rotation on a timer, and JWKS publication.
//
// Rotation model:
//   - At any moment there is exactly one *active* key, used to sign new
//     tokens.
//   - Retired keys are kept around for a grace period equal to the maximum
//     token lifetime, so tokens signed just before a rotation still verify
//     until they naturally expire.
//   - The JWKS endpoint publishes the public half of every key still in the
//     grace window (active + retired-but-not-yet-expired), keyed by "kid".
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/example/micro-identity-sidecar/internal/jwtutil"
)

// Algorithm selects which asymmetric primitive the manager generates.
type Algorithm string

const (
	AlgRS256 Algorithm = "RS256"
	AlgEdDSA Algorithm = "EdDSA"
)

// entry is one generated keypair with its lifecycle metadata.
type entry struct {
	kid       string
	alg       Algorithm
	createdAt time.Time
	// retiredAt is zero while the key is active.
	retiredAt time.Time

	rsaPriv *rsa.PrivateKey
	edPriv  ed25519.PrivateKey
}

func (e *entry) signer() jwtutil.Signer {
	switch e.alg {
	case AlgRS256:
		return jwtutil.NewRS256Signer(e.kid, e.rsaPriv)
	case AlgEdDSA:
		return jwtutil.NewEdDSASigner(e.kid, e.edPriv)
	}
	return nil
}

func (e *entry) verifier() jwtutil.Verifier {
	switch e.alg {
	case AlgRS256:
		return jwtutil.NewRS256Verifier(e.kid, &e.rsaPriv.PublicKey)
	case AlgEdDSA:
		return jwtutil.NewEdDSAVerifier(e.kid, e.edPriv.Public().(ed25519.PublicKey))
	}
	return nil
}

// Manager owns the current keyset and rotates it on a timer.
type Manager struct {
	mu sync.RWMutex

	alg         Algorithm
	rotateEvery time.Duration
	gracePeriod time.Duration

	active  *entry
	retired []*entry // kept until past gracePeriod, then dropped

	seq int
}

// NewManager creates a Manager and mints the first active key. Call
// StartRotation to begin the background rotation loop.
func NewManager(alg Algorithm, rotateEvery, gracePeriod time.Duration) (*Manager, error) {
	m := &Manager{alg: alg, rotateEvery: rotateEvery, gracePeriod: gracePeriod}
	first, err := m.generate()
	if err != nil {
		return nil, err
	}
	m.active = first
	return m, nil
}

func (m *Manager) generate() (*entry, error) {
	m.seq++
	kid := fmt.Sprintf("%s-%d-%d", m.alg, time.Now().Unix(), m.seq)
	e := &entry{kid: kid, alg: m.alg, createdAt: time.Now()}
	switch m.alg {
	case AlgRS256:
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate RSA key: %w", err)
		}
		e.rsaPriv = priv
	case AlgEdDSA:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate Ed25519 key: %w", err)
		}
		e.edPriv = priv
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", m.alg)
	}
	return e, nil
}

// StartRotation launches a background goroutine that rotates the active key
// every rotateEvery, and prunes retired keys older than gracePeriod. It
// stops when ctx is cancelled — callers pass a context tied to daemon
// shutdown.
func (m *Manager) StartRotation(stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(m.rotateEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := m.Rotate(); err != nil {
					log.Printf("keys: rotation error: %v", err)
					continue
				}
				m.prune()
			case <-stop:
				return
			}
		}
	}()
}

// Rotate mints a new active key and demotes the current one to retired
// (still valid for verification during the grace period).
func (m *Manager) Rotate() error {
	next, err := m.generate()
	if err != nil {
		return err
	}
	m.mu.Lock()
	prev := m.active
	prev.retiredAt = time.Now()
	m.retired = append(m.retired, prev)
	m.active = next
	m.mu.Unlock()
	log.Printf("keys: rotated active signing key -> kid=%s alg=%s", next.kid, next.alg)
	return nil
}

func (m *Manager) prune() {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().Add(-m.gracePeriod)
	kept := m.retired[:0]
	for _, e := range m.retired {
		if e.retiredAt.After(cutoff) {
			kept = append(kept, e)
		} else {
			log.Printf("keys: dropped expired retired key kid=%s", e.kid)
		}
	}
	m.retired = kept
}

// ActiveSigner returns the signer applications should use right now.
func (m *Manager) ActiveSigner() jwtutil.Signer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active.signer()
}

// Verifier looks up the verifier for a given kid across active + retired
// keys still within their grace window. Used when validating a JWT whose
// header names a specific kid.
func (m *Manager) Verifier(kid string) (jwtutil.Verifier, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active.kid == kid {
		return m.active.verifier(), true
	}
	for _, e := range m.retired {
		if e.kid == kid {
			return e.verifier(), true
		}
	}
	return nil, false
}

// jwk is the JSON Web Key representation for a single key.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// OKP (Ed25519)
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// JWKS renders the current published keyset (active + retired-in-grace) as
// the JSON body for GET /.well-known/jwks.json.
func (m *Manager) JWKS() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	all := append([]*entry{m.active}, m.retired...)
	out := jwks{Keys: make([]jwk, 0, len(all))}
	for _, e := range all {
		switch e.alg {
		case AlgRS256:
			n, ee := jwtutil.EncodeRSAPublicKeyModExp(&e.rsaPriv.PublicKey)
			out.Keys = append(out.Keys, jwk{
				Kty: "RSA", Use: "sig", Alg: "RS256", Kid: e.kid, N: n, E: ee,
			})
		case AlgEdDSA:
			x := jwtutil.EncodeEd25519PublicKey(e.edPriv.Public().(ed25519.PublicKey))
			out.Keys = append(out.Keys, jwk{
				Kty: "OKP", Use: "sig", Alg: "EdDSA", Kid: e.kid, Crv: "Ed25519", X: x,
			})
		}
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return b
}

// ActiveAlg reports the configured algorithm, mainly for the discovery doc.
func (m *Manager) ActiveAlg() Algorithm { return m.alg }
