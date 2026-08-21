// Package oidc implements the Authorization Server surface: OAuth 2.1
// authorization code grant (PKCE required, implicit grant rejected outright),
// OIDC discovery + JWKS, /token, /revoke, and /userinfo.
package oidc

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/example/micro-identity-sidecar/internal/keys"
	"github.com/example/micro-identity-sidecar/internal/session"
)

// authCode is a single-use authorization code bound to the PKCE challenge
// and redirect URI it was issued for, per RFC 9700 / OAuth 2.1 mixup and
// code-injection mitigations.
type authCode struct {
	code                string
	clientID            string
	redirectURI         string
	subject             string
	scope               string
	codeChallenge       string
	codeChallengeMethod string
	nonce               string
	authTime            time.Time
	expiresAt           time.Time
	used                bool
}

// Config bundles the runtime knobs Server needs beyond its collaborators.
type Config struct {
	Issuer          string
	AuthCodeTTL     time.Duration
	RefreshTokenTTL time.Duration
	// DefaultSessionMode is used for clients that don't set SessionMode.
	DefaultSessionMode session.Mode
	// StatelessTTL/StatefulTTL mirror the TTLs the two session.Store
	// backends were actually constructed with, so token responses can
	// report an accurate expires_in without Store exposing its TTL.
	StatelessTTL time.Duration
	StatefulTTL  time.Duration
}

// Server holds every collaborator the OIDC surface needs: the key manager
// (signing/JWKS), the session bridge (stateless/stateful access + ID
// tokens), the client and user registries, and the in-memory auth-code and
// refresh-token bookkeeping that's intrinsic to the authorization code
// grant regardless of session backend.
type Server struct {
	cfg     Config
	keys    *keys.Manager
	bridge  *session.Bridge
	clients *ClientRegistry
	users   UserStore

	mu    sync.Mutex
	codes map[string]*authCode

	// refreshTokens maps an opaque refresh token (stored via the stateful
	// session store, since refresh tokens must be revocable by design) to
	// the subject/client/scope it was issued for. We reuse OpaqueStore's
	// Session shape for this rather than inventing a parallel table.
	refreshStore session.Store

	statelessTTL time.Duration
	statefulTTL  time.Duration
}

func NewServer(cfg Config, km *keys.Manager, bridge *session.Bridge, refreshStore session.Store, clients *ClientRegistry, users UserStore) *Server {
	return &Server{
		cfg:          cfg,
		keys:         km,
		bridge:       bridge,
		clients:      clients,
		users:        users,
		codes:        make(map[string]*authCode),
		refreshStore: refreshStore,
		statelessTTL: cfg.StatelessTTL,
		statefulTTL:  cfg.StatefulTTL,
	}
}

// Routes wires every endpoint into a fresh ServeMux.
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/revoke", s.handleRevoke)
	mux.HandleFunc("/userinfo", s.handleUserinfo)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// ---- shared helpers ----

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("oidc: failed writing JSON response: %v", err)
	}
}

// oauthError writes an RFC 6749 §5.2 / §4.1.2.1 compliant error body.
type oauthErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, oauthErrorBody{Error: code, ErrorDescription: description})
}

func (s *Server) pruneExpiredCodes() {
	now := time.Now()
	for k, c := range s.codes {
		if now.After(c.expiresAt) {
			delete(s.codes, k)
		}
	}
}
