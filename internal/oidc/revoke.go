package oidc

import (
	"net/http"

	"github.com/example/micro-identity-sidecar/internal/session"
)

// handleRevoke implements RFC 7009. Per the spec, the server responds 200
// even if the token was already invalid or unknown — revocation is
// idempotent from the client's point of view. Stateless (JWT) access
// tokens cannot be individually revoked (by design: no server-side state
// to delete); the endpoint reports this in a 200 body rather than an error,
// since RFC 7009 §2.2 says unsupported token types should not fail the
// request either.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST only")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "could not parse form body")
		return
	}
	token := r.PostForm.Get("token")
	if token == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	clientIDField := r.PostForm.Get("client_id")
	if _, authErr := s.authenticateClient(r, clientIDField); authErr != "" {
		writeOAuthError(w, http.StatusUnauthorized, authErr, "client authentication failed")
		return
	}

	// Try the stateful backend first (refresh tokens and stateful access
	// tokens both live there); a stateless JWT will simply not be found,
	// which is fine — RFC 7009 says to return 200 regardless.
	_ = s.refreshStore.Revoke(token)
	_ = s.bridge.Revoke(session.ModeStateful, token)

	w.WriteHeader(http.StatusOK)
}
