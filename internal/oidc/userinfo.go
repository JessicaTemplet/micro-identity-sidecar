package oidc

import (
	"net/http"
	"strings"
)

// handleUserinfo accepts either a stateless or stateful access token
// (whichever the calling client's session mode minted) and returns the
// standard claims for that subject.
func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="sidecar"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "missing bearer access token")
		return
	}
	token := strings.TrimPrefix(auth, "Bearer ")

	sess, _, err := s.bridge.ValidateAny(token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "access token is invalid, expired, or revoked")
		return
	}

	claims := s.users.Profile(sess.Subject)
	claims["sub"] = sess.Subject
	writeJSON(w, http.StatusOK, claims)
}
