package oidc

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/example/micro-identity-sidecar/internal/jwtutil"
	"github.com/example/micro-identity-sidecar/internal/pkce"
	"github.com/example/micro-identity-sidecar/internal/session"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST only")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "could not parse form body")
		return
	}

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.tokenAuthorizationCode(w, r)
	case "refresh_token":
		s.tokenRefresh(w, r)
	default:
		// Note there is no "implicit" or "password" case: OAuth 2.1 removes
		// the implicit grant, and the resource owner password credentials
		// grant is likewise dropped from the spec.
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			"only authorization_code and refresh_token are supported")
	}
}

// authenticateClient resolves and authenticates the calling client, either
// via HTTP Basic auth or client_secret in the POST body (both are
// permitted by discovery's token_endpoint_auth_methods_supported), or via
// PKCE alone for registered public clients.
func (s *Server) authenticateClient(r *http.Request, clientIDFromBody string) (Client, string) {
	id := clientIDFromBody
	secret := r.PostForm.Get("client_secret")
	if basicID, basicSecret, ok := r.BasicAuth(); ok {
		id, secret = basicID, basicSecret
	}
	client, ok := s.clients.Get(id)
	if !ok {
		return Client{}, "invalid_client"
	}
	if client.Public {
		return client, "" // authenticated by PKCE alone
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(client.Secret)) != 1 {
		return Client{}, "invalid_client"
	}
	return client, ""
}

func (s *Server) sessionModeFor(c Client) session.Mode {
	switch c.SessionMode {
	case string(session.ModeStateful):
		return session.ModeStateful
	case string(session.ModeStateless):
		return session.ModeStateless
	default:
		return s.cfg.DefaultSessionMode
	}
}

func (s *Server) tokenAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	code := r.PostForm.Get("code")
	redirectURI := r.PostForm.Get("redirect_uri")
	verifier := r.PostForm.Get("code_verifier")
	clientIDField := r.PostForm.Get("client_id")

	if code == "" || verifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code and code_verifier are required")
		return
	}

	client, authErr := s.authenticateClient(r, clientIDField)
	if authErr != "" {
		writeOAuthError(w, http.StatusUnauthorized, authErr, "client authentication failed")
		return
	}

	s.mu.Lock()
	ac, ok := s.codes[code]
	if ok {
		delete(s.codes, code) // single-use: consumed on first exchange attempt, success or not
	}
	s.mu.Unlock()

	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown, expired, or already-used authorization code")
		return
	}
	if time.Now().After(ac.expiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code expired")
		return
	}
	if ac.clientID != client.ID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code was not issued to this client")
		return
	}
	if ac.redirectURI != redirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the one used at /authorize")
		return
	}
	if err := pkce.Verify(verifier, ac.codeChallenge); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	s.issueTokenSet(w, client, ac.subject, ac.scope, ac.nonce, ac.authTime)
}

func (s *Server) tokenRefresh(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.PostForm.Get("refresh_token")
	clientIDField := r.PostForm.Get("client_id")
	if refreshToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	client, authErr := s.authenticateClient(r, clientIDField)
	if authErr != "" {
		writeOAuthError(w, http.StatusUnauthorized, authErr, "client authentication failed")
		return
	}

	sess, err := s.refreshStore.Validate(refreshToken)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown, expired, or revoked refresh token")
		return
	}
	if sess.ClientID != client.ID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token was not issued to this client")
		return
	}

	// Rotate: revoke the presented refresh token and mint a replacement.
	// This limits the blast radius of a leaked refresh token to a single
	// use before detection (the legitimate client's next refresh attempt
	// will fail with invalid_grant, signaling the token was compromised).
	_ = s.refreshStore.Revoke(refreshToken)

	s.issueTokenSet(w, client, sess.Subject, sess.Scope, "", sess.IssuedAt)
}

// issueTokenSet mints and writes the access token (via the session bridge,
// per the client's configured mode), an id_token when scope includes
// "openid", and a rotated refresh token when scope includes
// "offline_access".
func (s *Server) issueTokenSet(w http.ResponseWriter, client Client, subject, scope, nonce string, authTime time.Time) {
	mode := s.sessionModeFor(client)

	accessToken, err := s.bridge.Create(mode, session.Session{
		Subject:  subject,
		ClientID: client.ID,
		Scope:    scope,
	})
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to mint access token")
		return
	}

	resp := tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.accessTokenTTL(mode).Seconds()),
		Scope:       scope,
	}

	if hasScope(scope, "openid") {
		idToken, err := s.mintIDToken(client.ID, subject, nonce, authTime)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to mint id_token")
			return
		}
		resp.IDToken = idToken
	}

	if hasScope(scope, "offline_access") {
		refreshToken, err := s.refreshStore.Create(session.Session{
			Subject:  subject,
			ClientID: client.ID,
			Scope:    scope,
		})
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to mint refresh_token")
			return
		}
		resp.RefreshToken = refreshToken
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) accessTokenTTL(mode session.Mode) time.Duration {
	// Mirrors the TTLs the stores themselves were constructed with; kept
	// here too so expires_in in the response is accurate without the
	// Store interface needing to expose its TTL.
	if mode == session.ModeStateful {
		return s.statefulTTL
	}
	return s.statelessTTL
}

func (s *Server) mintIDToken(clientID, subject, nonce string, authTime time.Time) (string, error) {
	now := time.Now()
	claims := jwtutil.Claims{
		Issuer:    s.cfg.Issuer,
		Subject:   subject,
		Audience:  []string{clientID},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(10 * time.Minute).Unix(),
		Extra:     map[string]interface{}{"auth_time": authTime.Unix()},
	}
	if nonce != "" {
		claims.Extra["nonce"] = nonce
	}
	for k, v := range s.users.Profile(subject) {
		if k == "sub" {
			continue
		}
		claims.Extra[k] = v
	}
	return s.keys.ActiveSigner().Sign(claims)
}

func hasScope(scope, want string) bool {
	for _, sc := range strings.Fields(scope) {
		if sc == want {
			return true
		}
	}
	return false
}
