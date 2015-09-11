package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/example/micro-identity-sidecar/internal/pkce"
)

var loginTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html>
<head><title>Sign in</title>
<style>
body{font-family:system-ui,sans-serif;max-width:360px;margin:80px auto;color:#222}
input{display:block;width:100%;box-sizing:border-box;padding:8px;margin:6px 0 14px;font-size:14px}
button{padding:8px 16px;font-size:14px;cursor:pointer}
.client{color:#666;font-size:13px;margin-bottom:20px}
.err{color:#b00020;font-size:13px;margin-bottom:12px}
</style>
</head>
<body>
<h2>Sign in</h2>
<p class="client">{{.ClientID}} is requesting access{{if .Scope}} to: {{.Scope}}{{end}}</p>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="POST" action="/authorize">
  <input type="text" name="username" placeholder="username" autofocus required>
  <input type="password" name="password" placeholder="password" required>
  <input type="hidden" name="client_id" value="{{.ClientID}}">
  <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
  <input type="hidden" name="response_type" value="{{.ResponseType}}">
  <input type="hidden" name="scope" value="{{.Scope}}">
  <input type="hidden" name="state" value="{{.State}}">
  <input type="hidden" name="nonce" value="{{.Nonce}}">
  <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
  <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
  <button type="submit">Sign in</button>
</form>
<p class="client">demo users: alice / bob, password: password123</p>
</body>
</html>`))

type loginPage struct {
	ClientID, RedirectURI, ResponseType, Scope, State, Nonce string
	CodeChallenge, CodeChallengeMethod                       string
	Error                                                    string
}

// handleAuthorize implements the authorization endpoint for GET (render
// login) and POST (process credentials + issue code). OAuth 2.1
// requirements enforced here:
//   - response_type MUST be "code" — "token" and hybrid types are rejected
//     outright, since implicit grant is banned.
//   - code_challenge + code_challenge_method=S256 are REQUIRED, not
//     optional, for every client (public or confidential).
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.authorizeShowLogin(w, r)
	case http.MethodPost:
		s.authorizeProcessLogin(w, r)
	default:
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "GET or POST only")
	}
}

// validated holds the request parameters once they've passed OAuth 2.1
// structural checks, shared by both the GET and POST paths.
type validatedAuthRequest struct {
	client              Client
	redirectURI         string
	scope               string
	state               string
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
}

// validateAuthRequest performs every check that must happen before we
// trust the redirect_uri enough to send errors *to* it (per RFC 6749
// §4.1.2.1, invalid client_id/redirect_uri errors are shown to the
// resource owner directly, never redirected).
func (s *Server) validateAuthRequest(r *http.Request) (*validatedAuthRequest, string, int) {
	var q url.Values
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		q = r.Form
	} else {
		q = r.URL.Query()
	}

	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	scope := q.Get("scope")
	state := q.Get("state")
	nonce := q.Get("nonce")
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")

	client, ok := s.clients.Get(clientID)
	if !ok {
		return nil, "unknown client_id", http.StatusBadRequest
	}
	if !client.redirectAllowed(redirectURI) {
		return nil, "redirect_uri is not registered for this client", http.StatusBadRequest
	}
	// Everything past this point is safe to report via redirect, since the
	// redirect_uri itself is now trusted.

	if responseType != "code" {
		return nil, "unsupported_response_type: only 'code' is supported (OAuth 2.1 removes the implicit grant)", http.StatusBadRequest
	}
	if challenge == "" {
		return nil, "code_challenge is required (OAuth 2.1 mandates PKCE for every authorization code grant)", http.StatusBadRequest
	}
	if err := pkce.VerifyMethod(method); err != nil {
		return nil, err.Error(), http.StatusBadRequest
	}

	return &validatedAuthRequest{
		client: client, redirectURI: redirectURI, scope: scope, state: state,
		nonce: nonce, codeChallenge: challenge, codeChallengeMethod: method,
	}, "", 0
}

func (s *Server) authorizeShowLogin(w http.ResponseWriter, r *http.Request) {
	req, errMsg, status := s.validateAuthRequest(r)
	if req == nil {
		writeOAuthError(w, status, "invalid_request", errMsg)
		return
	}
	page := loginPage{
		ClientID: req.client.ID, RedirectURI: req.redirectURI, ResponseType: "code",
		Scope: req.scope, State: req.state, Nonce: req.nonce,
		CodeChallenge: req.codeChallenge, CodeChallengeMethod: req.codeChallengeMethod,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTemplate.Execute(w, page)
}

func (s *Server) authorizeProcessLogin(w http.ResponseWriter, r *http.Request) {
	req, errMsg, status := s.validateAuthRequest(r)
	if req == nil {
		writeOAuthError(w, status, "invalid_request", errMsg)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	subject, ok := s.users.Authenticate(username, password)
	if !ok {
		page := loginPage{
			ClientID: req.client.ID, RedirectURI: req.redirectURI, ResponseType: "code",
			Scope: req.scope, State: req.state, Nonce: req.nonce,
			CodeChallenge: req.codeChallenge, CodeChallengeMethod: req.codeChallengeMethod,
			Error: "Invalid username or password.",
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_ = loginTemplate.Execute(w, page)
		return
	}

	code, err := randomToken(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to generate authorization code")
		return
	}

	s.mu.Lock()
	s.pruneExpiredCodes()
	s.codes[code] = &authCode{
		code:                code,
		clientID:            req.client.ID,
		redirectURI:         req.redirectURI,
		subject:             subject,
		scope:               req.scope,
		codeChallenge:       req.codeChallenge,
		codeChallengeMethod: req.codeChallengeMethod,
		nonce:               req.nonce,
		authTime:            time.Now(),
		expiresAt:           time.Now().Add(s.cfg.AuthCodeTTL),
	}
	s.mu.Unlock()

	dest, _ := url.Parse(req.redirectURI)
	values := dest.Query()
	values.Set("code", code)
	if req.state != "" {
		values.Set("state", req.state)
	}
	dest.RawQuery = values.Encode()
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

func randomToken(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
