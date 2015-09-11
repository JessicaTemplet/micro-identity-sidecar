package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
)

// UserStore authenticates resource owners during the /authorize login
// step. This ships with an in-memory demo implementation so the sidecar is
// runnable standalone; a real deployment should implement this interface
// against whatever identity source the application already has (a users
// table, an LDAP bind, a call out to another service, ...) and wire it in
// at startup instead of DemoUserStore.
type UserStore interface {
	// Authenticate checks credentials and returns a stable subject
	// identifier on success.
	Authenticate(username, password string) (subject string, ok bool)
	// Profile returns OIDC standard claims for a subject, for /userinfo
	// and for embedding in the id_token.
	Profile(subject string) map[string]interface{}
}

type demoUser struct {
	subject  string
	passHash [32]byte
	name     string
	email    string
}

// DemoUserStore is a fixed, in-memory set of credentials for local
// development and for exercising the full authorization code + PKCE flow
// end-to-end without wiring up a real identity backend.
type DemoUserStore struct {
	byUsername map[string]demoUser
}

func NewDemoUserStore() *DemoUserStore {
	mk := func(subject, username, password, name, email string) demoUser {
		return demoUser{
			subject:  subject,
			passHash: sha256.Sum256([]byte(password)),
			name:     name,
			email:    email,
		}
	}
	return &DemoUserStore{
		byUsername: map[string]demoUser{
			"alice": mk("user-alice", "alice", "password123", "Alice Anderson", "alice@example.com"),
			"bob":   mk("user-bob", "bob", "password123", "Bob Barker", "bob@example.com"),
		},
	}
}

func (s *DemoUserStore) Authenticate(username, password string) (string, bool) {
	u, ok := s.byUsername[username]
	if !ok {
		return "", false
	}
	given := sha256.Sum256([]byte(password))
	if subtle.ConstantTimeCompare(given[:], u.passHash[:]) != 1 {
		return "", false
	}
	return u.subject, true
}

func (s *DemoUserStore) Profile(subject string) map[string]interface{} {
	for _, u := range s.byUsername {
		if u.subject == subject {
			return map[string]interface{}{
				"sub":   u.subject,
				"name":  u.name,
				"email": u.email,
			}
		}
	}
	return map[string]interface{}{"sub": subject}
}
