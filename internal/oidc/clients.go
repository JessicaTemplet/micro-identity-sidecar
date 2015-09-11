package oidc

import "sync"

// Client is a registered OAuth/OIDC client (typically the application
// container the sidecar sits next to, or a browser SPA talking to it).
type Client struct {
	ID           string
	Secret       string // empty for public clients (SPAs, mobile) — PKCE covers them
	Public       bool
	RedirectURIs []string
	// SessionMode picks which session.Store backend access tokens minted
	// for this client use by default: "stateless" or "stateful".
	SessionMode string
}

func (c Client) redirectAllowed(uri string) bool {
	for _, r := range c.RedirectURIs {
		if r == uri {
			return true
		}
	}
	return false
}

// ClientRegistry is a simple in-memory client store. A production
// deployment would back this with the sidecar's config file or an admin
// API; the interface boundary here (Get/Register) is what you'd implement
// against a real store.
type ClientRegistry struct {
	mu      sync.RWMutex
	clients map[string]Client
}

func NewClientRegistry() *ClientRegistry {
	return &ClientRegistry{clients: make(map[string]Client)}
}

func (r *ClientRegistry) Register(c Client) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[c.ID] = c
}

func (r *ClientRegistry) Get(id string) (Client, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clients[id]
	return c, ok
}
