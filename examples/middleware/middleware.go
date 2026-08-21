// Package middleware is a worked example of the other half of the sidecar
// pattern: how the application container validates a bearer token the
// sidecar minted, WITHOUT reimplementing any auth logic itself.
//
// Two integration styles are shown:
//
//  1. Local() — the fast path. The app links this package directly (or a
//     port of it in another language), fetches the sidecar's JWKS once and
//     caches it, and verifies stateless JWTs in-process with zero network
//     calls per request. This only works for stateless sessions, since
//     stateful ones are opaque strings with no verifiable structure.
//
//  2. Remote() — the simple path. The app calls the sidecar's own
//     /userinfo endpoint on every request and trusts its answer. Works for
//     both session types uniformly, costs one loopback HTTP round trip per
//     request. This is usually the right default: a sidecar's whole
//     premise is being co-located on localhost, so the round trip is cheap,
//     and it means app code never needs to know which session mode a given
//     token uses.
//
// A real app typically only needs Remote(); Local() is included to show
// the latency/complexity trade-off explicitly, since "decouple auth logic
// from backend code entirely" doesn't mean "the backend can't ever look at
// a token" — it means the backend never implements OAuth/OIDC/crypto
// itself, which both styles satisfy.
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Principal is what request handlers get after successful auth, regardless
// of which validation style produced it.
type Principal struct {
	Subject string
	Claims  map[string]interface{}
}

type principalKey struct{}

// FromContext retrieves the authenticated Principal a middleware attached
// to the request context, if any.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok
}

// ---- Style 2: Remote (/userinfo round trip) ----

// RemoteValidator calls the sidecar's /userinfo endpoint to validate a
// bearer token. It works uniformly for stateless and stateful tokens,
// which is the point: the app never has to know or care which kind it got.
type RemoteValidator struct {
	SidecarBaseURL string
	HTTPClient     *http.Client
}

func NewRemoteValidator(sidecarBaseURL string) *RemoteValidator {
	return &RemoteValidator{
		SidecarBaseURL: strings.TrimRight(sidecarBaseURL, "/"),
		HTTPClient:     &http.Client{Timeout: 3 * time.Second},
	}
}

func (v *RemoteValidator) Validate(ctx context.Context, token string) (*Principal, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.SidecarBaseURL+"/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := v.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling sidecar /userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sidecar rejected token: status %d", resp.StatusCode)
	}
	var claims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("decoding /userinfo response: %w", err)
	}
	sub, _ := claims["sub"].(string)
	return &Principal{Subject: sub, Claims: claims}, nil
}

// Middleware returns an http.Handler wrapper that authenticates every
// request via the sidecar and rejects unauthenticated ones with 401,
// mirroring RFC 6750 bearer-token error semantics.
func (v *RemoteValidator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="app"`)
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")

		principal, err := v.Validate(r.Context(), token)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), principalKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ---- Style 1: Local (cached JWKS, in-process JWT verification) ----

// jwk mirrors the subset of RFC 7517 fields the sidecar publishes.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// LocalValidator caches the sidecar's JWKS and verifies stateless JWTs
// entirely in-process. It only handles stateless (JWT) tokens — pass a
// stateful (opaque) token to Validate and it will correctly fail, since
// there's nothing in an opaque string for a JWKS to verify. An app that
// mixes both session modes should fall back to RemoteValidator, or simply
// use RemoteValidator everywhere and skip this type.
//
// NOTE: this file intentionally reuses the same minimal JWT-parsing
// approach as the sidecar itself (see internal/jwtutil in the sidecar
// module) rather than importing it directly, so this package can be
// vendored into a separate application repository standalone.
type LocalValidator struct {
	jwksURL string
	issuer  string
	client  *http.Client

	mu        sync.RWMutex
	keys      map[string]jwk
	fetchedAt time.Time
	ttl       time.Duration
}

func NewLocalValidator(sidecarBaseURL, issuer string) *LocalValidator {
	return &LocalValidator{
		jwksURL: strings.TrimRight(sidecarBaseURL, "/") + "/.well-known/jwks.json",
		issuer:  issuer,
		client:  &http.Client{Timeout: 3 * time.Second},
		keys:    map[string]jwk{},
		ttl:     5 * time.Minute,
	}
}

func (v *LocalValidator) refreshIfStale(ctx context.Context) error {
	v.mu.RLock()
	stale := time.Since(v.fetchedAt) > v.ttl
	v.mu.RUnlock()
	if !stale {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetching JWKS: %w", err)
	}
	defer resp.Body.Close()

	var doc jwks
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("decoding JWKS: %w", err)
	}

	v.mu.Lock()
	v.keys = make(map[string]jwk, len(doc.Keys))
	for _, k := range doc.Keys {
		v.keys[k.Kid] = k
	}
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}

// Validate is deliberately left as a documented stub for the header/kid
// lookup step rather than a full duplicate JWT-verification implementation:
// wire in a JWT library of your app's choosing (or vendor the sidecar's
// internal/jwtutil package) and use LocalValidator only for the "which
// public key does this kid mean, and is my cache still fresh" bookkeeping
// shown above. Most applications should just use RemoteValidator; reach
// for this path only once /userinfo round trips are a measured bottleneck.
func (v *LocalValidator) Validate(ctx context.Context, token string) (*Principal, error) {
	if err := v.refreshIfStale(ctx); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("LocalValidator.Validate: plug in your JWT library's " +
		"verification call here, using Keys(kid) below to resolve the signing key")
}

// Keys returns the currently cached JWK for a kid, refreshing first if the
// cache is stale. Use this to resolve the key a JWT library needs to verify
// a token's signature.
func (v *LocalValidator) Keys(ctx context.Context, kid string) (jwk, bool, error) {
	if err := v.refreshIfStale(ctx); err != nil {
		return jwk{}, false, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	k, ok := v.keys[kid]
	return k, ok, nil
}
