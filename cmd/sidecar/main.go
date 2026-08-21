// Command sidecar runs the Micro-Identity Sidecar: a local-first OAuth 2.1 /
// OIDC authorization server plus a pluggable session bridge, meant to run
// as a background daemon alongside an application container so the app
// never has to implement auth itself — it just validates the bearer token
// the sidecar hands it (or asks the sidecar to validate one for it).
package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/micro-identity-sidecar/internal/config"
	"github.com/example/micro-identity-sidecar/internal/keys"
	"github.com/example/micro-identity-sidecar/internal/oidc"
	"github.com/example/micro-identity-sidecar/internal/session"
)

func main() {
	cfg := config.Load()
	log.Printf("micro-identity-sidecar starting | issuer=%s listen=%s alg=%s backend=%s",
		cfg.Issuer, cfg.ListenAddr, cfg.KeyAlgorithm, cfg.SessionBackend)

	stop := make(chan struct{})

	// --- Cryptographic session key rotation ---
	var alg keys.Algorithm
	switch cfg.KeyAlgorithm {
	case "RS256":
		alg = keys.AlgRS256
	default:
		alg = keys.AlgEdDSA
	}
	km, err := keys.NewManager(alg, cfg.KeyRotateEvery, cfg.KeyGracePeriod)
	if err != nil {
		log.Fatalf("failed to initialize key manager: %v", err)
	}
	km.StartRotation(stop)

	// --- Stateful vs. stateless session bridge ---
	var backend session.Backend
	switch cfg.SessionBackend {
	case "file":
		fb, err := session.NewFileBackend(cfg.SessionFilePath)
		if err != nil {
			log.Fatalf("failed to open session file backend: %v", err)
		}
		backend = fb
		log.Printf("stateful session table: file-backed at %s (survives restarts)", cfg.SessionFilePath)
	default:
		backend = session.NewMemoryBackend()
		log.Printf("stateful session table: in-memory (cleared on restart)")
	}

	statelessStore := session.NewJWTStore(km, cfg.Issuer, cfg.StatelessSessionTTL)
	statefulStore := session.NewOpaqueStore(backend, cfg.StatefulSessionTTL)
	statefulStore.StartSweeper(cfg.StatefulSweepEvery, stop)

	bridge := session.NewBridge(statelessStore, statefulStore)

	// Refresh tokens are always stateful (they must be revocable), on
	// their own TTL, sharing the same backend as regular stateful sessions.
	refreshStore := session.NewOpaqueStore(backend, cfg.RefreshTokenTTL)

	// --- Client + user registries (demo data; replace with real stores) ---
	clients := oidc.NewClientRegistry()
	clients.Register(oidc.Client{
		ID:     "demo-spa",
		Public: true, // PKCE-only, no client_secret
		RedirectURIs: []string{
			"http://127.0.0.1:9091/demo/callback",
			"http://localhost:9091/demo/callback",
		},
		SessionMode: string(session.ModeStateless),
	})
	clients.Register(oidc.Client{
		ID:     "demo-confidential-app",
		Secret: "demo-client-secret-change-me",
		RedirectURIs: []string{
			"http://127.0.0.1:9091/demo/callback",
		},
		SessionMode: string(session.ModeStateful),
	})
	users := oidc.NewDemoUserStore()

	// --- OIDC / OAuth 2.1 server ---
	srv := oidc.NewServer(oidc.Config{
		Issuer:             cfg.Issuer,
		AuthCodeTTL:        cfg.AuthCodeTTL,
		RefreshTokenTTL:    cfg.RefreshTokenTTL,
		DefaultSessionMode: session.ModeStateless,
		StatelessTTL:       cfg.StatelessSessionTTL,
		StatefulTTL:        cfg.StatefulSessionTTL,
	}, km, bridge, refreshStore, clients, users)

	mux := srv.Routes()
	mux.HandleFunc("/demo/callback", demoCallbackHandler)

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("listening on http://%s (loopback-only by default — bind wider only behind a trusted network boundary)", cfg.ListenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	log.Println("shutting down...")
	close(stop)
	_ = httpSrv.Close()
}

// demoCallbackHandler is a stand-in redirect_uri so the full PKCE flow can
// be exercised end-to-end with curl/browser without standing up a separate
// app container — it just echoes back what it received.
func demoCallbackHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("Authorization callback received.\n\nQuery: " + r.URL.RawQuery +
		"\n\nExchange this code at POST /token with grant_type=authorization_code, " +
		"the original code_verifier, redirect_uri, and client_id.\n"))
}
