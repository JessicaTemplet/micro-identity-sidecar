// Command exampleapp is a stand-in "backend application container" that
// demonstrates the whole point of the sidecar pattern: this file contains
// zero OAuth/OIDC/JWT/crypto logic. It only knows how to ask the sidecar
// "is this bearer token good, and who is it for?" via examples/middleware,
// and gets on with serving its actual API.
//
// Run alongside the sidecar:
//
//	go run ./cmd/sidecar &
//	go run ./examples/exampleapp &
//	# then hit the sidecar's /authorize + /token to get an access_token,
//	# and call this app's /api/whoami with it.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/example/micro-identity-sidecar/examples/middleware"
)

func main() {
	sidecarURL := envOr("SIDECAR_URL", "http://127.0.0.1:9091")
	listenAddr := envOr("APP_LISTEN_ADDR", "127.0.0.1:8080")

	validator := middleware.NewRemoteValidator(sidecarURL)

	mux := http.NewServeMux()

	// A public endpoint — no auth required, business as usual.
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// A protected endpoint. All the auth work happened before this
	// handler ever runs; it just reads the principal out of context.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := middleware.FromContext(r.Context())
		if !ok {
			http.Error(w, "no principal in context", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "this handler never saw a token, a JWT, or a key — the sidecar did that",
			"subject": principal.Subject,
			"claims":  principal.Claims,
		})
	})
	mux.Handle("/api/whoami", validator.Middleware(protected))

	log.Printf("example app listening on http://%s (delegating auth to sidecar at %s)", listenAddr, sidecarURL)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
