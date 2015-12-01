// Command sidecar runs the Micro-Identity Sidecar: a local-first OAuth 2.1 /
// OIDC authorization server plus a pluggable session bridge, meant to run
// as a background daemon alongside an application container so the app
// never has to implement auth itself — it just validates the bearer token
// the sidecar hands it (or asks the sidecar to validate one for it).
package main

import (
	"html/template"
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
	// The demo-spa client is reachable both from a local checkout (loopback
	// redirect URIs) and from wherever this sidecar is actually deployed —
	// cfg.Issuer is that public origin, so its own /demo/callback is always
	// a valid redirect target too. Without this, the "try it" flow on a
	// deployed instance would redirect to a 127.0.0.1 address no real
	// browser can reach.
	demoSPARedirectURIs := []string{
		"http://127.0.0.1:9091/demo/callback",
		"http://localhost:9091/demo/callback",
	}
	if cfg.Issuer != "" {
		demoSPARedirectURIs = append(demoSPARedirectURIs, cfg.Issuer+"/demo/callback")
	}
	clients.Register(oidc.Client{
		ID:           "demo-spa",
		Public:       true, // PKCE-only, no client_secret
		RedirectURIs: demoSPARedirectURIs,
		SessionMode:  string(session.ModeStateless),
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
	mux.HandleFunc("GET /{$}", handleHome(cfg))
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

// homePage is the data passed to homeTemplate.
type homePage struct {
	Issuer string
	Alg    string
}

var homeTemplate = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Micro Identity Sidecar</title>
<style>
  body{font-family:system-ui,-apple-system,sans-serif;max-width:640px;margin:60px auto;padding:0 20px;color:#1a1a1a;line-height:1.55}
  h1{font-size:22px;margin:0 0 4px}
  .sub{color:#666;font-size:14.5px;margin:0 0 28px;max-width:56ch}
  h2{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:#888;margin:34px 0 10px;font-weight:600}
  code{background:#f2f2f2;padding:1px 5px;border-radius:3px;font-size:13px}
  ul{padding-left:20px;margin:0}
  li{margin-bottom:7px;font-size:14.5px}
  .btn{display:inline-block;background:#111;color:#fff;text-decoration:none;padding:10px 18px;border-radius:6px;font-size:14px;font-weight:600;border:none;cursor:pointer;font-family:inherit}
  .btn:hover{background:#333}
  .creds{background:#f7f7f7;border:1px solid #eee;border-radius:6px;padding:10px 14px;font-size:13px;color:#444;margin-top:14px;display:inline-block}
  footer{margin-top:48px;font-size:12px;color:#999}
</style>
</head>
<body>
<h1>Micro Identity Sidecar</h1>
<p class="sub">A local-first OAuth 2.1 / OIDC authorization server, small enough to run as a
sidecar next to whatever actually needs the auth.</p>

<h2>Try it</h2>
<p>This runs a real Authorization Code + PKCE flow against the demo client
<code>demo-spa</code>: it logs you in as a demo user here on this server, then exchanges the
code for tokens right in your browser and shows you the resulting ID token claims.</p>
<button class="btn" id="start-flow">Sign in with demo-spa &rarr;</button>
<div class="creds">Demo users: <code>alice</code> / <code>bob</code> &middot; password <code>password123</code></div>

<h2>What's enforced</h2>
<ul>
  <li>PKCE (S256) is required on every authorization code grant — no <code>plain</code>, no exceptions.</li>
  <li>No implicit grant, no resource-owner-password grant — OAuth 2.1 drops both.</li>
  <li>Refresh tokens are single-use and rotate on every redemption.</li>
  <li>Signing keys ({{.Alg}}) rotate on a schedule with a grace period for tokens already in flight.</li>
</ul>

<h2>Endpoints</h2>
<ul>
  <li><a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a> &mdash; discovery document</li>
  <li><a href="/.well-known/jwks.json">/.well-known/jwks.json</a> &mdash; public signing keys</li>
  <li><code>/authorize</code>, <code>/token</code>, <code>/userinfo</code>, <code>/revoke</code></li>
</ul>

<footer>Issuer: <code>{{.Issuer}}</code></footer>

<script>
function b64url(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
document.getElementById('start-flow').addEventListener('click', async () => {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)).buffer);
  sessionStorage.setItem('sidecar_pkce_verifier', verifier);
  const challenge = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)).buffer);
  const params = new URLSearchParams({
    client_id: 'demo-spa',
    redirect_uri: location.origin + '/demo/callback',
    response_type: 'code',
    scope: 'openid profile email',
    state: state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  location.href = '/authorize?' + params.toString();
});
</script>
</body>
</html>`))

func handleHome(cfg config.Config) http.HandlerFunc {
	page := homePage{Issuer: cfg.Issuer, Alg: cfg.KeyAlgorithm}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = homeTemplate.Execute(w, page)
	}
}

// demoCallbackPage is the static HTML shell for the demo-spa redirect_uri.
// It intentionally does no server-side templating of the query string —
// the authorization `code`/`error` params are read and rendered entirely
// client-side via location.search, so nothing from the URL is ever
// reflected into the response by the server itself.
const demoCallbackPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Callback &middot; Micro Identity Sidecar</title>
<style>
  body{font-family:system-ui,-apple-system,sans-serif;max-width:640px;margin:60px auto;padding:0 20px;color:#1a1a1a;line-height:1.55}
  h1{font-size:20px;margin:0 0 20px}
  h3{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:#888;margin:24px 0 8px;font-weight:600}
  pre{background:#f2f2f2;padding:14px;border-radius:6px;font-size:12.5px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;margin:0}
  .err{color:#b00020}
  a{color:#111}
</style>
</head>
<body>
<h1>Authorization callback</h1>
<div id="status">Exchanging code for tokens…</div>
<div id="result"></div>
<p><a href="/">&larr; back to start</a></p>
<script>
function b64urlDecode(seg) {
  seg = seg.replace(/-/g, '+').replace(/_/g, '/');
  while (seg.length % 4) seg += '=';
  return decodeURIComponent(atob(seg).split('').map(c =>
    '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join(''));
}
(async () => {
  const params = new URLSearchParams(location.search);
  const statusEl = document.getElementById('status');
  const resultEl = document.getElementById('result');

  const error = params.get('error');
  if (error) {
    statusEl.innerHTML = '<span class="err">Authorization error: ' +
      (params.get('error_description') || error) + '</span>';
    return;
  }

  const code = params.get('code');
  const verifier = sessionStorage.getItem('sidecar_pkce_verifier');
  if (!code || !verifier) {
    statusEl.innerHTML = '<span class="err">Missing authorization code or stored code_verifier ' +
      '— start the flow from the <a href="/">home page</a>.</span>';
    return;
  }

  try {
    const res = await fetch('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: location.origin + '/demo/callback',
        client_id: 'demo-spa',
        code_verifier: verifier,
      }),
    });
    const data = await res.json();
    sessionStorage.removeItem('sidecar_pkce_verifier');

    if (!res.ok) {
      statusEl.innerHTML = '<span class="err">Token exchange failed (' + res.status + ')</span>';
      resultEl.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
      return;
    }

    statusEl.textContent = 'Token exchange succeeded.';
    let claimsHtml = '';
    if (data.id_token) {
      const claims = JSON.parse(b64urlDecode(data.id_token.split('.')[1]));
      claimsHtml = '<h3>ID token claims</h3><pre>' + JSON.stringify(claims, null, 2) + '</pre>';
    }
    resultEl.innerHTML = claimsHtml +
      '<h3>Full token response</h3><pre>' + JSON.stringify(data, null, 2) + '</pre>';
  } catch (e) {
    statusEl.innerHTML = '<span class="err">Network error contacting /token</span>';
  }
})();
</script>
</body>
</html>`

// demoCallbackHandler is a stand-in redirect_uri so the full PKCE flow can
// be exercised end-to-end in a real browser: it exchanges the code for
// tokens client-side and displays the resulting ID token claims.
func demoCallbackHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(demoCallbackPage))
}
