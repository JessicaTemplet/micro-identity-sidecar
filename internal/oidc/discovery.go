package oidc

import "net/http"

// discoveryDoc is the subset of OpenID Connect Discovery 1.0 metadata this
// sidecar publishes. Notably, response_types_supported advertises only
// "code" — no "token" and no "id_token token" — because implicit and
// hybrid grants are banned under OAuth 2.1.
type discoveryDoc struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "GET only")
		return
	}
	doc := discoveryDoc{
		Issuer:                s.cfg.Issuer,
		AuthorizationEndpoint: s.cfg.Issuer + "/authorize",
		TokenEndpoint:         s.cfg.Issuer + "/token",
		UserinfoEndpoint:      s.cfg.Issuer + "/userinfo",
		JWKSURI:               s.cfg.Issuer + "/.well-known/jwks.json",
		RevocationEndpoint:    s.cfg.Issuer + "/revoke",

		// OAuth 2.1 conformance: authorization code only, PKCE mandatory.
		// No "token" or "id_token token" (implicit/hybrid) response types.
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},

		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{string(s.keys.ActiveAlg())},
		ScopesSupported:                  []string{"openid", "profile", "email", "offline_access"},

		// "none" covers PKCE-only public clients (SPAs/mobile); confidential
		// clients authenticate with a shared secret.
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "name", "email"},
	}
	writeJSON(w, http.StatusOK, doc)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "GET only")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=300") // keys rotate on the order of hours/days
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.keys.JWKS())
}
