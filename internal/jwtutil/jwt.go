// Package jwtutil implements minimal, dependency-free JWT (JWS compact
// serialization) encoding/signing/verification for the two algorithms this
// sidecar supports: RS256 (RSA-PKCS1v15 + SHA256) and EdDSA (Ed25519).
//
// It intentionally does not pull in a third-party JWT library: the token
// format is simple enough (base64url(header) "." base64url(payload) "."
// base64url(signature)) that hand-rolling it keeps the trust boundary small
// and auditable, which matters for an auth component.
package jwtutil

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Alg identifies a signing algorithm.
type Alg string

const (
	RS256 Alg = "RS256"
	EdDSA Alg = "EdDSA"
)

// Header is the JOSE header. Kid ties the token to a specific key in the
// JWKS so verifiers can pick the right public key during rotation.
type Header struct {
	Alg Alg    `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Claims is a permissive claim set. Standard RFC 7519 claims are named
// explicitly; anything else round-trips through the Extra map.
type Claims struct {
	Issuer    string                 `json:"iss,omitempty"`
	Subject   string                 `json:"sub,omitempty"`
	Audience  []string               `json:"aud,omitempty"`
	ExpiresAt int64                  `json:"exp,omitempty"`
	NotBefore int64                  `json:"nbf,omitempty"`
	IssuedAt  int64                  `json:"iat,omitempty"`
	JWTID     string                 `json:"jti,omitempty"`
	Scope     string                 `json:"scope,omitempty"`
	Extra     map[string]interface{} `json:"-"`
}

// MarshalJSON flattens Extra into the same JSON object as the named fields,
// so custom OIDC claims (name, email, nonce, ...) sit alongside iss/sub/exp.
func (c Claims) MarshalJSON() ([]byte, error) {
	type alias Claims
	base, err := json.Marshal(alias(c))
	if err != nil {
		return nil, err
	}
	if len(c.Extra) == 0 {
		return base, nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(base, &m); err != nil {
		return nil, err
	}
	for k, v := range c.Extra {
		m[k] = v
	}
	return json.Marshal(m)
}

// UnmarshalJSON does the reverse: known fields populate their struct
// fields, everything else lands in Extra.
func (c *Claims) UnmarshalJSON(data []byte) error {
	type alias Claims
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*c = Claims(a)

	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	known := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true,
		"nbf": true, "iat": true, "jti": true, "scope": true,
	}
	c.Extra = map[string]interface{}{}
	for k, raw := range m {
		if known[k] {
			continue
		}
		var v interface{}
		if err := json.Unmarshal(raw, &v); err == nil {
			c.Extra[k] = v
		}
	}
	return nil
}

// Signer signs claims into a compact JWS. Implementations wrap a specific
// private key + kid + algorithm.
type Signer interface {
	Alg() Alg
	Kid() string
	Sign(claims Claims) (string, error)
}

// Verifier checks a compact JWS signature against a public key.
type Verifier interface {
	Alg() Alg
	Kid() string
	Verify(token string) (*Claims, error)
}

func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func unb64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func signingInput(header Header, claims Claims) (string, []byte, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", nil, err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", nil, err
	}
	input := b64(h) + "." + b64(c)
	return input, []byte(input), nil
}

// ---- RSA (RS256) ----

type rsaSigner struct {
	kid string
	key *rsa.PrivateKey
}

func NewRS256Signer(kid string, key *rsa.PrivateKey) Signer {
	return &rsaSigner{kid: kid, key: key}
}

func (s *rsaSigner) Alg() Alg    { return RS256 }
func (s *rsaSigner) Kid() string { return s.kid }

func (s *rsaSigner) Sign(claims Claims) (string, error) {
	header := Header{Alg: RS256, Typ: "JWT", Kid: s.kid}
	input, raw, err := signingInput(header, claims)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

type rsaVerifier struct {
	kid string
	pub *rsa.PublicKey
}

func NewRS256Verifier(kid string, pub *rsa.PublicKey) Verifier {
	return &rsaVerifier{kid: kid, pub: pub}
}

func (v *rsaVerifier) Alg() Alg    { return RS256 }
func (v *rsaVerifier) Kid() string { return v.kid }

func (v *rsaVerifier) Verify(token string) (*Claims, error) {
	header, claims, signingInput, sig, err := splitToken(token)
	if err != nil {
		return nil, err
	}
	if header.Alg != RS256 {
		return nil, fmt.Errorf("unexpected alg %q, want RS256", header.Alg)
	}
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(v.pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	return checkTimes(claims)
}

// ---- Ed25519 (EdDSA) ----

type edSigner struct {
	kid string
	key ed25519.PrivateKey
}

func NewEdDSASigner(kid string, key ed25519.PrivateKey) Signer {
	return &edSigner{kid: kid, key: key}
}

func (s *edSigner) Alg() Alg    { return EdDSA }
func (s *edSigner) Kid() string { return s.kid }

func (s *edSigner) Sign(claims Claims) (string, error) {
	header := Header{Alg: EdDSA, Typ: "JWT", Kid: s.kid}
	input, raw, err := signingInput(header, claims)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(s.key, raw)
	return input + "." + b64(sig), nil
}

type edVerifier struct {
	kid string
	pub ed25519.PublicKey
}

func NewEdDSAVerifier(kid string, pub ed25519.PublicKey) Verifier {
	return &edVerifier{kid: kid, pub: pub}
}

func (v *edVerifier) Alg() Alg    { return EdDSA }
func (v *edVerifier) Kid() string { return v.kid }

func (v *edVerifier) Verify(token string) (*Claims, error) {
	header, claims, signingInput, sig, err := splitToken(token)
	if err != nil {
		return nil, err
	}
	if header.Alg != EdDSA {
		return nil, fmt.Errorf("unexpected alg %q, want EdDSA", header.Alg)
	}
	if !ed25519.Verify(v.pub, []byte(signingInput), sig) {
		return nil, errors.New("signature verification failed")
	}
	return checkTimes(claims)
}

// ---- shared parsing helpers ----

func splitToken(token string) (Header, Claims, string, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Header{}, Claims{}, "", nil, errors.New("malformed JWT: expected 3 segments")
	}
	hb, err := unb64(parts[0])
	if err != nil {
		return Header{}, Claims{}, "", nil, fmt.Errorf("bad header encoding: %w", err)
	}
	var header Header
	if err := json.Unmarshal(hb, &header); err != nil {
		return Header{}, Claims{}, "", nil, fmt.Errorf("bad header json: %w", err)
	}
	cb, err := unb64(parts[1])
	if err != nil {
		return Header{}, Claims{}, "", nil, fmt.Errorf("bad claims encoding: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(cb, &claims); err != nil {
		return Header{}, Claims{}, "", nil, fmt.Errorf("bad claims json: %w", err)
	}
	sig, err := unb64(parts[2])
	if err != nil {
		return Header{}, Claims{}, "", nil, fmt.Errorf("bad signature encoding: %w", err)
	}
	return header, claims, parts[0] + "." + parts[1], sig, nil
}

func checkTimes(claims Claims) (*Claims, error) {
	now := time.Now().Unix()
	if claims.ExpiresAt != 0 && now > claims.ExpiresAt {
		return nil, errors.New("token expired")
	}
	if claims.NotBefore != 0 && now < claims.NotBefore {
		return nil, errors.New("token not yet valid")
	}
	return &claims, nil
}

// PeekKid extracts the kid from a token's header without verifying the
// signature, so a JWKS-backed verifier registry knows which key to try.
func PeekKid(token string) (string, Alg, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) < 1 {
		return "", "", errors.New("malformed JWT")
	}
	hb, err := unb64(parts[0])
	if err != nil {
		return "", "", err
	}
	var header Header
	if err := json.Unmarshal(hb, &header); err != nil {
		return "", "", err
	}
	return header.Kid, header.Alg, nil
}

// EncodeRSAPublicKeyModExp returns (n, e) base64url-encoded for JWKS "n"/"e".
func EncodeRSAPublicKeyModExp(pub *rsa.PublicKey) (n string, e string) {
	n = b64(pub.N.Bytes())
	eb := big64(pub.E)
	e = b64(eb)
	return
}

func big64(v int) []byte {
	// Minimal big-endian encoding of a small positive int (RSA exponent).
	if v == 0 {
		return []byte{0}
	}
	var out []byte
	for v > 0 {
		out = append([]byte{byte(v & 0xff)}, out...)
		v >>= 8
	}
	return out
}

// EncodeEd25519PublicKey returns the raw public key bytes, base64url encoded
// for JWKS "x".
func EncodeEd25519PublicKey(pub ed25519.PublicKey) string {
	return b64(pub)
}

// MarshalPKCS1PublicKeyDER is a small helper kept here so callers don't need
// to import x509 just to log/debug a key.
func MarshalPKCS1PublicKeyDER(pub *rsa.PublicKey) []byte {
	return x509.MarshalPKCS1PublicKey(pub)
}
