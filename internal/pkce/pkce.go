// Package pkce implements RFC 7636 Proof Key for Code Exchange validation.
//
// OAuth 2.1 mandates PKCE for every authorization code grant and drops the
// plain method — only S256 is acceptable, so that's all this package
// supports. Rejecting "plain" outright (rather than merely deprioritizing
// it) is itself part of the 2.1 conformance surface this sidecar advertises.
package pkce

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"regexp"
)

// Method is the only PKCE transform this server accepts.
const MethodS256 = "S256"

// verifierPattern enforces RFC 7636's unreserved character set and length
// bounds (43-128 chars) for code_verifier.
var verifierPattern = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)

// ValidateVerifierFormat checks that a code_verifier is well-formed before
// it's ever compared to anything. Called at /authorize time isn't
// necessary (the verifier isn't sent there) but is used at /token time.
func ValidateVerifierFormat(verifier string) error {
	if !verifierPattern.MatchString(verifier) {
		return errors.New("code_verifier does not match RFC 7636 charset/length rules")
	}
	return nil
}

// Challenge computes the S256 code_challenge for a given verifier:
// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))), no padding.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyMethod rejects anything other than S256 at authorization-request
// time. OAuth 2.1 servers MUST NOT accept "plain".
func VerifyMethod(method string) error {
	if method != MethodS256 {
		return errors.New("unsupported code_challenge_method: only S256 is accepted under OAuth 2.1")
	}
	return nil
}

// Verify checks that a presented code_verifier hashes to the stored
// code_challenge, using a constant-time comparison to avoid timing side
// channels on the derived digest.
func Verify(verifier, storedChallenge string) error {
	if err := ValidateVerifierFormat(verifier); err != nil {
		return err
	}
	computed := Challenge(verifier)
	if subtle.ConstantTimeCompare([]byte(computed), []byte(storedChallenge)) != 1 {
		return errors.New("PKCE verification failed: code_verifier does not match code_challenge")
	}
	return nil
}
