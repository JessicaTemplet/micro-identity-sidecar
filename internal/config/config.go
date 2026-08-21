// Package config centralizes daemon configuration, loaded from environment
// variables (the norm for a sidecar dropped into an existing container/pod)
// with sensible local-first defaults so it runs with zero config out of the
// box.
package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	// ListenAddr is where the sidecar's HTTP server binds. Defaults to
	// loopback-only, since a sidecar talks to its co-located app over
	// localhost, not the network.
	ListenAddr string

	// Issuer is the `iss` claim / discovery document base URL. In a real
	// deployment this is usually the sidecar's own address as seen by the
	// application container (e.g. http://localhost:9091).
	Issuer string

	// KeyAlgorithm selects RS256 or EdDSA for signing.
	KeyAlgorithm   string // "RS256" | "EdDSA"
	KeyRotateEvery time.Duration
	KeyGracePeriod time.Duration

	// StatelessSessionTTL bounds JWT session lifetime (short, since these
	// can't be revoked early).
	StatelessSessionTTL time.Duration
	// StatefulSessionTTL bounds opaque session lifetime.
	StatefulSessionTTL time.Duration
	// StatefulSweepEvery controls how often expired stateful rows are purged.
	StatefulSweepEvery time.Duration

	// SessionBackend selects the stateful table implementation: "memory" or "file".
	SessionBackend string
	// SessionFilePath is used when SessionBackend == "file".
	SessionFilePath string

	// AuthCodeTTL bounds how long an issued authorization code is valid.
	AuthCodeTTL time.Duration
	// RefreshTokenTTL bounds refresh token validity.
	RefreshTokenTTL time.Duration
}

func Load() Config {
	return Config{
		ListenAddr:          getEnv("SIDECAR_LISTEN_ADDR", "127.0.0.1:9091"),
		Issuer:              getEnv("SIDECAR_ISSUER", "http://127.0.0.1:9091"),
		KeyAlgorithm:        getEnv("SIDECAR_KEY_ALG", "EdDSA"),
		KeyRotateEvery:      getDuration("SIDECAR_KEY_ROTATE_EVERY", 24*time.Hour),
		KeyGracePeriod:      getDuration("SIDECAR_KEY_GRACE_PERIOD", 48*time.Hour),
		StatelessSessionTTL: getDuration("SIDECAR_STATELESS_TTL", 5*time.Minute),
		StatefulSessionTTL:  getDuration("SIDECAR_STATEFUL_TTL", 12*time.Hour),
		StatefulSweepEvery:  getDuration("SIDECAR_SWEEP_EVERY", 1*time.Minute),
		SessionBackend:      getEnv("SIDECAR_SESSION_BACKEND", "memory"),
		SessionFilePath:     getEnv("SIDECAR_SESSION_FILE", "sessions.db"),
		AuthCodeTTL:         getDuration("SIDECAR_AUTHCODE_TTL", 60*time.Second),
		RefreshTokenTTL:     getDuration("SIDECAR_REFRESH_TTL", 30*24*time.Hour),
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func getBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

var _ = getBool // reserved for future boolean flags (e.g. feature toggles)
