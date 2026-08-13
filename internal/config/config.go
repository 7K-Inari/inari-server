// Package config loads layered configuration: defaults < env (INARI_*).
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr           string
	LogLevel           string
	LogFormat          string
	DatabaseURL        string
	OIDCIssuerURL      string
	OIDCClientID       string
	KeycloakBaseURL    string
	KeycloakRealm      string
	KeycloakAdminUser  string
	KeycloakAdminPass  string
	OpenFGAAPIURL      string
	OpenFGAStoreName   string
	OutboxPollInterval time.Duration
	ShutdownTimeout    time.Duration
}

func Load() (*Config, error) {
	c := &Config{
		HTTPAddr:           env("INARI_HTTP_ADDR", ":8080"),
		LogLevel:           env("INARI_LOG_LEVEL", "info"),
		LogFormat:          env("INARI_LOG_FORMAT", "json"),
		DatabaseURL:        env("INARI_DATABASE_URL", "postgres://inari:inari@localhost:5432/inari?sslmode=disable"),
		OIDCIssuerURL:      env("INARI_OIDC_ISSUER_URL", "http://localhost:8081/realms/inari"),
		OIDCClientID:       env("INARI_OIDC_CLIENT_ID", "inari-server"),
		KeycloakBaseURL:    env("INARI_KEYCLOAK_BASE_URL", "http://localhost:8081"),
		KeycloakRealm:      env("INARI_KEYCLOAK_REALM", "inari"),
		KeycloakAdminUser:  env("INARI_KEYCLOAK_ADMIN_USER", "admin"),
		KeycloakAdminPass:  env("INARI_KEYCLOAK_ADMIN_PASS", "admin"),
		OpenFGAAPIURL:      env("INARI_OPENFGA_API_URL", "http://localhost:8082"),
		OpenFGAStoreName:   env("INARI_OPENFGA_STORE_NAME", "inari"),
		OutboxPollInterval: durEnv("INARI_OUTBOX_POLL_INTERVAL", time.Second),
		ShutdownTimeout:    durEnv("INARI_SHUTDOWN_TIMEOUT", 10*time.Second),
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("config: INARI_DATABASE_URL must not be empty")
	}
	if c.OIDCIssuerURL == "" {
		return nil, fmt.Errorf("config: INARI_OIDC_ISSUER_URL must not be empty")
	}
	return c, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func durEnv(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	return def
}
