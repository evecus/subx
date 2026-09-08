package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config holds runtime configuration resolved from environment variables.
type Config struct {
	Host          string
	Port          int
	PathPrefix    string
	DataDir       string
	DBPath        string
	JWTSecret     string
	TokenTTLHours int
	AdminUsername string
	AdminPassword string
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// Load reads configuration from environment variables.
//
// Supported variables (all lowercase, no legacy aliases):
//
//	host             listen host, default "0.0.0.0"
//	port             listen port, default 3000
//	data_dir         data directory, default "./data"
//	jwt_secret       JWT signing secret; auto-generated and persisted under
//	                 data_dir if unset
//	token_ttl_hours  login JWT lifetime in hours, default 168 (7 days)
//	auth             admin credentials in "username:password" form,
//	                 default "admin:admin". The admin account always
//	                 reflects this value exactly; it is never persisted
//	                 and nothing else can be used to log in.
//	base_path        URL path prefix for secret-panel access, e.g.
//	                 base_path=/mypanel serves everything under
//	                 http://host:port/mypanel/ and the root path
//	                 returns 404. Empty (default) serves from "/".
func Load() *Config {
	dataDir := getenv("data_dir", "./data")
	adminUsername, adminPassword := parseAuth(getenv("auth", "admin:admin"))
	return &Config{
		Host:          getenv("host", "0.0.0.0"),
		Port:          getenvInt("port", 3000),
		PathPrefix:    normalizePathPrefix(getenv("base_path", "")),
		DataDir:       dataDir,
		DBPath:        filepath.Join(dataDir, "substore.db"),
		JWTSecret:     loadOrCreateJWTSecret(dataDir),
		TokenTTLHours: getenvInt("token_ttl_hours", 24*7),
		AdminUsername: adminUsername,
		AdminPassword: adminPassword,
	}
}

// normalizePathPrefix normalizes the URL path prefix: empty stays empty,
// otherwise the value is guaranteed to start with "/" and never end with
// "/" (e.g. "mypanel/" -> "/mypanel", "/a//b" -> "/a/b").
func normalizePathPrefix(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "/" {
		return ""
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == '/' || r == ' ' })
	if len(parts) == 0 {
		return ""
	}
	return "/" + strings.Join(parts, "/")
}

// parseAuth splits an "auth" value of the form "username:password" into its
// two parts. If the value doesn't contain a ':', or the username part is
// empty, it falls back to the default admin:admin credentials.
func parseAuth(raw string) (username, password string) {
	idx := strings.IndexByte(raw, ':')
	if idx <= 0 || idx == len(raw)-1 {
		return "admin", "admin"
	}
	return raw[:idx], raw[idx+1:]
}

// loadOrCreateJWTSecret returns the configured JWT secret, or generates and
// persists a random one under the data directory so tokens survive restarts.
func loadOrCreateJWTSecret(dataDir string) string {
	if v := os.Getenv("jwt_secret"); v != "" {
		return v
	}
	path := filepath.Join(dataDir, "jwt_secret")
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		return string(b)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "substore-generated-secret"
	}
	secret := hex.EncodeToString(buf)
	if err := os.MkdirAll(dataDir, 0o755); err == nil {
		_ = os.WriteFile(path, []byte(secret), 0o600)
	}
	return secret
}
