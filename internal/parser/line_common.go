package parser

import (
	"strings"

	"substore/internal/model"
)

// TrimQuotes strips a pair of matching surrounding quotes (double or single)
// from a value, mirroring the quoted-string handling of the Sub-Store line
// grammars (Surge/Loon/QX).
func TrimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// isTrue reports whether a string parameter represents a truthy value.
// Values: "1", "true", "yes", "on".
func isTrue(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "1" || s == "true" || s == "yes" || s == "on"
}

// ParseBoolValue parses a boolean-ish string parameter into a Go bool.
// Falsy values are "false", "off", "0", ""; anything else is truthy.
// This mirrors how the Sub-Store line parsers coerce boolean parameters such
// as tls, udp, skip-cert-verify, fast-open, reuse.
func ParseBoolValue(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return !(s == "" || s == "false" || s == "off" || s == "0" || s == "no")
}

// ParseHeadersValue parses a headers string of the form
// "Header:value;Header2:value2" into a map, as used by the QX/Surge line
// formats (e.g. "X-Client:Surge;X-Token:abc").
func ParseHeadersValue(s string) map[string]string {
	out := map[string]string{}
	s = TrimQuotes(s)
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		key := strings.TrimSpace(kv[0])
		if key == "" {
			continue
		}
		val := ""
		if len(kv) == 2 {
			val = strings.TrimSpace(kv[1])
		}
		out[key] = val
	}
	return out
}

// NormalizeCipher canonicalizes a cipher name: lowercases it and maps the
// chacha20-ietf-poly1305 alias to chacha20-poly1305, matching the Sub-Store
// Surge/Loon grammars.
func NormalizeCipher(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	if c == "chacha20-ietf-poly1305" {
		return "chacha20-poly1305"
	}
	return c
}

// EnsureOpts returns the -opts map for a proxy, creating it when missing.
// Keys passed in should be like "ws-opts", "plugin-opts", "hysteria2-opts".
func EnsureOpts(p *model.Proxy, key string) map[string]any {
	opts := p.GetMap(key)
	if opts == nil {
		opts = map[string]any{}
		p.Set(key, opts)
	}
	return opts
}
