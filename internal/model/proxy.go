package model

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Proxy is the unified proxy node model.
//
// It is backed by a map[string]any to mirror the dynamic nature of the
// original Sub-Store implementation, so protocol-specific and future fields
// can be preserved losslessly through the parse -> process -> produce
// pipeline. Typed accessors are provided for the common fields.
type Proxy struct {
	fields map[string]any
}

// NewProxy creates an empty proxy node.
func NewProxy() *Proxy {
	return &Proxy{fields: map[string]any{}}
}

// ProxyFromMap wraps an existing map into a Proxy.
func ProxyFromMap(m map[string]any) *Proxy {
	if m == nil {
		m = map[string]any{}
	}
	return &Proxy{fields: m}
}

// Fields returns the raw backing map.
func (p *Proxy) Fields() map[string]any {
	return p.fields
}

// Data returns the raw backing map (alias of Fields).
func (p *Proxy) Data() map[string]any {
	return p.fields
}

// Get returns the raw value for a key.
func (p *Proxy) Get(key string) any {
	return p.fields[key]
}

// Has reports whether a key exists (even if its value is nil).
func (p *Proxy) Has(key string) bool {
	_, ok := p.fields[key]
	return ok
}

// Set assigns a value for a key.
func (p *Proxy) Set(key string, val any) {
	p.fields[key] = val
}

// Delete removes a key.
func (p *Proxy) Delete(key string) {
	delete(p.fields, key)
}

// GetString returns a string value, or "" when missing/non-string.
func (p *Proxy) GetString(key string) string {
	switch v := p.fields[key].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case bool:
		return strconv.FormatBool(v)
	default:
		return ""
	}
}

// GetInt returns an int value, or 0 when missing/unparseable.
func (p *Proxy) GetInt(key string) int {
	switch v := p.fields[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		n, _ := strconv.Atoi(v.String())
		return n
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	default:
		return 0
	}
}

// GetBool returns a bool value with a default.
func (p *Proxy) GetBool(key string) bool {
	switch v := p.fields[key].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	case int:
		return v != 0
	case float64:
		return v != 0
	default:
		return false
	}
}

// GetArray returns a []any value, or nil.
func (p *Proxy) GetArray(key string) []any {
	if v, ok := p.fields[key].([]any); ok {
		return v
	}
	if v, ok := p.fields[key].([]string); ok {
		out := make([]any, len(v))
		for i, s := range v {
			out[i] = s
		}
		return out
	}
	return nil
}

// GetMap returns a map[string]any value, or nil.
func (p *Proxy) GetMap(key string) map[string]any {
	if v, ok := p.fields[key].(map[string]any); ok {
		return v
	}
	return nil
}

// Type returns the proxy protocol type.
func (p *Proxy) Type() string { return p.GetString("type") }

// Name returns the display name.
func (p *Proxy) Name() string { return p.GetString("name") }

// Server returns the host.
func (p *Proxy) Server() string { return p.GetString("server") }

// Port returns the port.
func (p *Proxy) Port() int { return p.GetInt("port") }

// SupportedPlatforms returns the supported map (may be nil).
func (p *Proxy) SupportedPlatforms() map[string]any {
	return p.GetMap("supported")
}

// Clone returns a deep copy of the proxy.
func (p *Proxy) Clone() *Proxy {
	raw, _ := json.Marshal(p.fields)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return ProxyFromMap(m)
}

// MarshalJSON serializes the underlying map.
func (p *Proxy) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.fields)
}

// UnmarshalJSON loads the underlying map.
func (p *Proxy) UnmarshalJSON(b []byte) error {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	p.fields = m
	return nil
}

// DisplayName returns a human readable representation for logs/preview.
func (p *Proxy) DisplayName() string {
	if n := p.Name(); n != "" {
		return n
	}
	return fmt.Sprintf("%s %s:%d", p.Type(), p.Server(), p.Port())
}

// IsShadowsocksOverTls reports whether this is an SS node carried over TLS.
func (p *Proxy) IsShadowsocksOverTls() bool {
	if p.Type() != "ss" {
		return false
	}
	plugin := p.GetString("plugin")
	return plugin == "shadow-tls" || plugin == "v2ray-plugin"
}

// GetNested returns a value from a nested map path, e.g. "ws-opts.headers.Host".
func (p *Proxy) GetNested(path string) any {
	parts := strings.Split(path, ".")
	var cur any = p.fields
	for _, part := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[part]
		if !ok {
			return nil
		}
	}
	return cur
}
