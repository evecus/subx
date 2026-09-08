package parser

import (
	"encoding/json"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"substore/internal/model"
)

// clashSupportedParserTypes are the proxy types the Clash parser accepts.
// This mirrors Sub-Store's Clash_All parser which validates the type field.
var clashSupportedParserTypes = map[string]bool{
	"ss": true, "ssr": true, "vmess": true, "vless": true,
	"socks5": true, "http": true, "snell": true, "trojan": true,
	"tuic": true, "hysteria": true, "hysteria2": true,
	"wireguard": true, "ssh": true, "anytls": true,
	"juicity": true, "naive": true, "direct": true,
	"mieru": true, "masque": true, "sudoku": true,
	"shadowquic": true, "gost-relay": true,
	"openvpn": true, "tailscale": true, "trusttunnel": true,
	"h2-connect": true,
	"zerotier": true,
}

func init() {
	MustRegister(
		&Parser{Name: "Clash Proxy Parser",
			Test: func(line string) bool {
				// mirrors Sub-Store's Clash_All test (index.js:2522-2530):
				// try JSON first, fall back to YAML, and accept any
				// document carrying a "type" key (block-style YAML
				// single proxies included)
				t := strings.TrimSpace(line)
				t = strings.TrimSpace(strings.TrimPrefix(t, "-"))
				var fields map[string]any
				if err := json.Unmarshal([]byte(t), &fields); err != nil {
					fields = nil
					if err := yaml.Unmarshal([]byte(t), &fields); err != nil {
						return false
					}
				}
				typ, _ := fields["type"].(string)
				return typ != ""
			},
			Parse: parseClashLine,
		},
	)
}

// parseClashLine parses a single Clash proxy definition given as inline JSON
// or inline YAML map.
func parseClashLine(line string) (*model.Proxy, error) {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "-")
	line = strings.TrimSpace(line)

	var fields map[string]any
	if strings.HasPrefix(line, "{") {
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			if err := yaml.Unmarshal([]byte(line), &fields); err != nil {
				return nil, err
			}
		}
	} else {
		if err := yaml.Unmarshal([]byte(line), &fields); err != nil {
			return nil, err
		}
	}
	if fields == nil {
		return nil, errInvalidJSON
	}
	typ, _ := fields["type"].(string)
	if typ == "" {
		return nil, errInvalidJSON
	}
	// Validate type is supported (mirrors Sub-Store's Clash_All parser)
	if !clashSupportedParserTypes[typ] {
		return nil, errInvalidJSON
	}

	p := model.NewProxy()
	p.Set("type", typ)
	for k, v := range fields {
		switch k {
		case "udp":
			p.Set("udp", toBool(v))
		// "tfo"/"fast-open" and "port-range" pass through untouched
		// (mirrors Clash_All's whole-object passthrough, index.js:2531-2599)
		case "skip-cert-verify", "allow-insecure":
			p.Set("skip-cert-verify", toBool(v))
		case "port":
			p.Set(k, toInt(v))
		case "tls":
			p.Set("tls", toBool(v))
		default:
			p.Set(k, v)
		}
	}

	// Normalizations mirroring Sub-Store's Clash_All parser:

	// vmess/vless: servername -> sni
	if typ == "vmess" || typ == "vless" {
		if sn := p.GetString("servername"); sn != "" {
			p.Set("sni", sn)
			p.Delete("servername")
		}
	}

	// server-cert-fingerprint / fingerprint -> tls-fingerprint
	// (JS adds the mapped key without deleting the originals)
	if v := p.GetString("server-cert-fingerprint"); v != "" {
		p.Set("tls-fingerprint", v)
	}
	if v := p.GetString("fingerprint"); v != "" {
		p.Set("tls-fingerprint", v)
	}

	// dialer-proxy -> underlying-proxy
	if v := p.GetString("dialer-proxy"); v != "" {
		p.Set("underlying-proxy", v)
	}

	// benchmark-url -> test-url
	if v := p.GetString("benchmark-url"); v != "" {
		p.Set("test-url", v)
	}
	// benchmark-timeout -> test-timeout (value copied as-is, may be a number)
	if v := p.Get("benchmark-timeout"); v != nil && v != "" {
		p.Set("test-timeout", v)
	}

	// vmess cipher normalization
	if typ == "vmess" {
		if c := p.GetString("cipher"); c != "" {
			p.Set("cipher", normalizeVmessSecurity(c))
		}
	}

	// wireguard: keepalive <-> persistent-keepalive, preshared-key <-> pre-shared-key
	if typ == "wireguard" {
		if v := p.GetString("keepalive"); v != "" && !p.Has("persistent-keepalive") {
			p.Set("persistent-keepalive", v)
		}
		if v := p.GetString("persistent-keepalive"); v != "" && !p.Has("keepalive") {
			p.Set("keepalive", v)
		}
		if v := p.GetString("preshared-key"); v != "" && !p.Has("pre-shared-key") {
			p.Set("pre-shared-key", v)
		}
		if v := p.GetString("pre-shared-key"); v != "" && !p.Has("preshared-key") {
			p.Set("preshared-key", v)
		}
	}

	if p.GetString("name") == "" {
		p.Set("name", typ+" "+p.Server())
	}
	return p, nil
}

// normalizeVmessSecurity normalizes vmess cipher values to canonical form,
// mirroring Sub-Store's normalizeVmessSecurity utility.
func normalizeVmessSecurity(cipher string) string {
	c := strings.ToLower(strings.TrimSpace(cipher))
	switch c {
	case "", "auto", "none", "zero":
		if c == "" {
			return "auto"
		}
		return c
	case "aes-128-gcm":
		return "aes-128-gcm"
	case "chacha20-ietf-poly1305", "chacha20-poly1305":
		return "chacha20-poly1305"
	default:
		return "auto"
	}
}

func toBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return isTrue(t)
	case int:
		return t != 0
	case float64:
		return t != 0
	default:
		return false
	}
}

func toFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(t), 64); err == nil {
			return f
		}
		return 0
	case bool:
		if t {
			return 1
		}
		return 0
	default:
		return 0
	}
}

func toInt(v any) int {
	return int(toFloat(v))
}
