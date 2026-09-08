package producer

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"substore/internal/model"
	"substore/internal/parser"
)

func surgeFamilyProduce(t *testing.T, target string, proxies []*model.Proxy, opts map[string]any) string {
	t.Helper()
	p, ok := Get(target)
	if !ok {
		t.Fatalf("unknown target %s", target)
	}
	out, err := p(proxies, opts)
	if err != nil {
		t.Fatalf("produce %s: %v", target, err)
	}
	return out
}

func surgeFamilyProxy(fields map[string]any) *model.Proxy {
	m := map[string]any{"name": "P1", "server": "1.2.3.4", "port": 443}
	for k, v := range fields {
		m[k] = v
	}
	return model.ProxyFromMap(m)
}

func parseMixed(raw string, t *testing.T) []*model.Proxy {
	t.Helper()
	return parser.ParseText(parser.Preprocess(raw))
}

// TestSurgeVmessSecurity mirrors structured.spec.js "normalizes VMess
// security values for documented target platforms": Surge emits
// encrypt-method only for supported ciphers, mapping chacha20-poly1305 to
// chacha20-ietf-poly1305.
func TestSurgeVmessSecurity(t *testing.T) {
	base := map[string]any{
		"type":    "vmess",
		"server":  "vmess-invalid.example.com",
		"port":    443,
		"uuid":    testUUID,
		"cipher":  "aes-128-ctr",
		"alterId": 0,
	}
	invalid := surgeFamilyProxy(base)
	chacha := surgeFamilyProxy(base)
	chacha.Set("name", "VMess Chacha Security")
	chacha.Set("cipher", "chacha20-poly1305")

	outInvalid := surgeFamilyProduce(t, "surge", []*model.Proxy{invalid}, nil)
	if strings.Contains(outInvalid, "encrypt-method=") {
		t.Errorf("surge should omit encrypt-method for unsupported cipher, got: %s", outInvalid)
	}
	outChacha := surgeFamilyProduce(t, "surge", []*model.Proxy{chacha}, nil)
	if !strings.Contains(outChacha, ",encrypt-method=chacha20-ietf-poly1305") {
		t.Errorf("surge should map chacha20-poly1305 to chacha20-ietf-poly1305, got: %s", outChacha)
	}
}

// TestSurgeFiltersSSOverTLS mirrors structured.spec.js "filters canonical
// shadowsocks over-tls nodes for unsupported client targets by default".
func TestSurgeFiltersSSOverTLS(t *testing.T) {
	proxy := surgeFamilyProxy(map[string]any{
		"name":     "Unsupported SS TLS",
		"server":   "ss.example.com",
		"type":     "ss",
		"cipher":   "aes-128-gcm",
		"password": "secret",
		"tls":      true,
		"sni":      "a.com",
	})
	for _, target := range []string{"clash", "mihomo", "stash", "loon", "surge", "surge-mac", "surfboard", "egern", "sing-box", "uri", "v2ray"} {
		if out := surgeFamilyProduce(t, target, []*model.Proxy{proxy}, nil); strings.Contains(out, "Unsupported SS TLS") {
			t.Errorf("%s should filter ss over-tls proxy, got: %s", target, out)
		}
	}
	for _, target := range []string{"qx", "shadowrocket"} {
		if out := surgeFamilyProduce(t, target, []*model.Proxy{proxy}, nil); !strings.Contains(out, "Unsupported SS TLS") {
			t.Errorf("%s should keep ss over-tls proxy, got: %q", target, out)
		}
	}
}

// TestSurgeAnyTLS mirrors surge.js: only tcp anytls without reality is
// supported; anything else is skipped as unsupported.
func TestSurgeAnyTLS(t *testing.T) {
	plain := surgeFamilyProxy(map[string]any{
		"name":     "Surge AnyTLS",
		"server":   "anytls.example.com",
		"type":     "anytls",
		"password": "secret",
	})
	out := surgeFamilyProduce(t, "surge", []*model.Proxy{plain}, nil)
	if !strings.Contains(out, `Surge AnyTLS=anytls,anytls.example.com,443,password="secret"`) {
		t.Errorf("surge anytls output wrong: %q", out)
	}

	ws := surgeFamilyProxy(map[string]any{
		"name":     "AnyTLS WS",
		"type":     "anytls",
		"password": "secret",
		"network":  "ws",
	})
	if out := surgeFamilyProduce(t, "surge", []*model.Proxy{ws}, nil); strings.Contains(out, "AnyTLS WS") {
		t.Errorf("surge should skip anytls with non-tcp network, got: %q", out)
	}

	reality := surgeFamilyProxy(map[string]any{
		"name":         "AnyTLS Reality",
		"type":         "anytls",
		"password":     "secret",
		"network":      "tcp",
		"reality-opts": map[string]any{"public-key": "pk"},
	})
	if out := surgeFamilyProduce(t, "surge", []*model.Proxy{reality}, nil); strings.Contains(out, "AnyTLS Reality") {
		t.Errorf("surge should skip anytls with tcp + reality, got: %q", out)
	}

	plainReality := surgeFamilyProxy(map[string]any{
		"name":         "AnyTLS Plain Reality",
		"type":         "anytls",
		"password":     "secret",
		"reality-opts": map[string]any{"public-key": "pk"},
	})
	if out := surgeFamilyProduce(t, "surge", []*model.Proxy{plainReality}, nil); !strings.Contains(out, "AnyTLS Plain Reality") {
		t.Errorf("surge should keep anytls with reality when network is omitted, got: %q", out)
	}
}

// TestSurgeUnsupportedTypesSkipped: unsupported proxy types are skipped
// silently instead of failing the whole output.
func TestSurgeUnsupportedTypesSkipped(t *testing.T) {
	juicity := surgeFamilyProxy(map[string]any{
		"name":     "Juicity1",
		"server":   "juicity.example.com",
		"type":     "juicity",
		"password": "secret",
	})
	out := surgeFamilyProduce(t, "surge", []*model.Proxy{juicity}, nil)
	if out != "" {
		t.Errorf("surge should skip juicity, got: %q", out)
	}

	mixed := []*model.Proxy{
		juicity,
		surgeFamilyProxy(map[string]any{"name": "SS1", "type": "ss", "cipher": "aes-256-gcm", "password": "pass"}),
	}
	out = surgeFamilyProduce(t, "surge", mixed, nil)
	if !strings.Contains(out, "SS1=ss,1.2.3.4,443,encrypt-method=aes-256-gcm,password=\"pass\"") {
		t.Errorf("surge mixed output wrong: %q", out)
	}
}

// TestSurgeMacMihomoFallback: types the Surge producer cannot render (but
// Mihomo can, e.g. wireguard) are emitted as a Mihomo External Proxy Program
// when useMihomoExternal is set, mirroring surgemac.js.
func TestSurgeMacMihomoFallback(t *testing.T) {
	wg := surgeFamilyProxy(map[string]any{
		"name":        "WG1",
		"type":        "wireguard",
		"public-key":  "abcd1234",
		"private-key": "wxyz9876",
		"ip":          "10.0.0.1",
		"ipv6":        "fd00::1",
	})
	out := surgeFamilyProduce(t, "surge-mac", []*model.Proxy{wg}, map[string]any{"useMihomoExternal": true})
	if !strings.Contains(out, `WG1=external,exec="/usr/local/bin/mihomo",local-port=65535`) {
		t.Fatalf("surge-mac mihomo fallback output wrong: %q", out)
	}
	argsIdx := strings.LastIndex(out, `args="`)
	if argsIdx < 0 {
		t.Fatalf("expected args with base64 config: %q", out)
	}
	start := argsIdx + len(`args="`)
	end := strings.Index(out[start:], `"`) + start
	encoded := out[start:end]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("config args not valid base64: %v", err)
	}
	var config map[string]any
	if err := json.Unmarshal(decoded, &config); err != nil {
		t.Fatalf("config args not valid JSON: %v", err)
	}
	if config["mixed-port"] != float64(65535) {
		t.Errorf("expected mixed-port 65535 in config, got %v", config["mixed-port"])
	}
	proxies, ok := config["proxies"].([]any)
	if !ok || len(proxies) != 1 {
		t.Fatalf("expected 1 proxy in mihomo config, got %v", config["proxies"])
	}
	p0, _ := proxies[0].(map[string]any)
	if p0["name"] != "proxy" {
		t.Errorf("expected named 'proxy' in mihomo config, got %v", p0["name"])
	}
}

// TestSurgeMacExternal: plain external proxies pass through directly.
func TestSurgeMacExternal(t *testing.T) {
	external := surgeFamilyProxy(map[string]any{
		"name":       "Ext1",
		"type":       "external",
		"exec":       "/usr/bin/example",
		"local-port": 1080,
		"args":       []any{"-a", "b"},
		"udp":        true,
	})
	out := surgeFamilyProduce(t, "surge-mac", []*model.Proxy{external}, nil)
	want := `Ext1=external,exec="/usr/bin/example",local-port=1080,args="-a",args="b",udp-relay=true`
	if strings.TrimSpace(out) != want {
		t.Errorf("surge-mac external output wrong:\n got: %q\nwant: %q", out, want)
	}
}

// TestSurgeSmoke: a mixed subscription renders all supported types.
func TestSurgeSmoke(t *testing.T) {
	raw := strings.Join([]string{
		"ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#SS1",
		"vmess://eyJhZGQiOiIxLjEuMS4xIiwicG9ydCI6IjQ0MyIsImFpZCI6IjAiLCJpZCI6IjExMTExMTExLTExMTEtNDExMS04MTExLTExMTExMTExMTExMSIsIm5ldCI6IndzIiwicGF0aCI6Ii93cz9lZD0yMDQ4IiwidGxzIjoidGxzIn0=",
		"trojan://password@trojan.example.com:443?sni=trojan.example.com#Trojan1",
		"hysteria2://pass123@1.2.3.4:443?sni=www.foo.com#HY2",
		"anytls://secret@anytls.example.com:443#AnyTLS1",
	}, "\n")
	proxies := parseMixed(raw, t)
	if len(proxies) == 0 {
		t.Fatal("expected parsed proxies")
	}
	out := surgeFamilyProduce(t, "surge", proxies, nil)
	for _, want := range []string{"SS1=ss,1.2.3.4,8888,", "Trojan1=trojan,trojan.example.com,443,", "HY2=hysteria2,1.2.3.4,443,", "AnyTLS1=anytls,anytls.example.com,443,"} {
		if !strings.Contains(out, want) {
			t.Errorf("surge output missing %q: %s", want, out)
		}
	}
}
