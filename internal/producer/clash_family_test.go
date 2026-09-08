package producer

import (
	"strings"
	"testing"

	"substore/internal/model"
	"substore/internal/parser"
)

const testUUID = "11111111-1111-4111-8111-111111111111"

// TestClashFamilySmoke parses a mixed subscription and produces all four
// Clash-family formats without errors.
func TestClashFamilySmoke(t *testing.T) {
	raw := strings.Join([]string{
		"ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#SS1",
		"vmess://eyJhZGQiOiIxLjEuMS4xIiwicG9ydCI6IjQ0MyIsImFpZCI6IjAiLCJpZCI6IjExMTExMTExLTExMTEtNDExMS04MTExLTExMTExMTExMTExMSIsIm5ldCI6IndzIiwicGF0aCI6Ii93cz9lZD0yMDQ4IiwidGxzIjoidGxzIn0=",
		"trojan://password@trojan.example.com:443?sni=trojan.example.com#Trojan1",
		"hysteria2://pass123@1.2.3.4:443?sni=www.foo.com#HY2",
		"anytls://secret@anytls.example.com:443#AnyTLS1",
	}, "\n")
	proxies := parser.ParseText(parser.Preprocess(raw))
	if len(proxies) == 0 {
		t.Fatal("expected parsed proxies")
	}

	cases := []struct {
		name     string
		produce  func([]*model.Proxy, map[string]any) (string, error)
		contains []string
		exclude  []string
	}{
		{"clash", ProduceClashYAML, []string{"SS1", "Trojan1"}, []string{"HY2", "AnyTLS1"}},
		{"mihomo", ProduceClashMetaYAML, []string{"SS1", "Trojan1", "HY2", "AnyTLS1"}, nil},
		{"stash", ProduceStash, []string{"SS1", "Trojan1", "HY2", "AnyTLS1"}, nil},
		{"shadowrocket", ProduceShadowrocket, []string{"SS1", "Trojan1", "HY2"}, nil},
	}
	for _, tc := range cases {
		out, err := tc.produce(proxies, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !strings.HasPrefix(out, "proxies:\n") {
			t.Errorf("%s output should start with proxies:, got %q", tc.name, out[:minInt(40, len(out))])
		}
		for _, c := range tc.contains {
			if !strings.Contains(out, c) {
				t.Errorf("%s output missing %q: %s", tc.name, c, out)
			}
		}
		for _, e := range tc.exclude {
			if strings.Contains(out, e) {
				t.Errorf("%s output should not contain %q: %s", tc.name, e, out)
			}
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestClashFilterVmessWsEarlyData mirrors the first case of
// structured.spec.js: Clash filters unsupported proxies (vless flow/reality)
// and normalizes vmess ws early data in the path.
func TestClashFilterVmessWsEarlyData(t *testing.T) {
	proxies := []*model.Proxy{
		model.ProxyFromMap(map[string]any{
			"type":   "vmess",
			"name":   "Clash VMess",
			"server": "vmess.example.com",
			"port":   443,
			"uuid":   testUUID,
			"cipher": "chacha20",
			"aead":   true,
			"tls":    true,
			"sni":    "sni.example.com",
			"network": "ws",
			"ws-opts": map[string]any{
				"path": "/ws?a=1&ed=2048&b=2",
				"headers": map[string]any{
					"Host": "cdn.example.com",
				},
			},
		}),
		model.ProxyFromMap(map[string]any{
			"type":   "vless",
			"name":   "Clash Reality",
			"server": "vless.example.com",
			"port":   443,
			"uuid":   testUUID,
			"tls":    true,
			"flow":   "xtls-rprx-vision",
			"reality-opts": map[string]any{
				"public-key": "pubkey",
				"short-id":   "08",
			},
		}),
	}

	list := clashMapProxies(proxies, nil, clashPlatformClash, "internal")
	if len(list) != 1 {
		t.Fatalf("expected 1 proxy to survive Clash filter, got %d", len(list))
	}
	got := list[0]
	if got["type"] != "vmess" {
		t.Errorf("expected vmess, got %v", got["type"])
	}
	if got["cipher"] != "auto" {
		t.Errorf("expected cipher 'auto', got %v", got["cipher"])
	}
	if got["alterId"] != 0 {
		t.Errorf("expected alterId 0, got %v", got["alterId"])
	}
	if got["servername"] != "sni.example.com" {
		t.Errorf("expected servername, got %v", got["servername"])
	}
	if _, ok := got["sni"]; ok {
		t.Errorf("sni should have been renamed to servername")
	}
	wsOpts, ok := got["ws-opts"].(map[string]any)
	if !ok {
		t.Fatalf("expected ws-opts map, got %v", got["ws-opts"])
	}
	if wsOpts["path"] != "/ws?a=1&b=2" {
		t.Errorf("expected early-data stripped path, got %v", wsOpts["path"])
	}
	if wsOpts["early-data-header-name"] != "Sec-WebSocket-Protocol" {
		t.Errorf("expected early-data-header-name, got %v", wsOpts["early-data-header-name"])
	}
	if wsOpts["max-early-data"] != 2048 {
		t.Errorf("expected max-early-data 2048, got %v", wsOpts["max-early-data"])
	}
	headers, _ := wsOpts["headers"].(map[string]any)
	if headers["Host"] != "cdn.example.com" {
		t.Errorf("expected Host header preserved, got %v", headers)
	}

	out, err := ProduceClashYAML(proxies, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "proxies:\n") {
		t.Errorf("external output should be a proxies: list: %q", out)
	}
	if strings.Contains(out, "Clash Reality") {
		t.Errorf("external output should not contain the filtered vless proxy: %s", out)
	}
}
