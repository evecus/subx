package producer

import (
	"encoding/json"
	"testing"

	"substore/internal/model"
)

// TestSingBoxStructure verifies the {outbounds, endpoints} top-level shape:
// wireguard lands in endpoints, hysteria2 gets integer up_mbps, vless keeps
// detour.
func TestSingBoxStructure(t *testing.T) {
	wg := model.ProxyFromMap(map[string]any{
		"type": "wireguard", "name": "WG", "server": "1.2.3.4", "port": 51820,
		"private-key": "privkey=", "public-key": "pubkey=", "ip": "10.0.0.2",
		"reserved": "AQID",
	})
	hy2 := model.ProxyFromMap(map[string]any{
		"type": "hysteria2", "name": "HY2", "server": "1.2.3.4", "port": 443,
		"password": "pw", "up": "100", "down": "200", "obfs": "salamander",
		"obfs-password": "obpw",
	})
	vless := model.ProxyFromMap(map[string]any{
		"type": "vless", "name": "VL", "server": "1.2.3.4", "port": 443,
		"uuid": "uuid-1", "detour": "WG", "tls": true,
	})
	out, err := ProduceSingBox([]*model.Proxy{wg, hy2, vless}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not a JSON object: %v\n%s", err, out)
	}
	if len(doc.Endpoints) != 1 || doc.Endpoints[0]["type"] != "wireguard" {
		t.Fatalf("wireguard should be in endpoints: %s", out)
	}
	wgOut := doc.Endpoints[0]
	if wgOut["tag"] != "WG" {
		t.Errorf("wireguard tag mismatch: %v", wgOut["tag"])
	}
	if _, ok := wgOut["server"]; ok {
		t.Errorf("wireguard should not have top-level server: %s", out)
	}
	if _, ok := wgOut["peers"]; !ok {
		t.Errorf("wireguard should have peers: %s", out)
	}

	var hy2Out map[string]any
	for _, item := range doc.Outbounds {
		if item["type"] == "hysteria2" {
			hy2Out = item
		}
	}
	if hy2Out == nil {
		t.Fatalf("hysteria2 missing from outbounds: %s", out)
	}
	if v, ok := hy2Out["up_mbps"].(float64); !ok || v != 100 {
		t.Errorf("hysteria2 up_mbps should be integer 100, got %v", hy2Out["up_mbps"])
	}
	if obfs, ok := hy2Out["obfs"].(map[string]any); !ok || obfs["type"] != "salamander" {
		t.Errorf("hysteria2 obfs mismatch: %v", hy2Out["obfs"])
	}

	var vlessOut map[string]any
	for _, item := range doc.Outbounds {
		if item["type"] == "vless" {
			vlessOut = item
		}
	}
	if vlessOut == nil {
		t.Fatalf("vless missing from outbounds: %s", out)
	}
	if vlessOut["detour"] != "WG" {
		t.Errorf("vless detour should be WG, got %v", vlessOut["detour"])
	}
}
