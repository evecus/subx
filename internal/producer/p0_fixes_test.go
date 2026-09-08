package producer

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"substore/internal/model"
)

// Temporary end-to-end checks for the P0 produce fixes; delete after verification.
func TestP0ProduceFixesTmp(t *testing.T) {
	// 1. vmess+grpc must keep type=gun
	p := model.NewProxy()
	p.Set("type", "vmess")
	p.Set("name", "v1")
	p.Set("server", "1.2.3.4")
	p.Set("port", 443)
	p.Set("uuid", "00000000-0000-0000-0000-000000000000")
	p.Set("cipher", "auto")
	p.Set("network", "grpc")
	p.Set("tls", true)
	p.Set("grpc-opts", map[string]any{"grpc-service-name": "svc"})
	uri, err := ProduceURI([]*model.Proxy{p}, nil)
	if err != nil || strings.TrimSpace(uri) == "" {
		t.Fatalf("ProduceURI error: %v %q", err, uri)
	}
	payload := strings.TrimPrefix(strings.TrimSpace(uri), "vmess://")
	dec, err := base64StdDecodeTmp(payload)
	if err != nil {
		t.Fatalf("decode vmess: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(dec), &obj); err != nil {
		t.Fatalf("unmarshal vmess: %v", err)
	}
	if obj["net"] != "grpc" || obj["type"] != "gun" {
		t.Fatalf("vmess net=%v type=%v, want grpc/gun", obj["net"], obj["type"])
	}

	// 2. ssr output must use &protoparam=
	s := model.NewProxy()
	s.Set("type", "ssr")
	s.Set("name", "s1")
	s.Set("server", "1.2.3.4")
	s.Set("port", 443)
	s.Set("cipher", "aes-256-cfb")
	s.Set("password", "pass")
	s.Set("protocol", "auth_aes128_md5")
	s.Set("obfs", "tls1.2_ticket_auth")
	s.Set("protocol-param", "123:abc")
	ssrOut, err := ProduceURI([]*model.Proxy{s}, nil)
	if err != nil {
		t.Fatalf("ssr produce: %v", err)
	}
	dec2, err := base64StdDecodeTmp(strings.TrimPrefix(strings.TrimSpace(ssrOut), "ssr://"))
	if err != nil {
		t.Fatalf("decode ssr: %v", err)
	}
	if !strings.Contains(dec2, "&protoparam=") {
		t.Fatalf("ssr output missing protoparam: %s", dec2)
	}

	// 3. sing-box: wg goes into endpoints
	w := model.NewProxy()
	w.Set("type", "wireguard")
	w.Set("name", "w1")
	w.Set("server", "1.2.3.4")
	w.Set("port", 51820)
	w.Set("private-key", "PRIV")
	w.Set("public-key", "PUB")
	w.Set("ip", "10.0.0.2")
	sbOut, err := ProduceSingBox([]*model.Proxy{w}, nil)
	if err != nil {
		t.Fatalf("singbox: %v", err)
	}
	var top struct {
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(sbOut), &top); err != nil {
		t.Fatalf("singbox json: %v %s", err, sbOut)
	}
	if len(top.Endpoints) != 1 || top.Endpoints[0]["type"] != "wireguard" {
		t.Fatalf("wg not in endpoints: %s", sbOut)
	}
	if _, hasServer := top.Endpoints[0]["server"]; hasServer {
		t.Fatalf("endpoint still has top-level server")
	}
	if len(top.Outbounds) != 0 {
		t.Fatalf("outbounds should be empty for wg-only input")
	}
}

func base64StdDecodeTmp(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(padBase64Tmp(s)); return string(b), err
}

func padBase64Tmp(s string) string {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return strings.NewReplacer("-", "+", "_", "/").Replace(s)
}
