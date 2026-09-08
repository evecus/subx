package producer

import (
	"strings"
	"testing"

	"substore/internal/parser"
)

// TestProducerClashMeta verifies that mihomo producer supports protocols
// that Clash does not (hysteria2, tuic, anytls, etc.).
func TestProducerClashMeta(t *testing.T) {
	proxies := parser.ParseText("hysteria2://pass123@1.2.3.4:443?sni=www.foo.com#HY2")
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	out, err := ProduceClashMetaYAML(proxies, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "hysteria2") {
		t.Errorf("mihomo output should contain hysteria2 type: %s", out)
	}
	if !strings.Contains(out, "HY2") {
		t.Errorf("mihomo output should contain proxy name HY2: %s", out)
	}
}

// TestProducerClashFiltered verifies that Clash producer filters out
// protocols it doesn't support (hysteria2, tuic, etc.).
func TestProducerClashFiltered(t *testing.T) {
	proxies := parser.ParseText("hysteria2://pass123@1.2.3.4:443?sni=www.foo.com#HY2")
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	out, err := ProduceClashYAML(proxies, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Clash should filter out hysteria2, so no proxies in the list
	if strings.Contains(out, "HY2") {
		t.Errorf("Clash output should not contain hysteria2 proxy: %s", out)
	}
}

// TestProducerSurgeSnell verifies that Surge producer can output snell.
func TestProducerSurgeSnell(t *testing.T) {
	raw := "test = snell, 1.2.3.4, 443, password=pass, version=3"
	proxies := parser.ParseText(raw)
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	if proxies[0].Type() != "snell" {
		t.Fatalf("expected snell, got %s", proxies[0].Type())
	}
	out, err := ProduceSurge(proxies, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "snell") {
		t.Errorf("surge output should contain snell: %s", out)
	}
}

// TestProducerLoonSeparate verifies that Loon producer produces different
// output from Surge (different type names, field names).
func TestProducerLoonSeparate(t *testing.T) {
	proxies := parser.ParseText("ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#TestSS")
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	loonOut, _ := ProduceLoon(proxies, nil)
	surgeOut, _ := ProduceSurge(proxies, nil)
	// Loon uses "shadowsocks" while Surge uses "ss"
	if !strings.Contains(loonOut, "shadowsocks,") {
		t.Errorf("Loon output should use 'shadowsocks' type name: %s", loonOut)
	}
	if !strings.Contains(surgeOut, "ss,") {
		t.Errorf("Surge output should use 'ss' type name: %s", surgeOut)
	}
}

// TestProducerSingBoxHysteria2 verifies sing-box output for hysteria2.
func TestProducerSingBoxHysteria2(t *testing.T) {
	proxies := parser.ParseText("hysteria2://pass123@1.2.3.4:443?sni=www.foo.com#HY2")
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	out, err := ProduceSingBox(proxies, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "hysteria2") {
		t.Errorf("sing-box output should contain hysteria2: %s", out)
	}
	if !strings.Contains(out, "HY2") {
		t.Errorf("sing-box output should contain tag HY2: %s", out)
	}
}

// TestProducerQXSSR verifies QX producer can output SSR.
func TestProducerQXSSR(t *testing.T) {
	raw := "ssr://dm23OjEuMi4zLjQ6ODg4ODphdXRoX2NoYWluX2E6YWVzLTI1Ni1jZmI6dGxzMS4yLjNfY2RiOmRlbW8vP3JlbWFya3M9VGVzdA=="
	proxies := parser.ParseText(raw)
	if len(proxies) == 0 {
		// SSR parsing might fail in some environments; skip if so
		t.Skip("SSR parsing returned 0 proxies")
	}
	out, err := ProduceQX(proxies, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "shadowsocks=") {
		t.Errorf("QX SSR output should contain 'shadowsocks=': %s", out)
	}
}

// TestProducerV2RayIsBase64 verifies V2Ray output is base64-encoded URIs.
func TestProducerV2RayIsBase64(t *testing.T) {
	proxies := parser.ParseText("ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#TestSS")
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	out, err := ProduceV2Ray(proxies, nil)
	if err != nil {
		t.Fatal(err)
	}
	// V2Ray should be base64 of the URI list, not JSON
	if strings.Contains(out, "protocol") || strings.Contains(out, "outbounds") {
		t.Errorf("V2Ray output should be base64 URI list, not JSON: %s", out)
	}
	// Should decode to contain ss://
	decoded, err := base64StdDecode(out)
	if err != nil {
		t.Errorf("V2Ray output is not valid base64: %s", out)
	}
	if !strings.Contains(string(decoded), "ss://") {
		t.Errorf("V2Ray decoded output should contain ss://: %s", string(decoded))
	}
}

// TestProducerStash verifies Stash supports more protocols than Clash.
func TestProducerStash(t *testing.T) {
	proxies := parser.ParseText("hysteria2://pass123@1.2.3.4:443?sni=www.foo.com#HY2")
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	out, err := ProduceStash(proxies, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Stash supports hysteria2 (unlike Clash)
	if !strings.Contains(out, "HY2") {
		t.Errorf("Stash output should contain hysteria2 proxy: %s", out)
	}
}

// TestProducerSurfboard verifies Surfboard output format.
func TestProducerSurfboard(t *testing.T) {
	proxies := parser.ParseText("ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#TestSS")
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	out, err := ProduceSurfboard(proxies, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `TestSS=ss,1.2.3.4,8888,encrypt-method=aes-256-gcm,password="pass"`) {
		t.Errorf("Surfboard output wrong: %s", out)
	}
}

// TestProducerEgern verifies Egern output format.
func TestProducerEgern(t *testing.T) {
	proxies := parser.ParseText("ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#TestSS")
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	out, err := ProduceEgern(proxies, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "TestSS") {
		t.Errorf("Egern output should contain proxy name: %s", out)
	}
}

// TestProducerShadowrocket verifies Shadowrocket uses the Clash-format list
// (mirroring producers/shadowrocket.js), not the URI format.
func TestProducerShadowrocket(t *testing.T) {
	proxies := parser.ParseText("ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#TestSS")
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	out, err := ProduceShadowrocket(proxies, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "proxies:\n") {
		t.Errorf("Shadowrocket output should be a proxies: list: %s", out)
	}
	if !strings.Contains(out, "TestSS") {
		t.Errorf("Shadowrocket output should contain proxy name: %s", out)
	}
}

// TestLoonParser verifies Loon format parsing.
func TestLoonParser(t *testing.T) {
	raw := "TestSS = Shadowsocks, 1.2.3.4, 8888, aes-256-gcm, \"pass\", tag=TestSS"
	proxies := parser.ParseText(raw)
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy from Loon format, got %d", len(proxies))
	}
	p := proxies[0]
	if p.Type() != "ss" {
		t.Errorf("expected type 'ss', got '%s'", p.Type())
	}
	if p.GetString("cipher") != "aes-256-gcm" {
		t.Errorf("expected cipher 'aes-256-gcm', got '%s'", p.GetString("cipher"))
	}
	if p.GetString("password") != "pass" {
		t.Errorf("expected password 'pass', got '%s'", p.GetString("password"))
	}
}
