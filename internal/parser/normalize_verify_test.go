package parser

import (
	"encoding/json"
	"strings"
	"testing"

	"substore/internal/model"
)

// TestAnyTLSReusesVlessParser 验证 anytls:// 复用 VLESS 解析器后保留
// sni / reality-opts 等传输层字段（对照原版 URI_AnyTLS）。
func TestAnyTLSReusesVlessParser(t *testing.T) {
	line := `anytls://top-secret@anytls.example.com:443?sni=anytls-sni.example.com&security=reality&pbk=anytls-pubkey&sid=08&fp=chrome&insecure=1#AnyTLS Reality`
	proxies := ParseText(line)
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	p := proxies[0]
	if got := p.GetString("sni"); got != "anytls-sni.example.com" {
		t.Errorf("sni = %q, want %q", got, "anytls-sni.example.com")
	}
	reality := p.GetMap("reality-opts")
	if reality == nil {
		t.Fatalf("missing reality-opts: %v", p.Fields())
	}
	if reality["public-key"] != "anytls-pubkey" {
		t.Errorf("reality-opts.public-key = %v, want anytls-pubkey", reality["public-key"])
	}
	if reality["short-id"] != "08" {
		t.Errorf("reality-opts.short-id = %v, want \"08\"", reality["short-id"])
	}
	if got := p.GetString("client-fingerprint"); got != "chrome" {
		t.Errorf("client-fingerprint = %q, want chrome", got)
	}
	if !p.GetBool("skip-cert-verify") {
		t.Errorf("skip-cert-verify = false, want true")
	}
	if p.Type() != "anytls" {
		t.Errorf("type = %q, want anytls", p.Type())
	}
}

// TestNormalizeHysteria2ObfsPassword 验证 hysteria2 的 obfs_password
// 转换为 obfs-password（对照原版 lastParse；URI 解析器不产出该字段，
// 典型来源是 Clash YAML 节点）。
func TestNormalizeHysteria2ObfsPassword(t *testing.T) {
	raw := "proxies:\n  - name: hy2\n    type: hysteria2\n    server: hy2.example.com\n    port: 443\n    password: secret\n    obfs_password: mask-pw\n"
	proxies := ParseText(Preprocess(raw))
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	p := proxies[0]
	if got := p.GetString("obfs-password"); got != "mask-pw" {
		t.Errorf("obfs-password = %q, want mask-pw", got)
	}
	if _, exists := p.Fields()["obfs_password"]; exists {
		t.Errorf("obfs_password should be removed after normalization")
	}
}

// TestNormalizePortsSlashToComma 验证 ports 中的 / 归一化为 ,
// （对照原版 lastParse：String(ports).replace(/\//g, ',')）。
func TestNormalizePortsSlashToComma(t *testing.T) {
	p := model.NewProxy()
	p.Set("type", "hysteria2")
	p.Set("ports", "2000/3000,4000-5000/6000")
	normalizeProxy(p)
	if got := p.GetString("ports"); got != "2000,3000,4000-5000,6000" {
		t.Errorf("ports = %q, want %q", got, "2000,3000,4000-5000,6000")
	}

	// 空 ports 应被删除
	p2 := model.NewProxy()
	p2.Set("type", "hysteria2")
	p2.Set("ports", "")
	normalizeProxy(p2)
	if _, exists := p2.Fields()["ports"]; exists {
		t.Errorf("empty ports should be deleted")
	}
}

// TestNormalizeClashYamlShortID 验证 Clash YAML 中 short-id 标量被强制
// 加引号（对照原版 normalizeClashYaml）。
func TestNormalizeClashYamlShortID(t *testing.T) {
	raw := "proxies:\n  - name: a\n    type: vless\n    reality-opts:\n      short-id: 08\n"
	got := normalizeClashYaml(raw)
	if !strings.Contains(got, `short-id: "08"`) {
		t.Errorf("short-id not quoted: %q", got)
	}
	// 已带引号 / null 保持原样
	raw2 := "proxies:\n  - name: a\n    type: vless\n    reality-opts:\n      short-id: '08'\n      short-id: null\n"
	got2 := normalizeClashYaml(raw2)
	if !strings.Contains(got2, "short-id: '08'") || !strings.Contains(got2, "short-id: null") {
		t.Errorf("quoted/null short-id should be preserved: %q", got2)
	}
}

// TestPreprocessFallbackBase64 验证兜底 base64 预处理器：解码结果必须
// 以协议或 key=value 开头，否则原文返回。
func TestPreprocessFallbackBase64(t *testing.T) {
	encoded := b64("ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#SS1")
	if got := Preprocess(encoded); got != "ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#SS1" {
		t.Errorf("fallback base64 should decode valid subscription, got %q", got)
	}
	// 解码后不是协议内容 -> 原文返回
	if got := Preprocess(b64("just some plain text")); got != b64("just some plain text") {
		t.Errorf("non-protocol decoded content should return raw input, got %q", got)
	}
}

// TestNormalizeShadowTLSOptsPlugin 验证 shadow-tls-opts 转 plugin
// （对照原版 lastParse：vmess/vless/trojan/anytls）。
func TestNormalizeShadowTLSOptsPlugin(t *testing.T) {
	raw := "proxies:\n  - name: st\n    type: trojan\n    server: st.example.com\n    port: 443\n    password: secret\n    sni: mask.example.com\n    shadow-tls-opts:\n      password: st-pass\n      version: 3\n"
	proxies := ParseText(Preprocess(raw))
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	p := proxies[0]
	if p.GetString("plugin") != "shadow-tls" {
		t.Errorf("plugin = %q, want shadow-tls", p.GetString("plugin"))
	}
	opts := p.GetMap("plugin-opts")
	if opts == nil {
		t.Fatalf("missing plugin-opts")
	}
	if opts["password"] != "st-pass" || opts["host"] != "mask.example.com" {
		t.Errorf("plugin-opts = %v, want host/password from sni/shadow-tls-opts", opts)
	}
	if _, exists := p.Fields()["shadow-tls-opts"]; exists {
		t.Errorf("shadow-tls-opts should be removed after conversion")
	}
	b, _ := json.Marshal(p.Fields())
	t.Logf("result: %s", b)
}
