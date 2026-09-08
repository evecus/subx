package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"substore/internal/model"
)

// Regression tests for the P2 boundary fixes, each aligned against the
// original Sub-Store JS sources (see the per-test comments).

// 1. socks query stripping: the URI_SOCKS regex carries an optional
// "(\?.*?)?" group, so the query must not leak into the port.
func TestP2SocksQueryStripped(t *testing.T) {
	p := mustParseOne(t, "socks://socks.example.com:1080?x=1#S1")
	if p.GetString("server") != "socks.example.com" || p.GetString("port") != "1080" {
		t.Fatalf("server/port = %v/%v, want socks.example.com/1080", p.Get("server"), p.Get("port"))
	}
	if got := p.GetString("name"); got != "S1" {
		t.Fatalf("name = %q, want S1", got)
	}
}

// 2. ss plugin: ";tls=" maps to boolean true (index.js:439 val || true) and
// the valueless ";skip-cert-verify" / ";sni" forms of v2ray-plugin are
// boolean true (index.js:462-465).
func TestP2SSPluginEmptyValueBoolean(t *testing.T) {
	line := "ss://aes-256-gcm:pass@ss.example.com:8388?plugin=" +
		percentEncode("v2ray-plugin;obfs=websocket;tls=;skip-cert-verify;sni=example.com") + "#SS"
	p := mustParseOne(t, line)
	if p.GetString("plugin") != "v2ray-plugin" {
		t.Fatalf("plugin = %v", p.Get("plugin"))
	}
	opts := p.GetMap("plugin-opts")
	if opts == nil {
		t.Fatalf("plugin-opts missing")
	}
	if opts["tls"] != true {
		t.Fatalf("tls = %v (%T), want boolean true", opts["tls"], opts["tls"])
	}
	if opts["skip-cert-verify"] != true {
		t.Fatalf("skip-cert-verify = %v, want boolean true", opts["skip-cert-verify"])
	}
	if opts["sni"] != "example.com" {
		t.Fatalf("sni = %v, want example.com", opts["sni"])
	}
}

// 3. URI_PROXY: an empty username is still written (index.js:189-192
// `username != null`).
func TestP2ProxyEmptyUsernameWritten(t *testing.T) {
	p := mustParseOne(t, "http://:secret@proxy.example.com:8080#P")
	if v, ok := p.Get("username").(string); !ok || v != "" {
		t.Fatalf("username = %v (%T), want present empty string", p.Get("username"), p.Get("username"))
	}
	if p.GetString("password") != "secret" {
		t.Fatalf("password = %v", p.Get("password"))
	}
	// absent auth block must not create the keys
	p2 := mustParseOne(t, "http://proxy.example.com:8080#P2")
	if p2.Has("username") || p2.Has("password") {
		t.Fatalf("username/password should be absent, got %v/%v", p2.Get("username"), p2.Get("password"))
	}
}

// 4a. hysteria1: "?sni=" (explicit empty) still allows the peer fallback
// (index.js:2321 `!proxy.sni`).
func TestP2Hysteria1PeerFallbackAfterEmptySni(t *testing.T) {
	p := mustParseOne(t, "hy://hy.example.com:443?sni=&peer=peer.example.com#H")
	if p.GetString("sni") != "peer.example.com" {
		t.Fatalf("sni = %v, want peer.example.com", p.Get("sni"))
	}
}

// 4b. hysteria2: skip-cert-verify / tfo are written unconditionally via
// /(TRUE)|1/i.test(...) (index.js:2235-2236).
func TestP2Hysteria2UnconditionalFlags(t *testing.T) {
	p := mustParseOne(t, "hy2://pass@hy2.example.com:443?insecure=0&fastopen=0#H2")
	if v, ok := p.Get("skip-cert-verify").(bool); !ok || v {
		t.Fatalf("skip-cert-verify = %v (%T), want false", p.Get("skip-cert-verify"), p.Get("skip-cert-verify"))
	}
	if v, ok := p.Get("tfo").(bool); !ok || v {
		t.Fatalf("tfo = %v (%T), want false", p.Get("tfo"), p.Get("tfo"))
	}
}

// 4c/5a. hysteria2: "?sni=" writes sni:"" and normalize keeps it (no server
// fallback) while disable-sni is enabled (index.js:2224 + proxy-utils
// index.js:1033/1149).
func TestP2Hysteria2EmptySni(t *testing.T) {
	p := mustParseOne(t, "hy2://pass@hy2.example.com:443?sni=#H2")
	if v, ok := p.Get("sni").(string); !ok || v != "" {
		t.Fatalf("sni = %v (%T), want present empty string", p.Get("sni"), p.Get("sni"))
	}
	if p.GetString("sni") == "hy2.example.com" {
		t.Fatalf("sni fell back to server")
	}
	if !p.GetBool("disable-sni") {
		t.Fatalf("disable-sni not set for empty sni")
	}
}

// 5b. TUIC: "?sni=" -> disable-sni:true via ['', 'off'].includes(sni)
// (proxy-utils index.js:1149-1151).
func TestP2TuicEmptySniDisableSni(t *testing.T) {
	p := mustParseOne(t, "tuic://11111111-1111-4111-8111-111111111111:pass@tuic.example.com?sni=#T")
	if !p.GetBool("disable-sni") {
		t.Fatalf("disable-sni not set for empty tuic sni")
	}
	if p.GetString("sni") == "tuic.example.com" {
		t.Fatalf("sni fell back to server")
	}
}

// 6. fragment decoding keeps "+" verbatim (decodeURIComponent semantics).
func TestP2FragmentPlusKept(t *testing.T) {
	p := mustParseOne(t, "socks://socks.example.com:1080#na+me")
	if got := p.GetString("name"); got != "na+me" {
		t.Fatalf("name = %q, want na+me", got)
	}
}

// 7a/7b/7c. Clash: zerotier allowed; fast-open passes through untouched;
// port-range passes through untouched (Clash_All passthrough).
func TestP2ClashPassthrough(t *testing.T) {
	line := `{"type":"zerotier","name":"ZT","server":"zt.example.com","port":9993,"fast-open":true,"port-range":"1000-2000"}`
	p := mustParseOne(t, line)
	if p.Type() != "zerotier" {
		t.Fatalf("type = %v", p.Type())
	}
	if p.Get("fast-open") != true {
		t.Fatalf("fast-open = %v (%T), want passthrough true", p.Get("fast-open"), p.Get("fast-open"))
	}
	if p.Has("tfo") {
		t.Fatalf("tfo should not be created")
	}
	if p.Get("port-range") != "1000-2000" {
		t.Fatalf("port-range = %v (%T), want string passthrough", p.Get("port-range"), p.Get("port-range"))
	}
}

// 7d. Clash test accepts block-style YAML single proxies (JSON5.parse ->
// YAML.parse fallback, index.js:2522-2530). Verified directly on the
// parser entry because ParseText is line-based.
func TestP2ClashBlockYAML(t *testing.T) {
	var clashParser *Parser
	for _, pp := range Parsers() {
		if pp.Name == "Clash Proxy Parser" {
			clashParser = pp
		}
	}
	if clashParser == nil {
		t.Fatalf("Clash parser not registered")
	}
	line := "type: ss\nname: yaml-ss\nserver: ss.example.com\nport: 8388\ncipher: aes-128-gcm\npassword: secret"
	if !clashParser.Test(line) {
		t.Fatalf("block-style YAML single proxy should match the Clash test")
	}
	p, err := clashParser.Parse(line)
	if err != nil {
		t.Fatalf("parse block YAML: %v", err)
	}
	normalizeProxy(p)
	if p.Type() != "ss" || p.GetString("server") != "ss.example.com" {
		t.Fatalf("type/server = %v/%v", p.Type(), p.Get("server"))
	}
}

// 8a. Surge: shadow-tls-version=0 is falsy in the original and defaults
// to 2 (surge.js:35-41).
func TestP2SurgeShadowTLSVersionZero(t *testing.T) {
	p := mustParseOne(t, `Surge ST0 = trojan,surge-st.example.com,443,password=secret,tls=true,shadow-tls-password=shadow-pass,shadow-tls-version=0`)
	opts := p.GetMap("plugin-opts")
	if p.GetString("plugin") != "shadow-tls" || opts == nil {
		t.Fatalf("plugin/plugin-opts = %v/%v", p.Get("plugin"), p.Get("plugin-opts"))
	}
	if opts["version"] != 2 {
		t.Fatalf("version = %v, want 2", opts["version"])
	}
}

// 8b. LOON_ONLY_OPTIONS is case-insensitive in the original (/i).
func TestP2SurgeLoonOnlyCaseInsensitive(t *testing.T) {
	line := `S = http,1.2.3.4,8080,FAST-OPEN=true`
	if surgeLineTest(line) {
		t.Fatalf("Surge test should reject lines with case-insensitive Loon-only options")
	}
}

// 8c. Surge external: args/addresses are always written, possibly empty
// (index.js:3056-3063).
func TestP2SurgeExternalEmptyArrays(t *testing.T) {
	p := mustParseOne(t, `ext = external,exec=/usr/bin/x,local-port=1080`)
	if args, ok := p.Get("args").([]any); !ok || len(args) != 0 {
		t.Fatalf("args = %v (%T), want empty array", p.Get("args"), p.Get("args"))
	}
	if addrs, ok := p.Get("addresses").([]any); !ok || len(addrs) != 0 {
		t.Fatalf("addresses = %v (%T), want empty array", p.Get("addresses"), p.Get("addresses"))
	}
}

// 9a. QX: password values swallow commas until the next ",key=" parameter
// (peggy/qx.js:191 $((!next_parameter .)+)).
func TestP2QXPasswordWithComma(t *testing.T) {
	p := mustParseOne(t, `trojan=qx-trojan.example.com:443,password=abc,def,tag=QXT,tls-verification=false`)
	if p.GetString("password") != "abc,def" {
		t.Fatalf("password = %q, want abc,def", p.GetString("password"))
	}
	if p.GetString("name") != "QXT" {
		t.Fatalf("name = %q, want QXT", p.GetString("name"))
	}
}

// 9b/9c. QX: tag value is not trimmed (tag.join("")), and the line type
// check trims the text before "=" after splitting on ','.
func TestP2QXLineTestTrimAndTag(t *testing.T) {
	// spaces around the type: previously the QX test failed entirely
	p := mustParseOne(t, `shadowsocks = qx-ss.example.com:8388,method=aes-128-gcm,password=secret,tag= QX Tag`)
	if p.GetString("name") != "QX Tag" {
		t.Fatalf("name = %q, want QX Tag", p.GetString("name"))
	}
	if p.GetString("cipher") != "aes-128-gcm" {
		t.Fatalf("cipher = %v", p.Get("cipher"))
	}
}

// 10. "_ca" certificate files feed the tls-fingerprint like ca-str
// (proxy-utils index.js:1160-1170); read failures are ignored.
func TestP2CaFileFingerprint(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	// minimal PEM structure; the fingerprint logic only needs a decodable block
	pemData := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(caPath, []byte(pemData), 0o644); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	p := mustParseOne(t, `{"type":"tuic","name":"ca-tuic","uuid":"11111111-1111-4111-8111-111111111111","password":"p","server":"t.example.com","port":443,"_ca":"`+strings.ReplaceAll(caPath, `\`, `\\`)+`"}`)
	fp := p.GetString("tls-fingerprint")
	if fp == "" {
		t.Fatalf("tls-fingerprint not generated from _ca file")
	}
	if !strings.Contains(fp, ":") {
		t.Fatalf("tls-fingerprint = %q, want colon-separated hex", fp)
	}

	// unreadable path: skipped silently
	missing := filepath.Join(t.TempDir(), "missing.pem")
	p2 := mustParseOne(t, `{"type":"tuic","name":"ca-tuic2","uuid":"11111111-1111-4111-8111-111111111111","password":"p","server":"t.example.com","port":443,"_ca":"`+strings.ReplaceAll(missing, `\`, `\\`)+`"}`)
	if p2.GetString("tls-fingerprint") != "" {
		t.Fatalf("tls-fingerprint should be empty when the ca file is unreadable")
	}
}

func mustParseOne(t *testing.T, line string) *model.Proxy {
	t.Helper()
	ps := ParseText(line)
	if len(ps) != 1 {
		t.Fatalf("line %q: expected 1 proxy, got %d", line, len(ps))
	}
	return ps[0]
}
