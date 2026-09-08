package producer

import (
	"encoding/json"
	"strings"
	"testing"

	"substore/internal/model"
)

// egernTestOne runs ProduceEgern over a single proxy and returns the parsed
// single-key entry from the JSON line.
func egernTestOne(t *testing.T, fields map[string]any) map[string]any {
	t.Helper()
	out, err := ProduceEgern([]*model.Proxy{model.ProxyFromMap(fields)}, nil)
	if err != nil {
		t.Fatalf("ProduceEgern error: %v", err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) == 0 || lines[0] != "proxies:" {
		t.Fatalf("unexpected output header: %q", out)
	}
	if len(lines) != 2 {
		t.Fatalf("expected exactly one entry, got: %q", out)
	}
	line := strings.TrimSpace(strings.TrimPrefix(lines[1], "  - "))
	var entry map[string]any
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("bad json line %q: %v", line, err)
	}
	if len(entry) != 1 {
		t.Fatalf("entry must be single-key: %v", entry)
	}
	return entry
}

// vmess + ws + tls: transport must be wss with path/Host headers and a
// server-defaulted sni; security normalized; no type key inside.
func TestEgernVerifyVmessWsTls(t *testing.T) {
	entry := egernTestOne(t, map[string]any{
		"type": "vmess", "name": "vm", "server": "1.2.3.4", "port": 443.0,
		"uuid": "u-1", "cipher": "auto", "tls": true, "network": "ws",
		"ws-opts": map[string]any{
			"path":    "/ws",
			"headers": map[string]any{"Host": "h.com"},
		},
	})
	vm, ok := entry["vmess"].(map[string]any)
	if !ok {
		t.Fatalf("expected vmess key, got: %v", entry)
	}
	if _, bad := vm["type"]; bad {
		t.Fatalf("inner type key must be removed: %v", vm)
	}
	if vm["user_id"] != "u-1" || vm["security"] != "auto" || vm["legacy"] != false {
		t.Fatalf("bad vmess fields: %v", vm)
	}
	tr, ok := vm["transport"].(map[string]any)
	if !ok {
		t.Fatalf("missing transport: %v", vm)
	}
	ws, ok := tr["wss"].(map[string]any)
	if !ok {
		t.Fatalf("expected wss transport, got: %v", tr)
	}
	if ws["path"] != "/ws" {
		t.Fatalf("bad path: %v", ws["path"])
	}
	headers, _ := ws["headers"].(map[string]any)
	if headers == nil || headers["Host"] != "h.com" {
		t.Fatalf("bad headers: %v", ws["headers"])
	}
	if ws["sni"] != "1.2.3.4" { // sni defaulted to server
		t.Fatalf("bad sni: %v", ws["sni"])
	}
}

// ss: cipher alias chacha20-ietf-poly1305 -> chacha20-poly1305, obfs plugin
// mapped to obfs/obfs_host/obfs_uri.
func TestEgernVerifySS(t *testing.T) {
	entry := egernTestOne(t, map[string]any{
		"type": "ss", "name": "ss1", "server": "1.2.3.4", "port": 8388.0,
		"cipher": "chacha20-ietf-poly1305", "password": "pw", "udp": true,
		"plugin":      "obfs",
		"plugin-opts": map[string]any{"mode": "http", "host": "h.com", "path": "/p"},
	})
	ss, ok := entry["shadowsocks"].(map[string]any)
	if !ok {
		t.Fatalf("expected shadowsocks key, got: %v", entry)
	}
	if ss["method"] != "chacha20-poly1305" {
		t.Fatalf("bad method: %v", ss["method"])
	}
	if ss["obfs"] != "http" || ss["obfs_host"] != "h.com" || ss["obfs_uri"] != "/p" {
		t.Fatalf("bad obfs fields: %v", ss)
	}
	if ss["udp_relay"] != true {
		t.Fatalf("bad udp_relay: %v", ss["udp_relay"])
	}

	// unsupported cipher must be dropped
	out, err := ProduceEgern([]*model.Proxy{model.ProxyFromMap(map[string]any{
		"type": "ss", "name": "ss2", "server": "1.2.3.4", "port": 8388.0,
		"cipher": "aes-192-gcm", "password": "pw",
	})}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "shadowsocks") {
		t.Fatalf("unsupported cipher must be dropped: %q", out)
	}
}

// trojan plain tcp: no websocket key, reality passthrough.
func TestEgernVerifyTrojan(t *testing.T) {
	entry := egernTestOne(t, map[string]any{
		"type": "trojan", "name": "tj", "server": "1.2.3.4", "port": 443.0,
		"password": "pw", "sni": "s.com", "skip-cert-verify": true,
		"reality-opts": map[string]any{"public-key": "pk", "short-id": "ab"},
	})
	tj, ok := entry["trojan"].(map[string]any)
	if !ok {
		t.Fatalf("expected trojan key, got: %v", entry)
	}
	if _, has := tj["websocket"]; has {
		t.Fatalf("trojan tcp must not have websocket: %v", tj)
	}
	if tj["sni"] != "s.com" || tj["skip_tls_verify"] != true {
		t.Fatalf("bad tls fields: %v", tj)
	}
	r, ok := tj["reality"].(map[string]any)
	if !ok || r["public_key"] != "pk" || r["short_id"] != "ab" {
		t.Fatalf("bad reality: %v", tj["reality"])
	}
}

// hysteria2: bandwidth parsed from up, salamander obfs, port hopping.
func TestEgernVerifyHysteria2(t *testing.T) {
	entry := egernTestOne(t, map[string]any{
		"type": "hysteria2", "name": "hy2", "server": "1.2.3.4", "port": 443.0,
		"password": "authpw", "up": "200 Mbps", "udp": true,
		"obfs": "salamander", "obfs-password": "obfspw",
		"ports":         "20000-30000",
		"hop-interval":  30.0,
		"block-quic":    "on",
		"tls-fingerprint": "aabbcc",
	})
	hy, ok := entry["hysteria2"].(map[string]any)
	if !ok {
		t.Fatalf("expected hysteria2 key, got: %v", entry)
	}
	if hy["auth"] != "authpw" {
		t.Fatalf("bad auth: %v", hy["auth"])
	}
	if hy["bandwidth"] != 200.0 {
		t.Fatalf("bad bandwidth: %v", hy["bandwidth"])
	}
	if hy["obfs"] != "salamander" || hy["obfs_password"] != "obfspw" {
		t.Fatalf("bad obfs: %v", hy)
	}
	if hy["port_hopping"] != "20000-30000" || hy["port_hopping_interval"] != 30.0 {
		t.Fatalf("bad port hopping: %v", hy)
	}
	if hy["block_quic"] != true {
		t.Fatalf("bad block_quic: %v", hy["block_quic"])
	}
	if hy["fingerprint_sha256"] != "aabbcc" {
		t.Fatalf("bad fingerprint_sha256: %v", hy["fingerprint_sha256"])
	}
}
