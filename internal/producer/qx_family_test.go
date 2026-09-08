package producer

import (
	"strings"
	"testing"

	"substore/internal/model"
)

func qxProduce(t *testing.T, proxies []*model.Proxy) string {
	t.Helper()
	out, err := ProduceQX(proxies, nil)
	if err != nil {
		t.Fatalf("qx produce: %v", err)
	}
	return out
}

// TestQXVmessSecurity mirrors structured.spec.js: QX maps cipher to
// method=chacha20-poly1305 for chacha20-ietf-poly1305 aliases and falls back
// to chacha20-poly1305 for unsupported ciphers, keeping "none".
func TestQXVmessSecurity(t *testing.T) {
	cases := []struct {
		cipher string
		want   string
	}{
		{"aes-128-ctr", "chacha20-poly1305"},
		{"chacha20-poly1305", "chacha20-poly1305"},
		{"chacha20-ietf-poly1305", "chacha20-poly1305"},
		{"none", "none"},
	}
	for _, tc := range cases {
		p := surgeFamilyProxy(map[string]any{
			"name":    "V1",
			"type":    "vmess",
			"uuid":    testUUID,
			"cipher":  tc.cipher,
			"alterId": 0,
		})
		out := qxProduce(t, []*model.Proxy{p})
		want := "vmess=1.2.3.4:443,method=" + tc.want + ",password=" + testUUID
		if !strings.HasPrefix(out, want) {
			t.Errorf("qx cipher %q: want prefix %q, got %q", tc.cipher, want, out)
		}
	}
}

// TestQXShadowsocks mirrors qx.js shadowsocks(): SS over TLS is emitted as
// obfs=over-tls with obfs-host from sni.
func TestQXShadowsocks(t *testing.T) {
	ss := surgeFamilyProxy(map[string]any{
		"name":     "SS TLS",
		"server":   "ss.example.com",
		"type":     "ss",
		"cipher":   "aes-128-gcm",
		"password": "secret",
		"tls":      true,
		"sni":      "a.com",
	})
	out := qxProduce(t, []*model.Proxy{ss})
	want := `shadowsocks=ss.example.com:443,method=aes-128-gcm,password=secret,obfs=over-tls,obfs-host=a.com,tag=SS TLS`
	if strings.TrimSpace(out) != want {
		t.Errorf("qx ss over-tls output wrong:\n got: %q\nwant: %q", out, want)
	}

	obfs := surgeFamilyProxy(map[string]any{
		"name":     "SS1",
		"type":     "ss",
		"cipher":   "aes-256-gcm",
		"password": "pw",
		"plugin":   "obfs",
		"plugin-opts": map[string]any{
			"mode": "http",
			"host": "obfs.example.com",
		},
	})
	out = qxProduce(t, []*model.Proxy{obfs})
	if !strings.Contains(out, ",obfs=http,obfs-host=obfs.example.com,") {
		t.Errorf("qx ss obfs output wrong: %q", out)
	}

	bad := surgeFamilyProxy(map[string]any{
		"name":     "SS2",
		"type":     "ss",
		"cipher":   "aes-256-gcm",
		"password": "pw",
		"plugin":   "v2ray-plugin",
		"plugin-opts": map[string]any{
			"mode": "quic",
		},
	})
	if out := qxProduce(t, []*model.Proxy{bad}); strings.Contains(out, "SS2") {
		t.Errorf("qx should reject non-websocket v2ray-plugin: %q", out)
	}
}

// TestQXVmessTransport mirrors qx.js vmess(): ws/http transports emit
// obfs=wss/ws/http with obfs-uri and obfs-host; tcp emits obfs=over-tls.
func TestQXVmessTransport(t *testing.T) {
	ws := surgeFamilyProxy(map[string]any{
		"name":    "V1",
		"type":    "vmess",
		"uuid":    testUUID,
		"cipher":  "aes-128-gcm",
		"tls":     true,
		"network": "ws",
		"ws-opts": map[string]any{
			"path": "/ws",
			"headers": map[string]any{
				"Host": "cdn.example.com",
			},
		},
	})
	out := qxProduce(t, []*model.Proxy{ws})
	// alterId field is absent here, so per qx.js (alterId === 0) aead=false
	want := "vmess=1.2.3.4:443,method=chacha20-poly1305,password=" + testUUID +
		",obfs=wss,obfs-uri=/ws,obfs-host=cdn.example.com,aead=false,tag=V1"
	if !strings.Contains(out, want) {
		t.Errorf("qx vmess ws output wrong: %q", out)
	}

	plain := surgeFamilyProxy(map[string]any{
		"name":    "V2",
		"type":    "vmess",
		"uuid":    testUUID,
		"cipher":  "aes-128-gcm",
		"tls":     true,
		"network": "tcp",
	})
	out = qxProduce(t, []*model.Proxy{plain})
	if !strings.Contains(out, ",obfs=over-tls,") {
		t.Errorf("qx vmess tcp+tls should emit obfs=over-tls: %q", out)
	}
}

// TestQXVlessFlow mirrors qx.js: only xtls-rprx-vision flows survive and the
// outer wrapper rejects other flows after producing.
func TestQXVlessFlow(t *testing.T) {
	vision := surgeFamilyProxy(map[string]any{
		"name":    "L1",
		"type":    "vless",
		"uuid":    testUUID,
		"tls":     true,
		"flow":    "xtls-rprx-vision",
		"network": "tcp",
	})
	out := qxProduce(t, []*model.Proxy{vision})
	if !strings.Contains(out, ",vless-flow=xtls-rprx-vision") {
		t.Errorf("qx vless vision flow output wrong: %q", out)
	}

	other := surgeFamilyProxy(map[string]any{
		"name":    "L2",
		"type":    "vless",
		"uuid":    testUUID,
		"tls":     true,
		"flow":    "xtls-rprx-direct",
		"network": "tcp",
	})
	if out := qxProduce(t, []*model.Proxy{other}); strings.Contains(out, "L2") {
		t.Errorf("qx should reject non-vision flows: %q", out)
	}
}

// TestQXRealitySuffix mirrors qx.js outer wrapper: reality fields are
// appended as reality-base64-pubkey / reality-hex-shortid.
func TestQXRealitySuffix(t *testing.T) {
	trojan := surgeFamilyProxy(map[string]any{
		"name":       "T1",
		"type":       "trojan",
		"password":   "pw",
		"tls":        true,
		"sni":        "a.com",
		"reality-opts": map[string]any{
			"public-key": "base64pk",
			"short-id":   "08",
		},
	})
	out := qxProduce(t, []*model.Proxy{trojan})
	if !strings.Contains(out, ",reality-base64-pubkey=base64pk,reality-hex-shortid=08") {
		t.Errorf("qx reality suffix missing: %q", out)
	}
}

// TestQXSmoke: a mixed subscription renders supported types, unsupported
// types (hysteria2) are skipped.
func TestQXSmoke(t *testing.T) {
	raw := strings.Join([]string{
		"ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#SS1",
		"trojan://password@trojan.example.com:443?sni=trojan.example.com#Trojan1",
		"hysteria2://pass123@1.2.3.4:443?sni=www.foo.com#HY2",
		"anytls://secret@anytls.example.com:443#AnyTLS1",
	}, "\n")
	proxies := parseMixed(raw, t)
	if len(proxies) == 0 {
		t.Fatal("expected parsed proxies")
	}
	out := qxProduce(t, proxies)
	for _, want := range []string{
		"shadowsocks=1.2.3.4:8888,method=aes-256-gcm,password=pass,udp-relay=true,tag=SS1",
		"trojan=trojan.example.com:443,password=password,over-tls=true,tls-host=trojan.example.com,udp-relay=true,tag=Trojan1",
		"anytls=anytls.example.com:443,password=secret,over-tls=true,tls-verification=true,tls-host=anytls.example.com,udp-relay=true,tag=AnyTLS1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("qx output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "HY2") {
		t.Errorf("qx should skip hysteria2: %s", out)
	}
}
