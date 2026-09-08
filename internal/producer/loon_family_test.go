package producer

import (
	"strings"
	"testing"

	"substore/internal/model"
)

func loonProduce(t *testing.T, proxies []*model.Proxy) string {
	t.Helper()
	out, err := ProduceLoon(proxies, nil)
	if err != nil {
		t.Fatalf("loon produce: %v", err)
	}
	return out
}

// TestLoonSmoke mirrors loon.js: each supported type becomes a comma list
// with no spaces, unsupported types are skipped.
func TestLoonSmoke(t *testing.T) {
	raw := strings.Join([]string{
		"ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#SS1",
		"ssr://MTIzNDU2Nzg5MGFhYmJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWFiYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5egoxMjM0NTY3ODkwYWFiYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ1Njc4OTBhYWJiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6:YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#SSR1",
		"trojan://password@trojan.example.com:443?sni=trojan.example.com#Trojan1",
		"hysteria2://pass123@1.2.3.4:443?sni=www.foo.com#HY2",
		"anytls://secret@anytls.example.com:443#AnyTLS1",
		"vmess://eyJhZGQiOiIxLjEuMS4xIiwicG9ydCI6IjQ0MyIsImFpZCI6IjAiLCJpZCI6IjExMTExMTExLTExMTEtNDExMS04MTExLTExMTExMTExMTExMSIsIm5ldCI6IndzIiwicGF0aCI6Ii93cyIsInRscyI6InRscyJ9",
	}, "\n")
	proxies := parseMixed(raw, t)
	if len(proxies) == 0 {
		t.Fatal("expected parsed proxies")
	}
	out := loonProduce(t, proxies)
	for _, want := range []string{
		`SS1=shadowsocks,1.2.3.4,8888,aes-256-gcm,"pass"`,
		`Trojan1=trojan,trojan.example.com,443,"password",tls-name=trojan.example.com`,
		`HY2=Hysteria2,1.2.3.4,443,"pass123"`,
		`AnyTLS1=anytls,anytls.example.com,443,"secret"`,
		"VMess 1.1.1.1:443=vmess,1.1.1.1,443,auto,\"11111111-1111-4111-8111-111111111111\",transport=ws,path=/ws,host=,over-tls=true,alterId=0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("loon output missing %q:\n%s", want, out)
		}
	}
}

// TestLoonVmessSecurity mirrors vmess-security.js formatLoonVmessSecurity:
// invalid ciphers fall back to auto, chacha20-poly1305 maps to
// chacha20-ietf-poly1305.
func TestLoonVmessSecurity(t *testing.T) {
	invalid := surgeFamilyProxy(map[string]any{
		"name":    "V1",
		"type":    "vmess",
		"uuid":    testUUID,
		"cipher":  "aes-128-ctr",
		"alterId": 0,
	})
	out := loonProduce(t, []*model.Proxy{invalid})
	if !strings.Contains(out, "V1=vmess,1.2.3.4,443,auto,\""+testUUID+"\"") {
		t.Errorf("loon invalid security should fall back to auto: %q", out)
	}

	chacha := surgeFamilyProxy(map[string]any{
		"name":    "V2",
		"type":    "vmess",
		"uuid":    testUUID,
		"cipher":  "chacha20-poly1305",
		"alterId": 0,
	})
	out = loonProduce(t, []*model.Proxy{chacha})
	if !strings.Contains(out, "V2=vmess,1.2.3.4,443,chacha20-ietf-poly1305,\""+testUUID+"\"") {
		t.Errorf("loon chacha20-poly1305 should map to chacha20-ietf-poly1305: %q", out)
	}
}

// TestLoonShadowTLS mirrors loon.js appendShadowTLS: version 1 is rejected,
// version 2+ appends shadow-tls fields with alpn and tls-profile.
func TestLoonShadowTLS(t *testing.T) {
	low := surgeFamilyProxy(map[string]any{
		"name":     "S1",
		"type":     "ss",
		"cipher":   "aes-256-gcm",
		"password": "pw",
		"plugin":   "shadow-tls",
		"plugin-opts": map[string]any{
			"password": "stp",
			"host":     "mask.example.com",
			"version":  1,
		},
	})
	if out := loonProduce(t, []*model.Proxy{low}); strings.Contains(out, "S1") {
		t.Errorf("loon should reject shadow-tls version 1: %q", out)
	}

	ok := surgeFamilyProxy(map[string]any{
		"name":     "S2",
		"type":     "ss",
		"cipher":   "aes-256-gcm",
		"password": "pw",
		"plugin":   "shadow-tls",
		"plugin-opts": map[string]any{
			"password": "stp",
			"host":     "mask.example.com",
			"version":  3,
			"alpn":     []any{"h2", "http/1.1"},
		},
	})
	out := loonProduce(t, []*model.Proxy{ok})
	if !strings.Contains(out, `S2=shadowsocks,1.2.3.4,443,aes-256-gcm,"pw",shadow-tls-password=stp,shadow-tls-sni=mask.example.com,shadow-tls-version=3,alpn="h2,http/1.1"`) {
		t.Errorf("loon shadow-tls output wrong: %q", out)
	}
}

// TestLoonWireGuard mirrors loon.js wireguard(): peers are flattened into
// interface fields and a peers=[...] section.
func TestLoonWireGuard(t *testing.T) {
	wg := surgeFamilyProxy(map[string]any{
		"name":   "W1",
		"server": "wg.example.com",
		"port":   51820,
		"type":   "wireguard",
		"peers": []any{
			map[string]any{
				"server":      "wg2.example.com",
				"port":        51821,
				"ip":          "10.0.0.1",
				"ipv6":        "fd00::1",
				"public-key":  "pubkey1",
				"pre-shared-key": "psk1",
				"allowed-ips": []any{"0.0.0.0/0", "::/0"},
				"reserved":    []any{1, 2, 3},
			},
		},
		"private-key": "priv1",
	})
	out := loonProduce(t, []*model.Proxy{wg})
	want := `W1=wireguard,interface-ip=10.0.0.1,interface-ipv6=fd00::1,private-key="priv1",peers=[{public-key="pubkey1",allowed-ips="0.0.0.0/0,::/0",endpoint=wg2.example.com:51821,reserved=[1,2,3],preshared-key="psk1"}]`
	if strings.TrimSpace(out) != want {
		t.Errorf("loon wireguard output wrong:\n got: %q\nwant: %q", out, want)
	}
}

// TestLoonBlockQuicAndUDP mirrors loon.js block-quic on/off handling.
func TestLoonBlockQuicAndUDP(t *testing.T) {
	ss := surgeFamilyProxy(map[string]any{
		"name":       "S1",
		"type":       "ss",
		"cipher":     "aes-256-gcm",
		"password":   "pw",
		"block-quic": "on",
		"udp":        true,
	})
	out := loonProduce(t, []*model.Proxy{ss})
	if !strings.Contains(out, "S1=shadowsocks,1.2.3.4,443,aes-256-gcm,\"pw\",block-quic=true,udp=true") {
		t.Errorf("loon block-quic on output wrong: %q", out)
	}
	ss.Set("block-quic", "off")
	out = loonProduce(t, []*model.Proxy{ss})
	if !strings.Contains(out, ",block-quic=false") {
		t.Errorf("loon block-quic off output wrong: %q", out)
	}
}
