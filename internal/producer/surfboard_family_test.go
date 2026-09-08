package producer

import (
	"strings"
	"testing"

	"substore/internal/model"
)

func surfboardProduce(t *testing.T, proxies []*model.Proxy) string {
	t.Helper()
	out, err := ProduceSurfboard(proxies, nil)
	if err != nil {
		t.Fatalf("surfboard produce: %v", err)
	}
	return out
}

// TestSurfboardSmoke mirrors surfboard.js: supported types become lines,
// unsupported types are skipped.
func TestSurfboardSmoke(t *testing.T) {
	raw := strings.Join([]string{
		"ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#SS1",
		"trojan://password@trojan.example.com:443?sni=trojan.example.com#Trojan1",
		"hysteria2://pass123@1.2.3.4:443?sni=www.foo.com#HY2",
		"anytls://secret@anytls.example.com:443#AnyTLS1",
		"vmess://eyJhZGQiOiIxLjEuMS4xIiwicG9ydCI6IjQ0MyIsImFpZCI6IjAiLCJpZCI6IjExMTExMTExLTExMTEtNDExMS04MTExLTExMTExMTExMTExMSIsIm5ldCI6IndzIiwicGF0aCI6Ii93cyIsInRscyI6InRscyJ9",
	}, "\n")
	proxies := parseMixed(raw, t)
	if len(proxies) == 0 {
		t.Fatal("expected parsed proxies")
	}
	out := surfboardProduce(t, proxies)
	for _, want := range []string{
		`SS1=ss,1.2.3.4,8888,encrypt-method=aes-256-gcm,password="pass"`,
		"Trojan1=trojan,trojan.example.com,443,password=password",
		`HY2=hysteria2,1.2.3.4,443,password="pass123"`,
		`AnyTLS1=anytls,anytls.example.com,443,password="secret"`,
		"VMess 1.1.1.1:443=vmess,1.1.1.1,443,username=" + testUUID + ",ws=true,ws-path=/ws,ws-headers=Host:\"\",vmess-aead=true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("surfboard output missing %q:\n%s", want, out)
		}
	}
}

// TestSurfboardVmess mirrors surfboard.js vmess(): vmess-aead falls back to
// alterId === 0 when aead is absent; tcp + reality is rejected; ws is kept.
func TestSurfboardVmess(t *testing.T) {
	vmess := surgeFamilyProxy(map[string]any{
		"name":    "V1",
		"type":    "vmess",
		"uuid":    testUUID,
		"alterId": 0,
		"tls":     true,
		"network": "ws",
		"ws-opts": map[string]any{
			"path": "/ws",
			"headers": map[string]any{
				"Host": "cdn.example.com",
			},
		},
	})
	out := surfboardProduce(t, []*model.Proxy{vmess})
	if !strings.Contains(out, "V1=vmess,1.2.3.4,443,username="+testUUID+",ws=true,ws-path=/ws,ws-headers=Host:\"cdn.example.com\",vmess-aead=true,tls=true") {
		t.Errorf("surfboard vmess output wrong: %q", out)
	}

	reality := surgeFamilyProxy(map[string]any{
		"name":         "V2",
		"type":         "vmess",
		"uuid":         testUUID,
		"network":      "tcp",
		"reality-opts": map[string]any{"public-key": "pk"},
	})
	if out := surfboardProduce(t, []*model.Proxy{reality}); strings.Contains(out, "V2") {
		t.Errorf("surfboard should reject tcp + reality: %q", out)
	}

	grpc := surgeFamilyProxy(map[string]any{
		"name":    "V3",
		"type":    "vmess",
		"uuid":    testUUID,
		"network": "grpc",
	})
	if out := surfboardProduce(t, []*model.Proxy{grpc}); strings.Contains(out, "V3") {
		t.Errorf("surfboard should reject non-tcp/ws network: %q", out)
	}
}

// TestSurfboardTuic mirrors surfboard.js tuic(): token means v4 and is
// rejected; tuic-v5 is emitted with alpn and port-hopping.
func TestSurfboardTuic(t *testing.T) {
	v5 := surgeFamilyProxy(map[string]any{
		"name":       "T1",
		"type":       "tuic",
		"uuid":       testUUID,
		"password":   "pw",
		"alpn":       []any{"h3", "h2"},
		"udp":        false,
		"ports":      "443;444",
		"hop-interval": "1",
	})
	out := surfboardProduce(t, []*model.Proxy{v5})
	want := `T1=tuic-v5,1.2.3.4,443,uuid=` + testUUID + `,password="pw",alpn="h3,h2",port-hopping="443;444",port-hopping-interval=1,udp-relay=false`
	if strings.TrimSpace(out) != want {
		t.Errorf("surfboard tuic output wrong:\n got: %q\nwant: %q", out, want)
	}

	v4 := surgeFamilyProxy(map[string]any{
		"name":    "T2",
		"type":    "tuic",
		"token":   []any{"token1"},
		"uuid":    testUUID,
		"password": "pw",
	})
	if out := surfboardProduce(t, []*model.Proxy{v4}); strings.Contains(out, "T2") {
		t.Errorf("surfboard should reject tuic v4 with token: %q", out)
	}

	// surfboard.js `proxy.token?.length` is truthy for non-empty strings too
	v4StringToken := surgeFamilyProxy(map[string]any{
		"name":    "T3",
		"type":    "tuic",
		"token":   "token1",
		"uuid":    testUUID,
		"password": "pw",
	})
	if out := surfboardProduce(t, []*model.Proxy{v4StringToken}); strings.Contains(out, "T3") {
		t.Errorf("surfboard should reject tuic v4 with string token: %q", out)
	}
}

// TestSurfboardHysteria2 mirrors surfboard.js hysteria2(): only salamander
// obfs is supported and download-bandwidth is the first digit run of down.
func TestSurfboardHysteria2(t *testing.T) {
	ok := surgeFamilyProxy(map[string]any{
		"name":          "H1",
		"type":          "hysteria2",
		"password":      "pw",
		"obfs":          "salamander",
		"obfs-password": "sp",
		"down":          "50 mbps",
	})
	out := surfboardProduce(t, []*model.Proxy{ok})
	if !strings.Contains(out, `H1=hysteria2,1.2.3.4,443,password="pw",salamander-password="sp",download-bandwidth=50`) {
		t.Errorf("surfboard hysteria2 output wrong: %q", out)
	}

	bad := surgeFamilyProxy(map[string]any{
		"name":          "H2",
		"type":          "hysteria2",
		"password":      "pw",
		"obfs":          "gecko",
		"obfs-password": "gp",
	})
	if out := surfboardProduce(t, []*model.Proxy{bad}); strings.Contains(out, "H2") {
		t.Errorf("surfboard should reject non-salamander obfs: %q", out)
	}
}

// TestSurfboardSnellAndSS mirrors surfboard.js snell()/shadowsocks():
// snell versions 1-5 only, ss plugins limited to obfs.
func TestSurfboardSnellAndSS(t *testing.T) {
	snell := surgeFamilyProxy(map[string]any{
		"name":    "S1",
		"type":    "snell",
		"version": 3,
		"psk":     "psk1",
		"udp":     false,
	})
	out := surfboardProduce(t, []*model.Proxy{snell})
	if !strings.Contains(out, `S1=snell,1.2.3.4,443,version=3,psk="psk1",udp-relay=false`) {
		t.Errorf("surfboard snell v3 output wrong: %q", out)
	}

	snellV6 := surgeFamilyProxy(map[string]any{
		"name":    "S2",
		"type":    "snell",
		"version": 6,
		"psk":     "psk1",
	})
	if out := surfboardProduce(t, []*model.Proxy{snellV6}); strings.Contains(out, "S2") {
		t.Errorf("surfboard should reject snell v6: %q", out)
	}

	ssV2Ray := surgeFamilyProxy(map[string]any{
		"name":     "S3",
		"type":     "ss",
		"cipher":   "aes-256-gcm",
		"password": "pw",
		"plugin":   "v2ray-plugin",
	})
	if out := surfboardProduce(t, []*model.Proxy{ssV2Ray}); strings.Contains(out, "S3") {
		t.Errorf("surfboard should reject v2ray-plugin: %q", out)
	}

	ssObfs := surgeFamilyProxy(map[string]any{
		"name":     "S4",
		"type":     "ss",
		"cipher":   "aes-256-gcm",
		"password": "pw",
		"plugin":   "obfs",
		"plugin-opts": map[string]any{
			"mode": "http",
			"host": "obfs.example.com",
		},
	})
	out = surfboardProduce(t, []*model.Proxy{ssObfs})
	if !strings.Contains(out, "S4=ss,1.2.3.4,443,encrypt-method=aes-256-gcm,password=\"pw\",obfs=http,obfs-host=obfs.example.com") {
		t.Errorf("surfboard ss obfs output wrong: %q", out)
	}
}

// TestSurfboardWireGuard mirrors surfboard.js wireguard(): only
// wireguard-surge typed proxies are rendered.
func TestSurfboardWireGuard(t *testing.T) {
	wg := surgeFamilyProxy(map[string]any{
		"name":         "W1",
		"type":         "wireguard-surge",
		"section-name": "wg0",
		"block-quic":   false,
	})
	out := surfboardProduce(t, []*model.Proxy{wg})
	if strings.TrimSpace(out) != "W1=wireguard,section-name=wg0,block-quic=false" {
		t.Errorf("surfboard wireguard output wrong: %q", out)
	}

	plainWG := surgeFamilyProxy(map[string]any{
		"name":       "W2",
		"type":       "wireguard",
		"public-key": "pk",
	})
	if out := surfboardProduce(t, []*model.Proxy{plainWG}); strings.Contains(out, "W2") {
		t.Errorf("surfboard should reject plain wireguard: %q", out)
	}
}
