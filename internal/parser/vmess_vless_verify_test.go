package parser

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

const vlessTestUUID = "11111111-1111-4111-8111-111111111111"

// uqe mirrors JS encodeURIComponent for the limited charset used in the spec
// links (url.QueryEscape encodes spaces as '+' while encodeURIComponent uses
// '%20').
func uqe(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func vmessJSON(v any) string {
	b, _ := json.Marshal(v)
	return b64(string(b))
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func parseOneProxyMap(t *testing.T, input string) map[string]any {
	t.Helper()
	proxies := ParseText(input)
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	b, _ := json.Marshal(proxies[0].Fields())
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func nested(t *testing.T, got map[string]any, keys ...string) any {
	t.Helper()
	cur := got
	for i, k := range keys {
		v, ok := cur[k]
		if !ok {
			t.Fatalf("missing nested key %q", strings.Join(keys, "."))
		}
		if i == len(keys)-1 {
			return v
		}
		next, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("nested key %q is not a map", strings.Join(keys[:i+1], "."))
		}
		cur = next
	}
	return nil
}

func checkAbsent(t *testing.T, got map[string]any, keys ...string) {
	t.Helper()
	cur := got
	for i, k := range keys {
		v, ok := cur[k]
		if !ok {
			return
		}
		if i == len(keys)-1 {
			t.Errorf("expected %q to be absent, got %v", strings.Join(keys, "."), v)
			return
		}
		next, ok := v.(map[string]any)
		if !ok {
			return
		}
		cur = next
	}
}

func checkRejected(t *testing.T, input string) {
	t.Helper()
	if proxies := ParseText(input); len(proxies) != 0 {
		t.Errorf("expected 0 proxies for %q, got %d", input, len(proxies))
	}
}

func checkDeepEqual(t *testing.T, got, want any) {
	t.Helper()
	gb, _ := json.Marshal(got)
	wb, _ := json.Marshal(want)
	if string(gb) != string(wb) {
		t.Errorf("got %s, want %s", gb, wb)
	}
}

// TestVMessURI mirrors the VMess URI cases from Sub-Store's
// v2ray-and-platforms.spec.js.
func TestVMessURI(t *testing.T) {
	t.Run("QX share", func(t *testing.T) {
		share := b64("QX VMess = vmess,vmess-qx.example.com,443,auto,\"" + vlessTestUUID + "\",udp-relay=true,fast-open=true,tls-verification=false")
		checkSubset(t, "vmess://"+share, map[string]any{
			"type":             "vmess",
			"name":             "QX VMess",
			"server":           "vmess-qx.example.com",
			"port":             443,
			"cipher":           "auto",
			"uuid":             vlessTestUUID,
			"udp":              true,
			"tfo":              "true",
			"skip-cert-verify": false,
		})
	})

	t.Run("V2rayN ws", func(t *testing.T) {
		payload := vmessJSON(map[string]any{
			"ps":   "VMess WS",
			"add":  "vmess-ws.example.com",
			"port": "443",
			"id":   vlessTestUUID,
			"aid":  "0",
			"scy":  "auto",
			"net":  "ws",
			"host": "cdn.example.com",
			"path": "/ws",
		})
		checkSubset(t, "vmess://"+payload, map[string]any{
			"type":    "vmess",
			"name":    "VMess WS",
			"server":  "vmess-ws.example.com",
			"port":    443,
			"uuid":    vlessTestUUID,
			"alterId": 0,
			"cipher":  "auto",
			"network": "ws",
			"ws-opts": map[string]any{
				"path":    "/ws",
				"headers": map[string]any{"Host": "cdn.example.com"},
			},
		})
	})

	t.Run("fragment", func(t *testing.T) {
		payload := vmessJSON(map[string]any{
			"ps":   "Fragment",
			"add":  "fragment.example.com",
			"port": "443",
			"id":   vlessTestUUID,
			"aid":  "0",
			"scy":  "auto",
			"net":  "ws",
			"host": "ws.example.com",
			"path": "/fragment?ed=2560",
		})
		checkSubset(t, "vmess://"+payload+"#Outer%20Fragment%20Remark", map[string]any{
			"type":    "vmess",
			"name":    "Outer Fragment Remark",
			"network": "ws",
			"ws-opts": map[string]any{
				"path":                    "/fragment",
				"max-early-data":          2560,
				"early-data-header-name":  "Sec-WebSocket-Protocol",
				"headers":                 map[string]any{"Host": "ws.example.com"},
			},
		})
	})

	t.Run("full fragment", func(t *testing.T) {
		payload := vmessJSON(map[string]any{
			"ps":   "Full Fragment",
			"add":  "fragment.example.com",
			"port": "443",
			"id":   vlessTestUUID,
			"aid":  "0",
			"scy":  "auto",
			"net":  "ws",
			"host": "ws.example.com",
			"path": "/fragment",
		})
		checkSubset(t, "vmess://"+payload+"#Outer%20Fragment%23Remark", map[string]any{
			"type":    "vmess",
			"name":    "Outer Fragment#Remark",
			"network": "ws",
			"ws-opts": map[string]any{
				"path":    "/fragment",
				"headers": map[string]any{"Host": "ws.example.com"},
			},
		})
	})

	t.Run("zero security", func(t *testing.T) {
		payload := vmessJSON(map[string]any{
			"ps":   "Zero",
			"add":  "zero.example.com",
			"port": "443",
			"id":   vlessTestUUID,
			"aid":  "0",
			"scy":  "zero",
			"net":  "tcp",
		})
		checkSubset(t, "vmess://"+payload, map[string]any{
			"type":   "vmess",
			"name":   "Zero",
			"server": "zero.example.com",
			"port":   443,
			"cipher": "zero",
			"network": "tcp",
		})
	})

	t.Run("h2", func(t *testing.T) {
		payload := vmessJSON(map[string]any{
			"ps":   "VMess H2",
			"add":  "vmess-http.example.com",
			"port": "443",
			"id":   vlessTestUUID,
			"aid":  "1",
			"scy":  "unknown-cipher",
			"net":  "http",
			"host": "h1.example.com,h2.example.com",
			"path": "/a,/b",
		})
		checkSubset(t, "vmess://"+payload, map[string]any{
			"type":    "vmess",
			"name":    "VMess H2",
			"server":  "vmess-http.example.com",
			"port":    443,
			"uuid":    vlessTestUUID,
			"alterId": 1,
			"cipher":  "auto",
			"network": "h2",
			"h2-opts": map[string]any{
				"host": []any{"h1.example.com", "h2.example.com"},
				"path": "/a,/b",
			},
		})
	})

	t.Run("tcp fake-http", func(t *testing.T) {
		payload := vmessJSON(map[string]any{
			"ps":   "VMess HTTP Header",
			"add":  "vmess-http-header.example.com",
			"port": "80",
			"id":   vlessTestUUID,
			"aid":  "1",
			"scy":  "auto",
			"net":  "tcp",
			"type": "http",
			"host": "h1.example.com,h2.example.com",
			"path": "/a,/b",
		})
		checkSubset(t, "vmess://"+payload, map[string]any{
			"type":      "vmess",
			"name":      "VMess HTTP Header",
			"server":    "vmess-http-header.example.com",
			"port":      80,
			"uuid":      vlessTestUUID,
			"alterId":   1,
			"cipher":    "auto",
			"network":   "http",
			"http-opts": map[string]any{
				"headers": map[string]any{"Host": []any{"h1.example.com"}},
				"path":    []any{"/a,/b"},
			},
		})
	})

	t.Run("grpc", func(t *testing.T) {
		payload := vmessJSON(map[string]any{
			"ps":        "VMess gRPC",
			"add":       "vmess-grpc.example.com",
			"port":      "443",
			"id":        vlessTestUUID,
			"aid":       "0",
			"scy":       "auto",
			"net":       "grpc",
			"path":      "grpc-service",
			"type":      "multi",
			"authority": "grpc.example.com",
		})
		checkSubset(t, "vmess://"+payload, map[string]any{
			"type":    "vmess",
			"name":    "VMess gRPC",
			"server":  "vmess-grpc.example.com",
			"port":    443,
			"network": "grpc",
			"grpc-opts": map[string]any{
				"grpc-service-name": "grpc-service",
				"_grpc-type":        "multi",
				"_grpc-authority":   "grpc.example.com",
			},
		})
	})

	t.Run("quic", func(t *testing.T) {
		payload := vmessJSON(map[string]any{
			"ps":   "VMess QUIC",
			"add":  "vmess-quic.example.com",
			"port": "443",
			"id":   vlessTestUUID,
			"aid":  "0",
			"scy":  "auto",
			"net":  "quic",
			"host": "quic-host.example.com",
			"path": "/quic",
			"type": "wireguard",
		})
		checkSubset(t, "vmess://"+payload, map[string]any{
			"type":      "vmess",
			"name":      "VMess QUIC",
			"server":    "vmess-quic.example.com",
			"port":      443,
			"network":   "quic",
			"quic-opts": map[string]any{
				"_quic-type": "wireguard",
				"_quic-host": "quic-host.example.com",
				"_quic-path": "/quic",
			},
		})
	})

	t.Run("httpupgrade", func(t *testing.T) {
		payload := vmessJSON(map[string]any{
			"ps":   "VMess Upgrade",
			"add":  "vmess-upgrade.example.com",
			"port": "443",
			"id":   vlessTestUUID,
			"aid":  "0",
			"scy":  "auto",
			"net":  "httpupgrade",
			"host": "upgrade.example.com",
			"path": "/upgrade",
		})
		got := parseOneProxyMap(t, "vmess://"+payload)
		checkSubset(t, "vmess://"+payload, map[string]any{
			"type":    "vmess",
			"name":    "VMess Upgrade",
			"server":  "vmess-upgrade.example.com",
			"port":    443,
			"network": "ws",
			"ws-opts": map[string]any{
				"path":               "/upgrade",
				"headers":            map[string]any{"Host": "upgrade.example.com"},
				"v2ray-http-upgrade": true,
			},
		})
		checkAbsent(t, got, "ws-opts", "v2ray-http-upgrade-fast-open")
	})

	t.Run("httpupgrade path ed", func(t *testing.T) {
		payload := vmessJSON(map[string]any{
			"ps":   "VMess Upgrade ED",
			"add":  "vmess-upgrade.example.com",
			"port": "443",
			"id":   vlessTestUUID,
			"aid":  "0",
			"scy":  "auto",
			"net":  "httpupgrade",
			"host": "upgrade.example.com",
			"path": "/upgrade?a=1&ed=1024&b=2",
		})
		got := parseOneProxyMap(t, "vmess://"+payload)
		checkSubset(t, "vmess://"+payload, map[string]any{
			"type":    "vmess",
			"name":    "VMess Upgrade ED",
			"network": "ws",
			"ws-opts": map[string]any{
				"path":                      "/upgrade?a=1&b=2",
				"headers":                   map[string]any{"Host": "upgrade.example.com"},
				"v2ray-http-upgrade":        true,
				"v2ray-http-upgrade-fast-open": true,
				"_v2ray-http-upgrade-ed":    "1024",
			},
		})
		checkAbsent(t, got, "ws-opts", "max-early-data")
		checkAbsent(t, got, "ws-opts", "early-data-header-name")
	})

	t.Run("httpupgrade top-level ed", func(t *testing.T) {
		payload := vmessJSON(map[string]any{
			"ps":   "VMess Upgrade ED Param",
			"add":  "vmess-upgrade.example.com",
			"port": "443",
			"id":   vlessTestUUID,
			"aid":  "0",
			"scy":  "auto",
			"net":  "httpupgrade",
			"host": "upgrade.example.com",
			"path": "/upgrade",
			"ed":   "1024",
		})
		got := parseOneProxyMap(t, "vmess://"+payload)
		checkSubset(t, "vmess://"+payload, map[string]any{
			"network": "ws",
			"ws-opts": map[string]any{
				"path":                      "/upgrade",
				"headers":                   map[string]any{"Host": "upgrade.example.com"},
				"v2ray-http-upgrade":        true,
				"v2ray-http-upgrade-fast-open": true,
				"_v2ray-http-upgrade-ed":    "1024",
			},
		})
		checkAbsent(t, got, "ws-opts", "max-early-data")
	})

	t.Run("Shadowrocket vmess", func(t *testing.T) {
		base := b64("auto:" + vlessTestUUID + "@shadowrocket-vmess.example.com:443")
		input := "vmess://" + base + "?remarks=Shadowrocket%20VMess&obfs=websocket&path=%2Fshadow&obfsParam=ws.shadow.example.com&tls=1&peer=sni.shadow.example.com&allowInsecure=1&fp=safari&alpn=h2"
		checkSubset(t, input, map[string]any{
			"type":               "vmess",
			"name":               "Shadowrocket VMess",
			"server":             "shadowrocket-vmess.example.com",
			"port":               443,
			"uuid":               vlessTestUUID,
			"tls":                true,
			"sni":                "sni.shadow.example.com",
			"skip-cert-verify":   true,
			"client-fingerprint": "safari",
			"alpn":               []any{"h2"},
			"network":            "ws",
			"ws-opts": map[string]any{
				"path":    "/shadow",
				"headers": map[string]any{"Host": "ws.shadow.example.com"},
			},
		})
	})
}

// TestVLESSURI mirrors the VLESS URI cases from Sub-Store's
// v2ray-and-platforms.spec.js.
func TestVLESSURI(t *testing.T) {
	t.Run("ws", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@vless-ws.example.com:443?type=ws&security=tls&sni=sni.example.com&host=cdn.example.com&path=%2Fws&allowInsecure=1&fp=chrome&alpn=h2#VLESS%20WS"
		checkSubset(t, input, map[string]any{
			"type":               "vless",
			"name":               "VLESS WS",
			"server":             "vless-ws.example.com",
			"port":               443,
			"uuid":               vlessTestUUID,
			"tls":                true,
			"sni":                "sni.example.com",
			"skip-cert-verify":   true,
			"client-fingerprint": "chrome",
			"alpn":               []any{"h2"},
			"udp":                true,
			"packet-encoding":    "xudp",
			"network":            "ws",
			"ws-opts": map[string]any{
				"path":    "/ws",
				"headers": map[string]any{"Host": "cdn.example.com"},
			},
		})
	})

	t.Run("fragment full", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@fragment.example.com:443?type=ws&path=%2Ffrag#VLESS%20Outer%23Remark"
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS Outer#Remark",
			"network": "ws",
			"ws-opts": map[string]any{
				"path": "/frag",
			},
		})
	})

	t.Run("ws packet early data", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@ed.example.com:443?type=ws&security=tls&sni=ed.example.com&packetEncoding=packet&ed=2048&eh=X-Data#VLESS%20WS%20Packet%20Early%20Data"
		checkSubset(t, input, map[string]any{
			"type":            "vless",
			"server":          "ed.example.com",
			"sni":             "ed.example.com",
			"packet-encoding": "packetaddr",
			"network":         "ws",
			"ws-opts": map[string]any{
				"max-early-data":        2048,
				"early-data-header-name": "X-Data",
			},
		})
	})

	t.Run("ws xudp", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@xudp.example.com:443?type=ws&security=tls&sni=xudp.example.com&packetEncoding=xudp#VLESS%20WS%20XUDP"
		checkSubset(t, input, map[string]any{
			"type":            "vless",
			"server":          "xudp.example.com",
			"sni":             "xudp.example.com",
			"udp":             true,
			"packet-encoding": "xudp",
		})
	})

	t.Run("pcs", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@pcs.example.com:443?type=ws&security=tls&sni=pcs.example.com&pcs=fingerprint#VLESS%20PCS"
		checkSubset(t, input, map[string]any{
			"type":             "vless",
			"sni":              "pcs.example.com",
			"tls-fingerprint":  "fingerprint",
		})
	})

	t.Run("vcn", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@vcn.example.com:443?type=ws&security=tls&sni=vcn.example.com&vcn=" + uqe("first.example.com, second.example.com") + "#VLESS%20VCN"
		checkSubset(t, input, map[string]any{
			"type":             "vless",
			"name":             "VLESS VCN",
			"name-cert-verify": "first.example.com",
			"_vcn":             []any{"first.example.com", "second.example.com"},
		})
	})

	t.Run("ech config", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@ech.example.com:443?type=ws&security=ech&ech=ECHCONFIG#VLESS%20ECH%20Config"
		checkSubset(t, input, map[string]any{
			"type":           "vless",
			"tls":            true,
			"_echConfigList": "ECHCONFIG",
			"ech-opts": map[string]any{
				"enable": true,
				"config": "ECHCONFIG",
			},
		})
	})

	t.Run("ech dns", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@ech.example.com:443?type=ws&security=ech&ech=" + uqe("ech.example.com+https://1.1.1.1/dns-query") + "#VLESS%20ECH%20DNS"
		checkSubset(t, input, map[string]any{
			"type":           "vless",
			"_echConfigList": "ech.example.com+https://1.1.1.1/dns-query",
			"ech-opts": map[string]any{
				"enable":             true,
				"_dns":               "https://1.1.1.1/dns-query",
				"query-server-name":  "ech.example.com",
			},
		})
	})

	t.Run("grpc reality", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@vless-grpc.example.com:443?type=grpc&security=reality&serviceName=grpc-service&authority=grpc.example.com&mode=multi&pbk=pubkey&sid=08&spx=%2Fspider&flow=xtls-rprx-vision&encryption=none&pqv=1&alpn=h2#VLESS%20Reality"
		checkSubset(t, input, map[string]any{
			"type":        "vless",
			"name":        "VLESS Reality",
			"server":      "vless-grpc.example.com",
			"port":        443,
			"uuid":        vlessTestUUID,
			"tls":         true,
			"flow":        "xtls-rprx-vision",
			"encryption":  "none",
			"_pqv":        "1",
			"alpn":        []any{"h2"},
			"network":     "grpc",
			"grpc-opts": map[string]any{
				"grpc-service-name": "grpc-service",
				"_grpc-authority":   "grpc.example.com",
				"_grpc-type":        "multi",
			},
			"reality-opts": map[string]any{
				"public-key": "pubkey",
				"short-id":   "08",
				"_spider-x":  "/spider",
			},
			"_mode": "multi",
		})
	})

	t.Run("pbk with tls", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@vless-grpc.example.com:443?type=grpc&security=tls&serviceName=grpc-service&pbk=pubkey&sid=08#VLESS%20PBK"
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS PBK",
			"tls":     true,
			"network": "grpc",
			"grpc-opts": map[string]any{
				"grpc-service-name": "grpc-service",
				"_grpc-type":        "gun",
			},
			"reality-opts": map[string]any{
				"public-key": "pubkey",
				"short-id":   "08",
			},
		})
	})

	t.Run("pbk without tls", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@vless-grpc.example.com:443?type=grpc&security=none&serviceName=grpc-service&pbk=pubkey&sid=08#VLESS%20PBK%20No%20TLS"
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS PBK No TLS",
			"tls":     false,
			"network": "grpc",
			"grpc-opts": map[string]any{
				"grpc-service-name": "grpc-service",
				"_grpc-type":        "gun",
			},
			"reality-opts": map[string]any{
				"public-key": "pubkey",
				"short-id":   "08",
			},
		})
	})

	t.Run("tcp http header", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@vless-tcp-http.example.com:443?type=tcp&headerType=http&host=http.example.com&path=%2Fedge&method=GET#VLESS%20TCP%20HTTP"
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS TCP HTTP",
			"network": "http",
			"http-opts": map[string]any{
				"headers": map[string]any{"Host": []any{"http.example.com"}},
				"method":  "GET",
				"path":    []any{"/edge"},
			},
		})
	})

	t.Run("httpupgrade", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@vless-upgrade.example.com:443?type=httpupgrade&host=upgrade.example.com&path=%2Fupgrade#VLESS%20HTTP%20Upgrade"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS HTTP Upgrade",
			"network": "ws",
			"ws-opts": map[string]any{
				"path":               "/upgrade",
				"headers":            map[string]any{"Host": "upgrade.example.com"},
				"v2ray-http-upgrade": true,
			},
		})
		checkAbsent(t, got, "ws-opts", "v2ray-http-upgrade-fast-open")
	})

	t.Run("httpupgrade ed", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@vless-upgrade.example.com:443?type=httpupgrade&host=upgrade.example.com&path=%2Fupgrade&ed=1024&eh=X-Upgrade#VLESS%20HTTP%20Upgrade%20Early%20Data"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"network": "ws",
			"ws-opts": map[string]any{
				"path":                      "/upgrade",
				"headers":                   map[string]any{"Host": "upgrade.example.com"},
				"v2ray-http-upgrade":        true,
				"v2ray-http-upgrade-fast-open": true,
				"_v2ray-http-upgrade-ed":    "1024",
				"early-data-header-name":    "X-Upgrade",
			},
		})
		checkAbsent(t, got, "ws-opts", "max-early-data")
	})

	t.Run("httpupgrade path ed", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@vless-upgrade.example.com:443?type=httpupgrade&host=upgrade.example.com&path=%2Fupgrade%3Fa%3D1%26ed%3D1024%26b%3D2#VLESS%20HTTP%20Upgrade%20Path%20ED"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"network": "ws",
			"ws-opts": map[string]any{
				"path":                      "/upgrade?a=1&b=2",
				"headers":                   map[string]any{"Host": "upgrade.example.com"},
				"v2ray-http-upgrade":        true,
				"v2ray-http-upgrade-fast-open": true,
				"_v2ray-http-upgrade-ed":    "1024",
			},
		})
		checkAbsent(t, got, "ws-opts", "max-early-data")
		checkAbsent(t, got, "ws-opts", "early-data-header-name")
	})

	t.Run("httpupgrade duplicate ed", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@vless-upgrade.example.com:443?type=httpupgrade&host=upgrade.example.com&path=%2Fupgrade%3Fed%3D1024&ed=2048#VLESS%20HTTP%20Upgrade%20Dup%20ED"
		checkSubset(t, input, map[string]any{
			"network": "ws",
			"ws-opts": map[string]any{
				"path":                      "/upgrade",
				"headers":                   map[string]any{"Host": "upgrade.example.com"},
				"v2ray-http-upgrade":        true,
				"v2ray-http-upgrade-fast-open": true,
				"_v2ray-http-upgrade-ed":    "1024",
			},
		})
	})

	t.Run("ws path ed", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@vless-ws.example.com:443?type=ws&host=ws.example.com&path=%2Fws%3Fa%3D1%26ed%3D2048%26b%3D2#VLESS%20WS%20Path%20Early%20Data"
		checkSubset(t, input, map[string]any{
			"network": "ws",
			"ws-opts": map[string]any{
				"path":                   "/ws?a=1&b=2",
				"max-early-data":         2048,
				"early-data-header-name": "Sec-WebSocket-Protocol",
			},
		})
	})

	t.Run("kcp", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@vless-kcp.example.com:443?type=kcp&headerType=srtp&host=kcp.example.com&path=%2Fkcp&seed=seed-value&mode=packet&extra=extra-value#VLESS%20KCP"
		checkSubset(t, input, map[string]any{
			"type":       "vless",
			"name":       "VLESS KCP",
			"network":    "kcp",
			"seed":       "seed-value",
			"headerType": "srtp",
			"_mode":      "packet",
			"_extra":     "extra-value",
			"kcp-opts": map[string]any{
				"headers": map[string]any{"Host": "kcp.example.com"},
				"path":    "/kcp",
			},
		})
	})

	t.Run("h2", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@vless-h2.example.com:443?type=http&host=h2.example.com,h2-alt.example.com&path=%2Fh2&h2=1&packetEncoding=none#VLESS%20H2"
		checkSubset(t, input, map[string]any{
			"type":            "vless",
			"name":            "VLESS H2",
			"udp":             true,
			"packet-encoding": "",
			"network":         "h2",
			"_h2":             true,
			"h2-opts": map[string]any{
				"host": []any{"h2.example.com", "h2-alt.example.com"},
				"path": "/h2",
			},
		})
	})

	t.Run("h2 headers", func(t *testing.T) {
		obfsParam := mustJSON(map[string]any{
			"Host":       "cdn.example.com",
			"User-Agent": "curl/7.77.0",
		})
		input := "vless://" + vlessTestUUID + "@vless-h2.example.com:443?type=http&obfsParam=" + uqe(obfsParam) + "&path=%2Fh2#VLESS%20H2%20Headers"
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS H2 Headers",
			"network": "h2",
			"h2-opts": map[string]any{
				"headers": map[string]any{"User-Agent": "curl/7.77.0"},
				"host":    []any{"cdn.example.com"},
				"path":    "/h2",
			},
		})
	})

	t.Run("xhttp mihomo transport extras", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"noGRPCHeader":        true,
			"xPaddingBytes":       "64-128",
			"scMaxEachPostBytes":  1000000,
			"scMinPostsIntervalMs": 300,
			"sessionIDTable":      "abcXYZ012",
			"sessionIDLength":     16,
			"xmux": map[string]any{
				"maxConnections":   0,
				"maxConcurrency":   "16-32",
				"cMaxReuseTimes":   "64-128",
				"hMaxRequestTimes": "600-900",
				"hMaxReusableSecs": "1800-3000",
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP",
			"server":  "vless-xhttp.example.com",
			"port":    443,
			"uuid":    vlessTestUUID,
			"tls":     true,
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode":                    "stream-up",
				"path":                    "/xhttp",
				"host":                    "cdn.example.com",
				"no-grpc-header":          true,
				"x-padding-bytes":         "64-128",
				"sc-max-each-post-bytes":  1000000,
				"sc-min-posts-interval-ms": 300,
				"session-table":           "abcXYZ012",
				"session-length":          "16",
				"reuse-settings": map[string]any{
					"max-connections":    "0",
					"max-concurrency":   "16-32",
					"c-max-reuse-times": "64-128",
					"h-max-request-times": "600-900",
					"h-max-reusable-secs": "1800-3000",
				},
			},
		})
		checkAbsent(t, got, "_extra")
		checkAbsent(t, got, "_extra_unsupported")
	})

	t.Run("xhttp host from obfsParam", func(t *testing.T) {
		obfsParam := mustJSON(map[string]any{
			"Host":   "header.example.com",
			"X-Test": "demo",
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&obfsParam=" + uqe(obfsParam) + "&path=%2Fxhttp#VLESS%20XHTTP%20Host%20Header"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"host":    "header.example.com",
				"path":    "/xhttp",
				"headers": map[string]any{"X-Test": "demo"},
			},
		})
		checkAbsent(t, got, "xhttp-opts", "headers", "Host")
	})

	t.Run("xhttp downloadSettings", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"downloadSettings": map[string]any{
				"address":  "download.example.com",
				"port":     8443,
				"security": "tls",
				"tlsSettings": map[string]any{
					"serverName":  "download-sni.example.com",
					"fingerprint": "chrome",
					"alpn":        []any{"h2", "http/1.1"},
				},
				"xhttpSettings": map[string]any{
					"path":                 "/download",
					"host":                 "download-host.example.com",
					"noGRPCHeader":         true,
					"xPaddingBytes":        "32-64",
					"sessionIDTable":       "Base62",
					"scMaxEachPostBytes":   "500000-1000000",
					"scMinPostsIntervalMs": "0-300",
					"extra": map[string]any{
						"sessionIDLength": "8-12",
						"xmux": map[string]any{
							"maxConnections":  "8",
							"hMaxReusableSecs": "900",
						},
					},
				},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Download"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP Download",
			"tls":     true,
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode": "stream-up",
				"path": "/xhttp",
				"host": "cdn.example.com",
				"download-settings": map[string]any{
					"server":               "download.example.com",
					"port":                 8443,
					"tls":                  true,
					"servername":           "download-sni.example.com",
					"client-fingerprint":   "chrome",
					"alpn":                 []any{"h2", "http/1.1"},
					"path":                 "/download",
					"host":                 "download-host.example.com",
					"no-grpc-header":       true,
					"x-padding-bytes":      "32-64",
					"session-table":        "Base62",
					"session-length":       "8-12",
					"sc-max-each-post-bytes": "500000-1000000",
					"sc-min-posts-interval-ms": "0-300",
					"reuse-settings": map[string]any{
						"max-connections":     "8",
						"h-max-reusable-secs": "900",
					},
				},
			},
		})
		checkAbsent(t, got, "xhttp-opts", "download-settings", "network")
		checkAbsent(t, got, "_extra_unsupported")
	})

	t.Run("xhttp downloadSettings without mode", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"downloadSettings": map[string]any{
				"address":  "download.example.com",
				"port":     8443,
				"security": "tls",
				"tlsSettings": map[string]any{
					"serverName": "download-sni.example.com",
				},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Download%20No%20Mode"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP Download No Mode",
			"tls":     true,
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"path": "/xhttp",
				"host": "cdn.example.com",
				"download-settings": map[string]any{
					"server":     "download.example.com",
					"port":       8443,
					"tls":        true,
					"servername": "download-sni.example.com",
				},
			},
		})
		checkAbsent(t, got, "xhttp-opts", "mode")
	})

	t.Run("xhttp downloadSettings unsupported only", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"downloadSettings": map[string]any{
				"network": "xhttp",
				"sockopt": map[string]any{"mark": 255},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Download%20Unsupported%20Only"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP Download Unsupported Only",
			"tls":     true,
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode": "stream-up",
				"path": "/xhttp",
				"host": "cdn.example.com",
				"download-settings": map[string]any{
					"network": "xhttp",
				},
			},
		})
		checkDeepEqual(t, nested(t, got, "_extra_unsupported"), map[string]any{
			"downloadSettings": map[string]any{
				"sockopt": map[string]any{"mark": 255},
			},
		})
	})

	t.Run("xhttp splithttp downloadSettings", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"downloadSettings": map[string]any{
				"network": "splithttp",
				"sockopt": map[string]any{"mark": 255},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Download%20SplitHTTP"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP Download SplitHTTP",
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode": "stream-up",
				"path": "/xhttp",
				"host": "cdn.example.com",
				"download-settings": map[string]any{
					"network": "xhttp",
				},
			},
		})
		checkDeepEqual(t, nested(t, got, "_extra_unsupported"), map[string]any{
			"downloadSettings": map[string]any{
				"sockopt": map[string]any{"mark": 255},
			},
		})
	})

	t.Run("xhttp reality marker", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"downloadSettings": map[string]any{
				"address":  "download.example.com",
				"network":  "xhttp",
				"port":     8443,
				"security": "reality",
				"xhttpSettings": map[string]any{
					"path": "/download",
				},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Download%20Reality%20Marker"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP Download Reality Marker",
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode": "stream-up",
				"path": "/xhttp",
				"host": "cdn.example.com",
				"download-settings": map[string]any{
					"network": "xhttp",
					"server":  "download.example.com",
					"port":    8443,
					"tls":     true,
					"path":    "/download",
				},
			},
		})
		checkDeepEqual(t, nested(t, got, "xhttp-opts", "download-settings", "reality-opts"), map[string]any{})
		checkAbsent(t, got, "_extra_unsupported")
	})

	t.Run("xhttp invalid extra raw", func(t *testing.T) {
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe("{bad") + "#VLESS%20XHTTP%20Invalid%20Extra"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP Invalid Extra",
			"tls":     true,
			"network": "xhttp",
			"_extra":  "{bad",
			"xhttp-opts": map[string]any{
				"mode": "stream-up",
				"path": "/xhttp",
				"host": "cdn.example.com",
			},
		})
		checkAbsent(t, got, "_extra_unsupported")
	})

	scMinReuseSettings := map[string]any{
		"max-connections":     "0",
		"max-concurrency":     "16-32",
		"c-max-reuse-times":   "64-128",
		"h-max-request-times": "600-900",
		"h-max-reusable-secs": "1800-3000",
	}

	t.Run("xhttp scMinPostsIntervalMs range", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"noGRPCHeader":        true,
			"xPaddingBytes":       "64-128",
			"scMinPostsIntervalMs": "100 - 300",
			"xmux": map[string]any{
				"maxConnections":   0,
				"maxConcurrency":   "16-32",
				"cMaxReuseTimes":   "64-128",
				"hMaxRequestTimes": "600-900",
				"hMaxReusableSecs": "1800-3000",
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Min%20Interval%20Range"
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP Min Interval Range",
			"tls":     true,
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode":                    "stream-up",
				"path":                    "/xhttp",
				"host":                    "cdn.example.com",
				"no-grpc-header":          true,
				"x-padding-bytes":         "64-128",
				"sc-min-posts-interval-ms": "100-300",
				"reuse-settings":           scMinReuseSettings,
			},
		})
	})

	t.Run("xhttp scMinPostsIntervalMs string", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"noGRPCHeader":        true,
			"xPaddingBytes":       "64-128",
			"scMinPostsIntervalMs": "300",
			"xmux": map[string]any{
				"maxConnections":   0,
				"maxConcurrency":   "16-32",
				"cMaxReuseTimes":   "64-128",
				"hMaxRequestTimes": "600-900",
				"hMaxReusableSecs": "1800-3000",
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Min%20Interval%20String"
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP Min Interval String",
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode":                    "stream-up",
				"path":                    "/xhttp",
				"host":                    "cdn.example.com",
				"no-grpc-header":          true,
				"x-padding-bytes":         "64-128",
				"sc-min-posts-interval-ms": 300,
				"reuse-settings":           scMinReuseSettings,
			},
		})
	})

	t.Run("xhttp scMinPostsIntervalMs zero lower bound", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"noGRPCHeader":        true,
			"xPaddingBytes":       "64-128",
			"scMinPostsIntervalMs": "0-300",
			"xmux": map[string]any{
				"maxConnections":   0,
				"maxConcurrency":   "16-32",
				"cMaxReuseTimes":   "64-128",
				"hMaxRequestTimes": "600-900",
				"hMaxReusableSecs": "1800-3000",
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Min%20Interval%20Zero%20Lower%20Bound"
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP Min Interval Zero Lower Bound",
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode":                    "stream-up",
				"path":                    "/xhttp",
				"host":                    "cdn.example.com",
				"no-grpc-header":          true,
				"x-padding-bytes":         "64-128",
				"sc-min-posts-interval-ms": "0-300",
				"reuse-settings":           scMinReuseSettings,
			},
		})
	})

	t.Run("xhttp leading-zero scalars", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"noGRPCHeader":        true,
			"xPaddingBytes":       "64-128",
			"scMaxEachPostBytes":  "000001-1000000",
			"scMinPostsIntervalMs": "0300",
			"downloadSettings": map[string]any{
				"address":  "download.example.com",
				"port":     8443,
				"security": "tls",
				"xhttpSettings": map[string]any{
					"path":                 "/download",
					"host":                 "download-host.example.com",
					"scMaxEachPostBytes":   "000001-1000000",
					"scMinPostsIntervalMs": "000-300",
				},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Leading%20Zero%20Scalars"
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP Leading Zero Scalars",
			"tls":     true,
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode":                    "stream-up",
				"path":                    "/xhttp",
				"host":                    "cdn.example.com",
				"no-grpc-header":          true,
				"x-padding-bytes":         "64-128",
				"sc-max-each-post-bytes":  "1-1000000",
				"sc-min-posts-interval-ms": 300,
				"download-settings": map[string]any{
					"server":                  "download.example.com",
					"port":                    8443,
					"tls":                     true,
					"path":                    "/download",
					"host":                    "download-host.example.com",
					"sc-max-each-post-bytes":  "1-1000000",
					"sc-min-posts-interval-ms": "0-300",
				},
			},
		})
	})

	t.Run("xhttp explicit-plus scalars", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"noGRPCHeader":        true,
			"xPaddingBytes":       "64-128",
			"scMaxEachPostBytes":  "+500000-+1000000",
			"scMinPostsIntervalMs": "+300",
			"downloadSettings": map[string]any{
				"address":  "download.example.com",
				"port":     8443,
				"security": "tls",
				"xhttpSettings": map[string]any{
					"path":                 "/download",
					"host":                 "download-host.example.com",
					"scMaxEachPostBytes":   "+1-+1000000",
					"scMinPostsIntervalMs": "+0-+300",
				},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Explicit%20Plus%20Scalars"
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP Explicit Plus Scalars",
			"tls":     true,
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode":                    "stream-up",
				"path":                    "/xhttp",
				"host":                    "cdn.example.com",
				"no-grpc-header":          true,
				"x-padding-bytes":         "64-128",
				"sc-max-each-post-bytes":  "500000-1000000",
				"sc-min-posts-interval-ms": 300,
				"download-settings": map[string]any{
					"server":                  "download.example.com",
					"port":                    8443,
					"tls":                     true,
					"path":                    "/download",
					"host":                    "download-host.example.com",
					"sc-max-each-post-bytes":  "1-1000000",
					"sc-min-posts-interval-ms": "0-300",
				},
			},
		})
	})

	t.Run("xhttp invalid scMinPostsIntervalMs values", func(t *testing.T) {
		invalidValues := []any{"1.5", 1.5, "0", 0, "0-0", "fast", "10-1", "9007199254740993", "1-9007199254740993"}
		for _, value := range invalidValues {
			extra := mustJSON(map[string]any{
				"noGRPCHeader":        true,
				"xPaddingBytes":       "64-128",
				"scMinPostsIntervalMs": value,
				"xmux": map[string]any{
					"maxConnections":   0,
					"maxConcurrency":   "16-32",
					"cMaxReuseTimes":   "64-128",
					"hMaxRequestTimes": "600-900",
					"hMaxReusableSecs": "1800-3000",
				},
			})
			input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Min%20Interval%20Invalid"
			got := parseOneProxyMap(t, input)
			checkSubset(t, input, map[string]any{
				"type":    "vless",
				"tls":     true,
				"network": "xhttp",
				"xhttp-opts": map[string]any{
					"mode":            "stream-up",
					"path":            "/xhttp",
					"host":            "cdn.example.com",
					"no-grpc-header":  true,
					"x-padding-bytes": "64-128",
					"reuse-settings":  scMinReuseSettings,
				},
			})
			checkAbsent(t, got, "xhttp-opts", "sc-min-posts-interval-ms")
			checkDeepEqual(t, nested(t, got, "_extra_unsupported"), map[string]any{
				"scMinPostsIntervalMs": value,
			})
		}
	})

	t.Run("xhttp invalid nested scMinPostsIntervalMs", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"downloadSettings": map[string]any{
				"address":  "download.example.com",
				"port":     8443,
				"security": "tls",
				"tlsSettings": map[string]any{
					"serverName": "download-sni.example.com",
				},
				"xhttpSettings": map[string]any{
					"path":                 "/download",
					"host":                 "download-host.example.com",
					"noGRPCHeader":         true,
					"xPaddingBytes":        "32-64",
					"scMinPostsIntervalMs": "0-0",
				},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Download%20Invalid%20Min%20Interval"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"tls":     true,
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode": "stream-up",
				"path": "/xhttp",
				"host": "cdn.example.com",
				"download-settings": map[string]any{
					"server":           "download.example.com",
					"port":             8443,
					"tls":              true,
					"servername":       "download-sni.example.com",
					"path":             "/download",
					"host":             "download-host.example.com",
					"no-grpc-header":   true,
					"x-padding-bytes":  "32-64",
				},
			},
		})
		checkAbsent(t, got, "xhttp-opts", "download-settings", "sc-min-posts-interval-ms")
		checkDeepEqual(t, nested(t, got, "_extra_unsupported"), map[string]any{
			"downloadSettings": map[string]any{
				"xhttpSettings": map[string]any{
					"scMinPostsIntervalMs": "0-0",
				},
			},
		})
	})

	t.Run("xhttp empty session table", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"sessionIDTable": "",
			"downloadSettings": map[string]any{
				"network": "xhttp",
				"xhttpSettings": map[string]any{
					"sessionIDTable": "",
				},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Empty%20Session%20Table"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"tls":     true,
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode":           "stream-up",
				"path":           "/xhttp",
				"host":           "cdn.example.com",
				"session-table":  "",
				"download-settings": map[string]any{
					"network":       "xhttp",
					"session-table": "",
				},
			},
		})
		checkAbsent(t, got, "_extra")
		checkAbsent(t, got, "_extra_unsupported")
	})

	t.Run("xhttp invalid session id fields", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"sessionIDTable":   123,
			"sessionIDLength":  "0-32",
			"downloadSettings": map[string]any{
				"network": "xhttp",
				"xhttpSettings": map[string]any{
					"sessionIDTable": false,
					"extra": map[string]any{
						"sessionIDLength": "0-0",
					},
				},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Invalid%20Session%20ID"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"tls":     true,
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode": "stream-up",
				"path": "/xhttp",
				"host": "cdn.example.com",
				"download-settings": map[string]any{
					"network": "xhttp",
				},
			},
		})
		checkAbsent(t, got, "xhttp-opts", "session-table")
		checkAbsent(t, got, "xhttp-opts", "session-length")
		checkAbsent(t, got, "xhttp-opts", "download-settings", "session-table")
		checkAbsent(t, got, "xhttp-opts", "download-settings", "session-length")
		checkDeepEqual(t, nested(t, got, "_extra_unsupported"), map[string]any{
			"sessionIDTable":   123,
			"sessionIDLength":  "0-32",
			"downloadSettings": map[string]any{
				"xhttpSettings": map[string]any{
					"sessionIDTable": false,
					"extra": map[string]any{
						"sessionIDLength": "0-0",
					},
				},
			},
		})
	})

	t.Run("xhttp extended extra", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"headers":            map[string]any{"X-Test": "demo"},
			"noGRPCHeader":       true,
			"xPaddingBytes":      "64-128",
			"xPaddingObfsMode":   true,
			"xPaddingKey":        "x_padding",
			"xPaddingHeader":     "Referer",
			"xPaddingPlacement":  "header",
			"xPaddingMethod":     "tokenish",
			"uplinkHTTPMethod":   "PUT",
			"sessionPlacement":   "query",
			"sessionKey":         "x_session_id",
			"seqPlacement":       "header",
			"seqKey":             "X-Seq",
			"uplinkDataPlacement": "header",
			"uplinkDataKey":      "X-Data",
			"uplinkChunkSize":    "64-128",
			"xmux": map[string]any{
				"maxConcurrency":  "16-32",
				"hKeepAlivePeriod": 15,
			},
			"noSSEHeader": true,
			"downloadSettings": map[string]any{
				"address":  "download.example.com",
				"port":     8443,
				"security": "tls",
				"tlsSettings": map[string]any{
					"serverName":    "download-sni.example.com",
					"fingerprint":   "chrome",
					"allowInsecure": true,
					"alpn":          []any{"h2"},
					"echConfigList": "ECHCONFIG",
				},
				"xhttpSettings": map[string]any{
					"path":              "/download",
					"host":              "download-host.example.com",
					"headers":           map[string]any{"X-Download": "1"},
					"noGRPCHeader":      true,
					"xPaddingBytes":     "16-32",
					"xPaddingObfsMode":  true,
					"xPaddingKey":       "x_padding_dl",
					"xPaddingHeader":    "Cookie",
					"xPaddingPlacement": "query",
					"xPaddingMethod":    "repeat-x",
					"uplinkHTTPMethod":  "PATCH",
					"sessionPlacement":  "header",
					"sessionKey":        "X-Session",
					"seqPlacement":      "query",
					"seqKey":            "x_seq",
					"uplinkDataPlacement": "cookie",
					"uplinkDataKey":     "x_data",
					"uplinkChunkSize":   48,
					"extra": map[string]any{
						"xmux": map[string]any{
							"maxConcurrency":  "8-16",
							"hKeepAlivePeriod": -1,
						},
					},
				},
				"sockopt": map[string]any{"mark": 255},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Extended%20Extra"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP Extended Extra",
			"tls":     true,
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode": "stream-up",
				"path": "/xhttp",
				"host": "cdn.example.com",
				"headers":             map[string]any{"X-Test": "demo"},
				"no-grpc-header":      true,
				"x-padding-bytes":     "64-128",
				"x-padding-obfs-mode": true,
				"x-padding-key":       "x_padding",
				"x-padding-header":    "Referer",
				"x-padding-placement": "header",
				"x-padding-method":    "tokenish",
				"uplink-http-method":  "PUT",
				"session-placement":   "query",
				"session-key":         "x_session_id",
				"seq-placement":       "header",
				"seq-key":             "X-Seq",
				"uplink-data-placement": "header",
				"uplink-data-key":     "X-Data",
				"uplink-chunk-size":   "64-128",
				"reuse-settings": map[string]any{
					"max-concurrency":   "16-32",
					"h-keep-alive-period": 15,
				},
				"download-settings": map[string]any{
					"server":               "download.example.com",
					"port":                 8443,
					"tls":                  true,
					"servername":           "download-sni.example.com",
					"client-fingerprint":   "chrome",
					"skip-cert-verify":     true,
					"alpn":                 []any{"h2"},
					"ech-opts": map[string]any{
						"enable": true,
						"config": "ECHCONFIG",
					},
					"path":                "/download",
					"host":                "download-host.example.com",
					"headers":             map[string]any{"X-Download": "1"},
					"no-grpc-header":      true,
					"x-padding-bytes":     "16-32",
					"x-padding-obfs-mode": true,
					"x-padding-key":       "x_padding_dl",
					"x-padding-header":    "Cookie",
					"x-padding-placement": "query",
					"x-padding-method":    "repeat-x",
					"uplink-http-method":  "PATCH",
					"session-placement":   "header",
					"session-key":         "X-Session",
					"seq-placement":       "query",
					"seq-key":             "x_seq",
					"uplink-data-placement": "cookie",
					"uplink-data-key":     "x_data",
					"uplink-chunk-size":   48,
					"reuse-settings": map[string]any{
						"max-concurrency":    "8-16",
						"h-keep-alive-period": -1,
					},
				},
			},
		})
		checkAbsent(t, got, "_extra")
		checkDeepEqual(t, nested(t, got, "_extra_unsupported"), map[string]any{
			"noSSEHeader": true,
			"downloadSettings": map[string]any{
				"sockopt": map[string]any{"mark": 255},
			},
		})
		checkAbsent(t, got, "xhttp-opts", "no-sse-header")
		checkAbsent(t, got, "xhttp-opts", "download-settings", "sockopt")
	})

	t.Run("xhttp typed extra", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"headers":        map[string]any{"X-Empty": "", "X-Number": 1},
			"noGRPCHeader":   false,
			"xPaddingBytes":  128,
			"xPaddingObfsMode": false,
			"xPaddingKey":    "",
			"xPaddingHeader": "",
			"xPaddingPlacement": "",
			"xPaddingMethod": "",
			"uplinkHTTPMethod": "",
			"sessionIDPlacement": "header",
			"sessionIDKey":   "X-Session-ID",
			"sessionPlacement": "query",
			"sessionKey":     "legacy-session",
			"seqPlacement":   "",
			"seqKey":         "",
			"uplinkDataPlacement": "",
			"uplinkDataKey":  "",
			"downloadSettings": map[string]any{
				"network": "xhttp",
				"xhttpSettings": map[string]any{
					"headers":            map[string]any{"X-Download-Empty": ""},
					"noGRPCHeader":       false,
					"xPaddingBytes":      32,
					"xPaddingObfsMode":   false,
					"sessionIDPlacement": "query",
					"sessionIDKey":       "x_session_id",
				},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Typed%20Extra"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP Typed Extra",
			"tls":     true,
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode":            "stream-up",
				"path":            "/xhttp",
				"host":            "cdn.example.com",
				"headers":         map[string]any{"X-Empty": ""},
				"x-padding-bytes": "128",
				"session-placement": "header",
				"session-key":     "X-Session-ID",
				"download-settings": map[string]any{
					"network":          "xhttp",
					"headers":          map[string]any{"X-Download-Empty": ""},
					"x-padding-bytes":  "32",
					"session-placement": "query",
					"session-key":      "x_session_id",
				},
			},
		})
		checkAbsent(t, got, "xhttp-opts", "no-grpc-header")
		checkAbsent(t, got, "xhttp-opts", "x-padding-obfs-mode")
		checkAbsent(t, got, "xhttp-opts", "x-padding-key")
		checkAbsent(t, got, "xhttp-opts", "x-padding-header")
		checkAbsent(t, got, "xhttp-opts", "x-padding-placement")
		checkAbsent(t, got, "xhttp-opts", "x-padding-method")
		checkAbsent(t, got, "xhttp-opts", "uplink-http-method")
		checkAbsent(t, got, "xhttp-opts", "seq-placement")
		checkAbsent(t, got, "xhttp-opts", "seq-key")
		checkAbsent(t, got, "xhttp-opts", "uplink-data-placement")
		checkAbsent(t, got, "xhttp-opts", "uplink-data-key")
		checkAbsent(t, got, "xhttp-opts", "download-settings", "no-grpc-header")
		checkAbsent(t, got, "xhttp-opts", "download-settings", "x-padding-obfs-mode")
		checkDeepEqual(t, nested(t, got, "_extra_unsupported"), map[string]any{
			"headers":        map[string]any{"X-Number": 1},
			"noGRPCHeader":   false,
			"xPaddingObfsMode": false,
			"downloadSettings": map[string]any{
				"xhttpSettings": map[string]any{
					"noGRPCHeader":     false,
					"xPaddingObfsMode": false,
				},
			},
		})
	})

	t.Run("xhttp nested ech dns", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"downloadSettings": map[string]any{
				"address":  "download.example.com",
				"port":     8443,
				"security": "tls",
				"tlsSettings": map[string]any{
					"echConfigList": "download-ech.example.com+https://1.1.1.1/dns-query",
					"echForceQuery": "half",
					"echSockopt":    map[string]any{"mark": 255},
				},
				"xhttpSettings": map[string]any{
					"path": "/download",
				},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Nested%20ECH%20DNS"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"download-settings": map[string]any{
					"server": "download.example.com",
					"port":   8443,
					"tls":    true,
					"ech-opts": map[string]any{
						"enable":            true,
						"_dns":              "https://1.1.1.1/dns-query",
						"query-server-name": "download-ech.example.com",
						"_force-query":      "half",
						"_sockopt":          map[string]any{"mark": 255},
					},
					"path": "/download",
				},
			},
		})
		checkAbsent(t, got, "_extra_unsupported")
	})

	t.Run("xhttp xmux canonical", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"xmux": map[string]any{
				"maxConnections":  "+0008",
				"maxConcurrency":  "0008-0016",
				"hKeepAlivePeriod": "9007199254740993",
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20XMUX%20Canonical"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode": "stream-up",
				"path": "/xhttp",
				"host": "cdn.example.com",
				"reuse-settings": map[string]any{
					"max-connections": "8",
					"max-concurrency": "8-16",
				},
			},
		})
		checkAbsent(t, got, "xhttp-opts", "reuse-settings", "h-keep-alive-period")
		checkDeepEqual(t, nested(t, got, "_extra_unsupported"), map[string]any{
			"xmux": map[string]any{"hKeepAlivePeriod": "9007199254740993"},
		})
	})

	t.Run("xhttp string download port", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"downloadSettings": map[string]any{
				"address":  "download.example.com",
				"port":     "8443",
				"security": "tls",
				"xhttpSettings": map[string]any{
					"path": "/download",
				},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20String%20Download%20Port"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode": "stream-up",
				"path": "/xhttp",
				"host": "cdn.example.com",
				"download-settings": map[string]any{
					"server": "download.example.com",
					"port":   8443,
					"tls":    true,
					"path":   "/download",
				},
			},
		})
		checkAbsent(t, got, "_extra_unsupported")
	})

	t.Run("xhttp malformed ranges", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"xPaddingBytes":   "fast",
			"uplinkChunkSize": "fast",
			"downloadSettings": map[string]any{
				"address":  "download.example.com",
				"port":     8443,
				"security": "tls",
				"xhttpSettings": map[string]any{
					"path":            "/download",
					"xPaddingBytes":   "faster",
					"uplinkChunkSize": "faster",
				},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Malformed%20Uplink%20Chunk"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode": "stream-up",
				"path": "/xhttp",
				"host": "cdn.example.com",
				"download-settings": map[string]any{
					"server": "download.example.com",
					"port":   8443,
					"tls":    true,
					"path":   "/download",
				},
			},
		})
		checkAbsent(t, got, "xhttp-opts", "x-padding-bytes")
		checkAbsent(t, got, "xhttp-opts", "uplink-chunk-size")
		checkAbsent(t, got, "xhttp-opts", "download-settings", "x-padding-bytes")
		checkAbsent(t, got, "xhttp-opts", "download-settings", "uplink-chunk-size")
		checkDeepEqual(t, nested(t, got, "_extra_unsupported"), map[string]any{
			"xPaddingBytes":   "fast",
			"uplinkChunkSize": "fast",
			"downloadSettings": map[string]any{
				"xhttpSettings": map[string]any{
					"xPaddingBytes":   "faster",
					"uplinkChunkSize": "faster",
				},
			},
		})
	})

	t.Run("xhttp mixed alpn", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"downloadSettings": map[string]any{
				"address":  "download.example.com",
				"port":     8443,
				"security": "tls",
				"tlsSettings": map[string]any{
					"alpn": []any{"h2", map[string]any{"foo": 1}},
				},
				"xhttpSettings": map[string]any{
					"path": "/download",
				},
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Mixed%20ALPN"
		got := parseOneProxyMap(t, input)
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode": "stream-up",
				"path": "/xhttp",
				"host": "cdn.example.com",
				"download-settings": map[string]any{
					"server": "download.example.com",
					"port":   8443,
					"tls":    true,
					"path":   "/download",
				},
			},
		})
		checkAbsent(t, got, "xhttp-opts", "download-settings", "alpn")
		checkDeepEqual(t, nested(t, got, "_extra_unsupported"), map[string]any{
			"downloadSettings": map[string]any{
				"tlsSettings": map[string]any{
					"alpn": []any{"h2", map[string]any{"foo": 1}},
				},
			},
		})
	})

	t.Run("xhttp scMaxEachPostBytes range", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"noGRPCHeader":       true,
			"xPaddingBytes":      "64-128",
			"scMaxEachPostBytes": "500000 - 1000000",
			"xmux": map[string]any{
				"maxConnections":   0,
				"maxConcurrency":   "16-32",
				"cMaxReuseTimes":   "64-128",
				"hMaxRequestTimes": "600-900",
				"hMaxReusableSecs": "1800-3000",
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Range"
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP Range",
			"tls":     true,
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode":                   "stream-up",
				"path":                   "/xhttp",
				"host":                   "cdn.example.com",
				"no-grpc-header":         true,
				"x-padding-bytes":        "64-128",
				"sc-max-each-post-bytes": "500000-1000000",
				"reuse-settings":         scMinReuseSettings,
			},
		})
	})

	t.Run("xhttp scMaxEachPostBytes string", func(t *testing.T) {
		extra := mustJSON(map[string]any{
			"noGRPCHeader":       true,
			"xPaddingBytes":      "64-128",
			"scMaxEachPostBytes": "1000000",
			"xmux": map[string]any{
				"maxConnections":   0,
				"maxConcurrency":   "16-32",
				"cMaxReuseTimes":   "64-128",
				"hMaxRequestTimes": "600-900",
				"hMaxReusableSecs": "1800-3000",
			},
		})
		input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20String"
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "VLESS XHTTP String",
			"tls":     true,
			"network": "xhttp",
			"xhttp-opts": map[string]any{
				"mode":                   "stream-up",
				"path":                   "/xhttp",
				"host":                   "cdn.example.com",
				"no-grpc-header":         true,
				"x-padding-bytes":        "64-128",
				"sc-max-each-post-bytes": 1000000,
				"reuse-settings":         scMinReuseSettings,
			},
		})
	})

	t.Run("xhttp invalid scMaxEachPostBytes values", func(t *testing.T) {
		invalidValues := []any{"1.5", 1.5, "0", 0, "0-1000000", "+0-+1000000", "000-1000000", "fast", "10-1", "9007199254740993", "1-9007199254740993"}
		for _, value := range invalidValues {
			extra := mustJSON(map[string]any{
				"noGRPCHeader":       true,
				"xPaddingBytes":      "64-128",
				"scMaxEachPostBytes": value,
				"xmux": map[string]any{
					"maxConnections":   0,
					"maxConcurrency":   "16-32",
					"cMaxReuseTimes":   "64-128",
					"hMaxRequestTimes": "600-900",
					"hMaxReusableSecs": "1800-3000",
				},
			})
			input := "vless://" + vlessTestUUID + "@vless-xhttp.example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fxhttp&mode=stream-up&extra=" + uqe(extra) + "#VLESS%20XHTTP%20Invalid"
			got := parseOneProxyMap(t, input)
			checkSubset(t, input, map[string]any{
				"type":    "vless",
				"tls":     true,
				"network": "xhttp",
				"xhttp-opts": map[string]any{
					"mode":            "stream-up",
					"path":            "/xhttp",
					"host":            "cdn.example.com",
					"no-grpc-header":  true,
					"x-padding-bytes": "64-128",
					"reuse-settings":  scMinReuseSettings,
				},
			})
			checkAbsent(t, got, "xhttp-opts", "sc-max-each-post-bytes")
			checkDeepEqual(t, nested(t, got, "_extra_unsupported"), map[string]any{
				"scMaxEachPostBytes": value,
			})
		}
	})

	t.Run("Shadowrocket vless", func(t *testing.T) {
		base := b64("none:" + vlessTestUUID + "@shadowrocket-vless.example.com:443")
		input := "vless://" + base + "?remarks=Shadowrocket%20VLESS&tls=1&obfs=websocket&obfsParam=ws.shadow.example.com&path=%2Fshadow&xtls=2"
		checkSubset(t, input, map[string]any{
			"type":    "vless",
			"name":    "Shadowrocket VLESS",
			"server":  "shadowrocket-vless.example.com",
			"port":    443,
			"uuid":    vlessTestUUID,
			"tls":     true,
			"flow":    "xtls-rprx-vision",
			"network": "ws",
			"ws-opts": map[string]any{
				"path":    "/shadow",
				"headers": map[string]any{"Host": "ws.shadow.example.com"},
			},
		})
	})
}

// TestVLESSRejects mirrors the rejection cases from the spec.
func TestVLESSRejects(t *testing.T) {
	checkRejected(t, "vless://"+vlessTestUUID+"@vless-ws.example.com:443?type=ws&security=tls&host=cdn.example.com&path=%2Fws&ed=2048foo#VLESS%20WS%20Malformed%20ED")
	checkRejected(t, "vless://"+vlessTestUUID+"@vless-ws.example.com:443?type=ws&security=tls&host=cdn.example.com&path=%2Fws&ed=999999999999999999999#VLESS%20WS%20Too%20Large")
}
