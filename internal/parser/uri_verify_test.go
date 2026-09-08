package parser

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"
)

func b64(s string) string  { return base64.StdEncoding.EncodeToString([]byte(s)) }
func b64URL(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
func qe(s string) string { return url.QueryEscape(s) }

func checkSubset(t *testing.T, input string, want map[string]any) {
	t.Helper()
	proxies := ParseText(input)
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	gotB, _ := json.Marshal(proxies[0].Fields())
	var got map[string]any
	if err := json.Unmarshal(gotB, &got); err != nil {
		t.Fatal(err)
	}
	for k, v := range want {
		gv, ok := got[k]
		if !ok {
			t.Errorf("missing key %q", k)
			continue
		}
		if !deepSubset(gv, v) {
			gj, _ := json.Marshal(gv)
			wj, _ := json.Marshal(v)
			t.Errorf("key %q = %s, want %s", k, gj, wj)
		}
	}
}

// deepSubset reports whether got satisfies want with Sub-Store's
// expectSubset semantics: every key of a want map must exist in got with a
// deep-subset value; arrays require an exact index-wise deep match.
func deepSubset(got, want any) bool {
	wm, wok := want.(map[string]any)
	if wok {
		gm, gok := got.(map[string]any)
		if !gok {
			return false
		}
		for k, wv := range wm {
			gv, ok := gm[k]
			if !ok {
				return false
			}
			if !deepSubset(gv, wv) {
				return false
			}
		}
		return true
	}
	wa, wok := want.([]any)
	if wok {
		ga, gok := got.([]any)
		if !gok || len(ga) != len(wa) {
			return false
		}
		for i := range wa {
			if !deepSubset(ga[i], wa[i]) {
				return false
			}
		}
		return true
	}
	gj, _ := json.Marshal(got)
	wj, _ := json.Marshal(want)
	return string(gj) == string(wj)
}

// TestURIGeneric mirrors the generic-URI cases from Sub-Store's uri.spec.js.
func TestURIGeneric(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  map[string]any
	}{
		{
			name:  "https implicit default port",
			input: `https://alice:pa%24%24@https.example.com#HTTPS%20Default`,
			want: map[string]any{
				"type": "http", "name": "HTTPS Default",
				"server": "https.example.com", "port": 443,
				"tls": true, "username": "alice", "password": "pa$$",
			},
		},
		{
			name:  "https full fragment after first hash",
			input: `https://alice:pa%24%24@https.example.com#HTTPS%20Outer#Remark`,
			want: map[string]any{
				"type": "http", "name": "HTTPS Outer#Remark",
				"server": "https.example.com", "port": 443,
				"tls": true, "username": "alice", "password": "pa$$",
			},
		},
		{
			name:  "legacy socks base64 auth",
			input: `socks://` + qe(b64("bob:secret")) + `@socks.example.com:1080#SOCKS`,
			want: map[string]any{
				"type": "socks5", "name": "SOCKS",
				"server": "socks.example.com", "port": 1080,
				"username": "bob", "password": "secret",
			},
		},
		{
			name:  "socks full fragment after first hash",
			input: `socks://` + qe(b64("bob:secret")) + `@socks.example.com:1080#SOCKS#Remark`,
			want: map[string]any{
				"type": "socks5", "name": "SOCKS#Remark",
				"server": "socks.example.com", "port": 1080,
				"username": "bob", "password": "secret",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkSubset(t, tc.input, tc.want)
		})
	}
}

// TestURIShadowsocks mirrors the shadowsocks-family cases from uri.spec.js.
func TestURIShadowsocks(t *testing.T) {
	userInfo := qe(b64("aes-128-gcm:secret"))
	cases := []struct {
		name  string
		input string
		want  map[string]any
	}{
		{
			name: "sip002 obfs and transport flags",
			input: `ss://` + userInfo + `@ss.example.com:8388/?plugin=` +
				qe("obfs-local;obfs=http;obfs-host=obfs.example.com") +
				`&uot=1&tfo=1#SS Obfs`,
			want: map[string]any{
				"type": "ss", "name": "SS Obfs",
				"server": "ss.example.com", "port": 8388,
				"cipher": "aes-128-gcm", "password": "secret",
				"plugin": "obfs",
				"plugin-opts": map[string]any{"mode": "http", "host": "obfs.example.com"},
				"udp-over-tcp": true, "tfo": true,
			},
		},
		{
			name:  "sip002 base64url userinfo",
			input: `ss://` + b64URL("aes-128-gcm:aa>") + `@ss.example.com:8388#SS Base64URL`,
			want: map[string]any{
				"type": "ss", "name": "SS Base64URL",
				"server": "ss.example.com", "port": 8388,
				"cipher": "aes-128-gcm", "password": "aa>",
			},
		},
		{
			name:  "sip002 plain percent-encoded credentials",
			input: `ss://aes-128-gcm:` + qe("sec:ret@/plus+") + `@ss.example.com:8388#SS Plain`,
			want: map[string]any{
				"type": "ss", "name": "SS Plain",
				"server": "ss.example.com", "port": 8388,
				"cipher": "aes-128-gcm", "password": "sec:ret@/plus+",
			},
		},
		{
			name:  "sip002 aead-2022 plain userinfo",
			input: `ss://2022-blake3-aes-256-gcm:` + qe("YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI=") + `@192.168.100.1:8888#SS 2022`,
			want: map[string]any{
				"type": "ss", "name": "SS 2022",
				"server": "192.168.100.1", "port": 8888,
				"cipher": "2022-blake3-aes-256-gcm",
				"password": "YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI=",
			},
		},
		{
			name: "legacy v2ray-plugin",
			input: `ss://` + b64("chacha20-ietf-poly1305:legacy-pass@legacy.example.com:443") +
				`?plugin=` + qe("v2ray-plugin;tls;host=cdn.example.com;path=/socket") +
				`#SS V2ray`,
			want: map[string]any{
				"type": "ss", "name": "SS V2ray",
				"server": "legacy.example.com", "port": 443,
				"cipher": "chacha20-ietf-poly1305", "password": "legacy-pass",
				"plugin": "v2ray-plugin",
				"plugin-opts": map[string]any{
					"mode": "websocket", "host": "cdn.example.com",
					"path": "/socket", "tls": true,
				},
			},
		},
		{
			name:  "full ss fragment after first hash",
			input: `ss://` + userInfo + `@ss.example.com:8388#SS Outer#Remark`,
			want: map[string]any{
				"type": "ss", "name": "SS Outer#Remark",
				"server": "ss.example.com", "port": 8388,
				"cipher": "aes-128-gcm", "password": "secret",
			},
		},
		{
			name: "v2ray-plugin flags sni skip-cert-verify mux",
			input: `ss://` + userInfo + `@ss.example.com:443/?plugin=` +
				qe("v2ray-plugin;obfs=websocket;host=cdn.example.com;path=/socket;tls;sni=sni.example.com;skip-cert-verify=1;mux=1") +
				`#SS V2ray Flags`,
			want: map[string]any{
				"type": "ss", "name": "SS V2ray Flags",
				"server": "ss.example.com", "port": 443,
				"cipher": "aes-128-gcm", "password": "secret",
				"plugin": "v2ray-plugin",
				"plugin-opts": map[string]any{
					"mode": "websocket", "host": "cdn.example.com",
					"path": "/socket", "tls": true, "sni": "sni.example.com",
					"skip-cert-verify": true, "mux": 1,
				},
			},
		},
		{
			name: "v2ray-plugin escaped equals in path",
			input: `ss://` + userInfo + `@ss.example.com:8080?plugin=` +
				qe(`v2ray-plugin;mode=websocket;host=cdn.example.com;path=/?enc\=aes-128-gcm`) +
				`#SS Escaped Path`,
			want: map[string]any{
				"type": "ss", "name": "SS Escaped Path",
				"server": "ss.example.com", "port": 8080,
				"cipher": "aes-128-gcm", "password": "secret",
				"plugin": "v2ray-plugin",
				"plugin-opts": map[string]any{
					"mode": "websocket", "host": "cdn.example.com",
					"path": "/?enc=aes-128-gcm",
				},
			},
		},
		{
			name: "ws early data extraction",
			input: `ss://` + userInfo + `@ss-ws.example.com:443?type=ws&path=` +
				qe("/ws?a=1&ed=2048&b=2") + `&host=cdn.example.com&security=tls#SS WS Early`,
			want: map[string]any{
				"type": "ss", "name": "SS WS Early",
				"server": "ss-ws.example.com", "port": 443,
				"cipher": "aes-128-gcm", "password": "secret",
				"tls": true, "network": "ws",
				"ws-opts": map[string]any{
					"path": "/ws?a=1&b=2",
					"headers": map[string]any{"Host": "cdn.example.com"},
					"max-early-data": 2048,
					"early-data-header-name": "Sec-WebSocket-Protocol",
				},
			},
		},
		{
			name: "httpupgrade no double decode",
			input: `ss://` + userInfo + `@ss-upgrade.example.com:443?type=httpupgrade&path=` +
				qe("/upgrade?redirect=%26ed%3D2048") + `&host=cdn.example.com&security=tls#SS Upgrade Escaped`,
			want: map[string]any{
				"type": "ss", "name": "SS Upgrade Escaped",
				"server": "ss-upgrade.example.com", "port": 443,
				"network": "ws",
				"ws-opts": map[string]any{
					"path": "/upgrade?redirect=%26ed%3D2048",
					"headers": map[string]any{"Host": "cdn.example.com"},
					"v2ray-http-upgrade": true,
				},
			},
		},
		{
			name: "shadow-tls compatibility payload",
			input: `ss://` + b64("aes-256-gcm:shadow-pass") + `@ss.example.com:8388?shadow-tls=` +
				b64(`{"host":"mask.example.com","password":"tls-pass","version":"3","address":"1.1.1.1","port":"9443"}`) +
				`#SS ShadowTLS`,
			want: map[string]any{
				"type": "ss", "name": "SS ShadowTLS",
				"server": "1.1.1.1", "port": 9443,
				"cipher": "aes-256-gcm", "password": "shadow-pass",
				"plugin": "shadow-tls",
				"plugin-opts": map[string]any{
					"host": "mask.example.com", "password": "tls-pass", "version": 3,
				},
			},
		},
		{
			name: "shadowrocket gost-plugin",
			input: `ss://` + b64("2022-blake3-aes-128-gcm:YTE1ZWU4ZTEyZjc3YmEzZA==:Y2JhZTU3ODYtZjg3MC00NA==@openai.com:11") +
				`?gost=` + b64(`{"path":"\/ws","port":"11","host":"a","route":"ws","address":"a"}`) +
				// fragment decoding mirrors decodeURIComponent (no "+"-to-space),
				// so the space is sent as %20 instead of QueryEscape's "+"
				`#` + percentEncode("🇯🇵 日本-A77ACD92"),
			want: map[string]any{
				"type": "ss", "name": "🇯🇵 日本-A77ACD92",
				"server": "a", "port": 11,
				"cipher": "2022-blake3-aes-128-gcm",
				"password": "YTE1ZWU4ZTEyZjc3YmEzZA==:Y2JhZTU3ODYtZjg3MC00NA==",
				"plugin": "gost-plugin",
				"plugin-opts": map[string]any{
					"mode": "websocket", "host": "a", "path": "/ws",
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkSubset(t, tc.input, tc.want)
		})
	}

	// SSR URIs with protocol and obfs parameters
	ssrPayload := b64("ssr.example.com:8899:origin:aes-256-cfb:http_simple:" +
		b64("ssr-secret") + "/?remarks=" + b64("SSR Node") +
		"&obfsparam=" + b64("cdn.example.com") +
		"&protoparam=" + b64("user:pass"))
	checkSubset(t, `ssr://`+ssrPayload, map[string]any{
		"type": "ssr", "name": "SSR Node",
		"server": "ssr.example.com", "port": 8899,
		"protocol": "origin", "cipher": "aes-256-cfb", "obfs": "http_simple",
		"password": "ssr-secret",
		"protocol-param": "user:pass", "obfs-param": "cdn.example.com",
	})
}

// TestURIAnyTLSHysteria mirrors the modern URI cases from uri.spec.js.
func TestURIAnyTLSHysteria(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  map[string]any
	}{
		{
			name:  "anytls drops tcp transport metadata",
			input: `anytls://top-secret@anytls.example.com:443?type=tcp&alpn=h2,http/1.1&insecure=1&udp=1#AnyTLS`,
			want: map[string]any{
				"type": "anytls", "name": "AnyTLS",
				"server": "anytls.example.com", "port": 443,
				"password": "top-secret", "tls": true,
				"sni": "anytls.example.com",
				"alpn": []any{"h2", "http/1.1"},
				"udp": true, "skip-cert-verify": true,
			},
		},
		{
			name:  "hysteria fallback sni and throughput",
			input: `hy://hysteria.example.com:8443?auth=token&peer=sni.example.com&alpn=h3,h2&mport=2000,3000&obfsParam=mask&upmbps=10&downmbps=20&insecure=1#Hysteria`,
			want: map[string]any{
				"type": "hysteria", "name": "Hysteria",
				"server": "hysteria.example.com", "port": 8443,
				"protocol": "udp", "auth-str": "token",
				"sni": "sni.example.com", "alpn": []any{"h3", "h2"},
				"ports": "2000,3000", "obfs": "mask",
				"up": "10", "down": "20", "skip-cert-verify": true,
			},
		},
		{
			name:  "hysteria2 port hopping range",
			input: `hy2://hy2-secret@hy2.example.com:8443-8445?peer=peer.example.com&obfs=salamander&obfs-password=mask&insecure=1&fastopen=1&pinSHA256=fingerprint&hop-interval=30&keepalive=15#Hy2 Range`,
			want: map[string]any{
				"type": "hysteria2", "name": "Hy2 Range",
				"server": "hy2.example.com", "ports": "8443-8445",
				"password": "hy2-secret", "sni": "peer.example.com",
				"obfs": "salamander", "obfs-password": "mask",
				"skip-cert-verify": true, "tfo": true,
				"tls-fingerprint": "fingerprint",
				"hop-interval": 30, "keepalive": 15,
			},
		},
		{
			name:  "hysteria2 hop-interval range split",
			input: `hy2://hy2-secret@hy2.example.com:443?hop-interval=15-30#Hy2 Hop Range`,
			want: map[string]any{
				"type": "hysteria2", "name": "Hy2 Hop Range",
				"server": "hy2.example.com", "port": 443,
				"password": "hy2-secret",
				"hop-interval": 15, "hop-interval-max": 30,
			},
		},
		{
			name:  "hysteria2 invalid hop-interval dropped",
			input: `hy2://hy2-secret@hy2.example.com:443?hop-interval=30-15#Hy2 Invalid Hop`,
			want: map[string]any{
				"type": "hysteria2", "name": "Hy2 Invalid Hop",
				"server": "hy2.example.com", "port": 443,
				"password": "hy2-secret",
			},
		},
		{
			name:  "hysteria2 mport override",
			input: `hy2://hy2-secret@hy2.example.com:443?mport=9000,9002-9004#Hy2 Mport`,
			want: map[string]any{
				"type": "hysteria2", "name": "Hy2 Mport",
				"server": "hy2.example.com", "port": 443,
				"ports": "9000,9002-9004", "password": "hy2-secret",
			},
		},
		{
			name:  "hysteria2 throughput",
			input: `hy2://hy2-secret@hy2.example.com:443?upmbps=50&downmbps=100#Hy2 Throughput`,
			want: map[string]any{
				"type": "hysteria2", "name": "Hy2 Throughput",
				"server": "hy2.example.com", "port": 443,
				"password": "hy2-secret", "up": "50", "down": "100",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkSubset(t, tc.input, tc.want)
		})
	}

	// hysteria2 ech fields
	proxies := ParseText(`hy2://hy2-secret@hy2.example.com:443?ech=ECHCONFIG#Hy2 ECH`)
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	ech, _ := json.Marshal(proxies[0].Get("ech-opts"))
	if string(ech) != `{"config":"ECHCONFIG","enable":true}` {
		t.Errorf("ech-opts = %s", ech)
	}

	// hysteria2 salamander obfs without obfs-password is rejected
	if proxies := ParseText(`hy2://hy2-secret@hy2.example.com:443?obfs=salamander#Hy2 Missing Password`); len(proxies) != 0 {
		t.Errorf("expected 0 proxies, got %d", len(proxies))
	}

	// hy2 port range selects a port within the range
	proxies = ParseText(`hy2://hy2-secret@hy2.example.com:8443-8445?obfs=salamander&obfs-password=mask#Hy2 Port`)
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	if p := proxies[0].GetInt("port"); p < 8443 || p > 8445 {
		t.Errorf("port = %d, want within 8443..8445", p)
	}
}

// TestURITUICWireGuardTrojan mirrors the remaining modern URI cases.
func TestURITUICWireGuardTrojan(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  map[string]any
	}{
		{
			name:  "tuic colon password and booleans",
			input: `tuic://11111111-1111-4111-8111-111111111111:pass%3Aword@tuic.example.com?alpn=h3,hq-29&allow-insecure=1&fast-open=1&disable-sni=1&reduce-rtt=1&congestion-control=bbr#TUIC`,
			want: map[string]any{
				"type": "tuic", "name": "TUIC",
				"server": "tuic.example.com", "port": 443,
				"uuid": "11111111-1111-4111-8111-111111111111",
				"password": "pass:word", "alpn": []any{"h3", "hq-29"},
				"skip-cert-verify": true, "tfo": true,
				"disable-sni": true, "reduce-rtt": true,
				"congestion-controller": "bbr",
			},
		},
		{
			name:  "wireguard address lists and reserved bytes",
			input: `wg://private-key@wg.example.com?publickey=public-key&privatekey=override-key&address=10.0.0.2/32,[fd00::2]/128&reserved=1,2,3&mtu=1280&udp=0#WG`,
			want: map[string]any{
				"type": "wireguard", "name": "WG",
				"server": "wg.example.com", "port": 51820,
				"private-key": "override-key", "public-key": "public-key",
				"ip": "10.0.0.2", "ipv6": "fd00::2",
				"ip-cidr": 32, "ipv6-cidr": 128,
				"reserved": []any{1, 2, 3}, "mtu": 1280, "udp": false,
			},
		},
		{
			name:  "wireguard default cidr suffixes",
			input: `wg://private-key@wg.example.com?publickey=public-key&address=10.0.0.2,[fd00::2]#WG Default CIDR`,
			want: map[string]any{
				"type": "wireguard", "name": "WG Default CIDR",
				"ip": "10.0.0.2", "ipv6": "fd00::2",
				"ip-cidr": 32, "ipv6-cidr": 128,
			},
		},
		{
			name: "wireguard camelCase keys with base64 padding",
			input: `wg://120.233.41.77:19368?publicKey=N+K9fXobvy0vy3VFbn8a7tPRgUNcQbGRwjlyOMx4WHc=&privateKey=QJjrFqqqpbIqfI5qhbYWrPXhaBFmFq71jCj8mMaQE04=&ip=10.0.20.45/16,fd10:10:10:0:10:0:20:45/64&mtu=1420&udp=1#` + qe("HK-大带宽4"),
			want: map[string]any{
				"type": "wireguard", "name": "HK-大带宽4",
				"server": "120.233.41.77", "port": 19368,
				"public-key": "N+K9fXobvy0vy3VFbn8a7tPRgUNcQbGRwjlyOMx4WHc=",
				"private-key": "QJjrFqqqpbIqfI5qhbYWrPXhaBFmFq71jCj8mMaQE04=",
				"ip": "10.0.20.45", "ip-cidr": 16,
				"ipv6": "fd10:10:10:0:10:0:20:45", "ipv6-cidr": 64,
				"mtu": 1420, "udp": true,
			},
		},
		{
			name:  "trojan websocket early data",
			input: `trojan://trojan-pass@trojan-ws.example.com?type=ws&host=ws.example.com&path=` + qe("/ws?ed=1024&a=1&b=2") + `#Trojan WS`,
			want: map[string]any{
				"type": "trojan", "name": "Trojan WS",
				"server": "trojan-ws.example.com", "port": 443,
				"password": "trojan-pass", "network": "ws",
				"ws-opts": map[string]any{
					"path": "/ws?a=1&b=2",
					"headers": map[string]any{"Host": "ws.example.com"},
					"max-early-data": 1024,
					"early-data-header-name": "Sec-WebSocket-Protocol",
				},
			},
		},
		{
			name:  "trojan ipv6 valueless flags",
			input: `trojan://trojan-pass@[2001:db8::1]:443?udp&tfo&ws&wspath=%2Fws#Trojan IPv6`,
			want: map[string]any{
				"type": "trojan", "name": "Trojan IPv6",
				"server": "2001:db8::1", "port": 443,
				"network": "ws", "udp": true, "tfo": true,
				"ws-opts": map[string]any{"path": "/ws"},
			},
		},
		{
			name:  "trojan bare ipv6",
			input: `trojan://trojan-pass@2001:db8::1:443#Trojan Bare IPv6`,
			want: map[string]any{
				"server": "2001:db8::1", "port": 443,
			},
		},
		{
			name:  "trojan no double decode of path query",
			input: `trojan://trojan-pass@trojan-ws.example.com?type=ws&host=ws.example.com&path=` + qe("/ws?redirect=%26ed%3D2048") + `#Trojan WS Escaped`,
			want: map[string]any{
				"type": "trojan", "name": "Trojan WS Escaped",
				"network": "ws",
				"ws-opts": map[string]any{
					"path": "/ws?redirect=%26ed%3D2048",
					"headers": map[string]any{"Host": "ws.example.com"},
				},
			},
		},
		{
			name:  "trojan pcs as tls fingerprint",
			input: `trojan://trojan-pass@trojan-ws.example.com?type=ws&host=ws.example.com&path=%2Fws&pcs=fingerprint#Trojan WS PCS`,
			want: map[string]any{
				"type": "trojan", "name": "Trojan WS PCS",
				"server": "trojan-ws.example.com", "port": 443,
				"password": "trojan-pass", "tls-fingerprint": "fingerprint",
				"network": "ws",
				"ws-opts": map[string]any{
					"path": "/ws",
					"headers": map[string]any{"Host": "ws.example.com"},
				},
			},
		},
		{
			name:  "trojan vcn sidecar fields",
			input: `trojan://trojan-pass@trojan.example.com:443?vcn=first.example.com%2Csecond.example.com#Trojan VCN`,
			want: map[string]any{
				"name-cert-verify": "first.example.com",
				"_vcn": []any{"first.example.com", "second.example.com"},
			},
		},
		{
			name:  "trojan grpc reality metadata",
			input: `trojan://trojan-pass@trojan-grpc.example.com?type=grpc&serviceName=grpc-service&authority=grpc.example.com&mode=multi&security=reality&pbk=pubkey==&sid=08&spx=%2Fspider&extra=` + qe(`{"x":1}`) + `&udp=1&tfo=1#Trojan Reality`,
			want: map[string]any{
				"type": "trojan", "name": "Trojan Reality",
				"server": "trojan-grpc.example.com", "port": 443,
				"password": "trojan-pass", "network": "grpc",
				"udp": true, "tfo": true,
				"grpc-opts": map[string]any{
					"grpc-service-name": "grpc-service",
					"_grpc-type": "multi",
					"_grpc-authority": "grpc.example.com",
				},
				"reality-opts": map[string]any{
					"public-key": "pubkey==", "short-id": "08",
					"_spider-x": "/spider",
				},
				"_mode": "multi", "_extra": `{"x":1}`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkSubset(t, tc.input, tc.want)
		})
	}

	// rejected trojan lines
	rejections := []string{
		`trojan://trojan-pass@trojan.example.com:0#Invalid Port`,
		`trojan://trojan-pass@trojan.example.com:65536#Invalid Port`,
		`trojan://trojan-pass@host:123:443#Invalid Host`,
		`trojan://trojan-pass@trojan.example.com:443?type=__proto__.ws&path=%2Fx#Prototype Pollution`,
		`trojan://trojan-pass@trojan.example.com:443?type=constructor.prototype.ws&path=%2Fx#Prototype Pollution`,
	}
	for _, input := range rejections {
		if proxies := ParseText(input); len(proxies) != 0 {
			t.Errorf("expected 0 proxies for %q, got %d", input, len(proxies))
		}
	}
}
