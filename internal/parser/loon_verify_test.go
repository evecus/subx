package parser

import (
	"encoding/json"
	"testing"
)

// TestLoonSubStoreCases mirrors the Loon raw-input cases from Sub-Store's
// v2ray-and-platforms.spec.js (expectSubset semantics: expected keys must be
// present in the parsed proxy with equal values; extra keys are allowed).
func TestLoonSubStoreCases(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "shadowsocks obfs tls",
			input: `Loon SS=shadowsocks,loon-ss.example.com,8388,aes-128-gcm,"secret",obfs-name=tls,obfs-host=obfs.example.com,obfs-uri=/tls,udp=true,fast-open=true`,
			want:  `{"type":"ss","name":"Loon SS","server":"loon-ss.example.com","port":8388,"cipher":"aes-128-gcm","password":"secret","udp":true,"tfo":true,"plugin":"obfs","plugin-opts":{"mode":"tls","host":"obfs.example.com","path":"/tls"}}`,
		},
		{
			name:  "shadowsocks 2022 obfs http",
			input: `Loon SS2022=shadowsocks,loon-ss2022.example.com,8388,2022-blake3-aes-128-gcm,"server-key:user-key",obfs-name=http,obfs-host=obfs.example.com,obfs-uri=/`,
			want:  `{"type":"ss","name":"Loon SS2022","server":"loon-ss2022.example.com","port":8388,"cipher":"2022-blake3-aes-128-gcm","password":"server-key:user-key","plugin":"obfs","plugin-opts":{"mode":"http","host":"obfs.example.com","path":"/"}}`,
		},
		{
			name:  "shadowsocks shadow-tls alpn",
			input: `Loon ShadowTLS ALPN=shadowsocks,loon-st.example.com,8388,aes-128-gcm,"secret",shadow-tls-password=shadow-pass,shadow-tls-sni=mask.example.com,shadow-tls-version=3,alpn="h2,http/1.1"`,
			want:  `{"type":"ss","name":"Loon ShadowTLS ALPN","server":"loon-st.example.com","port":8388,"cipher":"aes-128-gcm","password":"secret","plugin":"shadow-tls","plugin-opts":{"host":"mask.example.com","password":"shadow-pass","version":3,"alpn":["h2","http/1.1"]}}`,
		},
		{
			name:  "shadowsocks shadow-tls tls-profile",
			input: `Loon ShadowTLS TLS Profile=shadowsocks,loon-st.example.com,8388,aes-128-gcm,"secret",shadow-tls-password=shadow-pass,shadow-tls-sni=mask.example.com,shadow-tls-version=3,tls-profile=ios26`,
			want:  `{"type":"ss","name":"Loon ShadowTLS TLS Profile","server":"loon-st.example.com","port":8388,"cipher":"aes-128-gcm","password":"secret","plugin":"shadow-tls","plugin-opts":{"host":"mask.example.com","password":"shadow-pass","version":3},"_loon_tls_profile":"ios26","client-fingerprint":"ios"}`,
		},
		{
			name:  "shadowsocksr",
			input: `Loon SSR=shadowsocksr,loon-ssr.example.com,8389,aes-256-cfb,"secret",protocol=auth_chain_b,protocol-param=device-id,obfs=tls1.2_ticket_fastauth,obfs-param=cdn.example.com`,
			want:  `{"type":"ssr","name":"Loon SSR","server":"loon-ssr.example.com","port":8389,"cipher":"aes-256-cfb","password":"secret","protocol":"auth_chain_b","protocol-param":"device-id","obfs":"tls1.2_ticket_fastauth","obfs-param":"cdn.example.com"}`,
		},
		{
			name:  "vmess http tls",
			input: `Loon VMess=vmess,loon-vmess.example.com,443,auto,"11111111-1111-1111-1111-111111111111",transport=http,host=cdn.example.com,path=/http,over-tls=true,tls-name=sni.example.com,skip-cert-verify=true,tls-profile=chrome,alpn="http/1.1,h2,h3",alterId=0`,
			want:  `{"type":"vmess","name":"Loon VMess","server":"loon-vmess.example.com","port":443,"cipher":"auto","uuid":"11111111-1111-1111-1111-111111111111","alterId":0,"tls":true,"sni":"sni.example.com","skip-cert-verify":true,"_loon_tls_profile":"chrome","client-fingerprint":"chrome","alpn":["http/1.1","h2","h3"],"network":"http","http-opts":{"path":["/http"],"headers":{"Host":["cdn.example.com"]}}}`,
		},
		{
			name:  "vmess reality",
			input: `Loon VMess Reality=vmess,loon-vmess-reality.example.com,443,auto,"11111111-1111-1111-1111-111111111111",transport=tcp,over-tls=true,sni=sni.example.com,skip-cert-verify=true,public-key=vmess-pubkey,short-id=01,alterId=0`,
			want:  `{"type":"vmess","name":"Loon VMess Reality","server":"loon-vmess-reality.example.com","port":443,"cipher":"auto","uuid":"11111111-1111-1111-1111-111111111111","alterId":0,"tls":true,"sni":"sni.example.com","skip-cert-verify":true,"reality-opts":{"public-key":"vmess-pubkey","short-id":"01"}}`,
		},
		{
			name:  "vmess chacha20 canonicalized",
			input: `Loon VMess Chacha=vmess,loon-vmess-chacha.example.com,443,chacha20-ietf-poly1305,"11111111-1111-1111-1111-111111111111"`,
			want:  `{"type":"vmess","name":"Loon VMess Chacha","server":"loon-vmess-chacha.example.com","port":443,"cipher":"chacha20-poly1305","uuid":"11111111-1111-1111-1111-111111111111","alterId":0}`,
		},
		{
			name:  "vmess invalid security defaults to auto",
			input: `Loon VMess Invalid=vmess,loon-vmess-invalid.example.com,443,unknown-cipher,"11111111-1111-1111-1111-111111111111"`,
			want:  `{"type":"vmess","name":"Loon VMess Invalid","server":"loon-vmess-invalid.example.com","port":443,"cipher":"auto","uuid":"11111111-1111-1111-1111-111111111111","alterId":0}`,
		},
		{
			name:  "vless websocket reality",
			input: `Loon VLESS=vless,loon-vless.example.com,443,"11111111-1111-1111-1111-111111111111",transport=ws,host=cdn.example.com,path=/ws,over-tls=true,tls-name=sni.example.com,skip-cert-verify=true,flow=xtls-rprx-vision,public-key=pubkey,short-id=08`,
			want:  `{"type":"vless","name":"Loon VLESS","server":"loon-vless.example.com","port":443,"uuid":"11111111-1111-1111-1111-111111111111","tls":true,"sni":"sni.example.com","skip-cert-verify":true,"flow":"xtls-rprx-vision","network":"ws","ws-opts":{"path":"/ws","headers":{"Host":"cdn.example.com"}},"reality-opts":{"public-key":"pubkey","short-id":"08"}}`,
		},
		{
			name:  "trojan websocket tls",
			input: `Loon Trojan=trojan,loon-trojan.example.com,443,"secret",transport=ws,host=cdn.example.com,path=/trojan,over-tls=true,tls-name=sni.example.com,skip-cert-verify=true`,
			want:  `{"type":"trojan","name":"Loon Trojan","server":"loon-trojan.example.com","port":443,"password":"secret","tls":true,"sni":"sni.example.com","skip-cert-verify":true,"network":"ws","ws-opts":{"path":"/trojan","headers":{"Host":"cdn.example.com"}}}`,
		},
		{
			name:  "trojan reality",
			input: `Loon Trojan Reality=trojan,loon-trojan-reality.example.com,443,"secret",over-tls=true,sni=sni.example.com,skip-cert-verify=true,public-key=trojan-pubkey,short-id=02`,
			want:  `{"type":"trojan","name":"Loon Trojan Reality","server":"loon-trojan-reality.example.com","port":443,"password":"secret","tls":true,"sni":"sni.example.com","skip-cert-verify":true,"reality-opts":{"public-key":"trojan-pubkey","short-id":"02"}}`,
		},
		{
			name:  "anytls",
			input: `Loon AnyTLS=anytls,loon-anytls.example.com,443,"secret",transport=ws,host=cdn.example.com,path=/anytls,over-tls=true,tls-name=sni.example.com,skip-cert-verify=true,idle-session-timeout=30,max-stream-count=16`,
			want:  `{"type":"anytls","name":"Loon AnyTLS","server":"loon-anytls.example.com","port":443,"password":"secret","tls":true,"sni":"sni.example.com","skip-cert-verify":true,"network":"ws","ws-opts":{"path":"/anytls","headers":{"Host":"cdn.example.com"}},"idle-session-timeout":30,"max-stream-count":16}`,
		},
		{
			name:  "anytls reality",
			input: `Loon AnyTLS Reality=anytls,loon-anytls-reality.example.com,443,"secret",over-tls=true,sni=sni.example.com,skip-cert-verify=true,public-key=anytls-pubkey,short-id=03`,
			want:  `{"type":"anytls","name":"Loon AnyTLS Reality","server":"loon-anytls-reality.example.com","port":443,"password":"secret","tls":true,"sni":"sni.example.com","skip-cert-verify":true,"reality-opts":{"public-key":"anytls-pubkey","short-id":"03"}}`,
		},
		{
			name:  "hysteria2",
			input: `Loon Hysteria2=hysteria2,loon-hy2.example.com,443,"secret",tls-name=peer.example.com,skip-cert-verify=true,download-bandwidth=100,salamander-password=mask,ecn=true`,
			want:  `{"type":"hysteria2","name":"Loon Hysteria2","server":"loon-hy2.example.com","port":443,"password":"secret","sni":"peer.example.com","skip-cert-verify":true,"down":"100","obfs":"salamander","obfs-password":"mask","ecn":true}`,
		},
		{
			name:  "hysteria2 port hopping",
			input: `Loon Hysteria2 Port Hopping=hysteria2,loon-hy2.example.com,443,"secret",server-ports="1000,2000-3000,5000",hop-interval=30,tls-name=peer.example.com,skip-cert-verify=true`,
			want:  `{"type":"hysteria2","name":"Loon Hysteria2 Port Hopping","server":"loon-hy2.example.com","port":443,"ports":"1000,2000-3000,5000","hop-interval":30,"password":"secret","sni":"peer.example.com","skip-cert-verify":true}`,
		},
		{
			name:  "https auth",
			input: `Loon HTTPS=https,loon-http.example.com,8443,user,"pass",tls-name=sni.example.com,skip-cert-verify=true`,
			want:  `{"type":"http","name":"Loon HTTPS","server":"loon-http.example.com","port":8443,"username":"user","password":"pass","tls":true,"sni":"sni.example.com","skip-cert-verify":true}`,
		},
		{
			name:  "https ip-mode",
			input: `Loon HTTPS IP Mode=https,loon-http.example.com,8443,user,"pass",ip-mode=v4-only`,
			want:  `{"type":"http","name":"Loon HTTPS IP Mode","server":"loon-http.example.com","port":8443,"username":"user","password":"pass","tls":true,"ip-version":"v4-only"}`,
		},
		{
			name:  "https tls-cert-sha256",
			input: `Loon HTTPS Fingerprint=https,loon-http.example.com,8443,user,"pass",tls-cert-sha256=fingerprint`,
			want:  `{"type":"http","name":"Loon HTTPS Fingerprint","server":"loon-http.example.com","port":8443,"username":"user","password":"pass","tls":true,"tls-fingerprint":"fingerprint"}`,
		},
		{
			name:  "https tls-pubkey-sha256",
			input: `Loon HTTPS Pubkey=https,loon-http.example.com,8443,user,"pass",tls-pubkey-sha256=pubkey`,
			want:  `{"type":"http","name":"Loon HTTPS Pubkey","server":"loon-http.example.com","port":8443,"username":"user","password":"pass","tls":true,"tls-pubkey-sha256":"pubkey"}`,
		},
		{
			name:  "socks5 over tls",
			input: `Loon SOCKS5=socks5,loon-socks.example.com,1080,user,"pass",over-tls=true,tls-name=sni.example.com,skip-cert-verify=true`,
			want:  `{"type":"socks5","name":"Loon SOCKS5","server":"loon-socks.example.com","port":1080,"username":"user","password":"pass","tls":true,"sni":"sni.example.com","skip-cert-verify":true}`,
		},
		{
			name:  "socks5 ip-mode",
			input: `Loon SOCKS5 IP Mode=socks5,loon-socks.example.com,1080,user,"pass",ip-mode=v4-only`,
			want:  `{"type":"socks5","name":"Loon SOCKS5 IP Mode","server":"loon-socks.example.com","port":1080,"username":"user","password":"pass","ip-version":"v4-only"}`,
		},
		{
			name:  "wireguard",
			input: `Loon WG=wireguard,interface-ip=10.0.0.2,interface-ipv6=fd00::2,private-key=private-key,mtu=1280,keepalive=25,dns=1.1.1.1,dnsv6=2606:4700:4700::1111,peers=[{endpoint=loon-wg.example.com:51820,public-key=public-key,allowed-ips="0.0.0.0/0, ::/0",reserved=[1,2,3]}]`,
			want:  `{"type":"wireguard","name":"Loon WG","server":"loon-wg.example.com","port":51820,"ip":"10.0.0.2","ipv6":"fd00::2","private-key":"private-key","public-key":"public-key","mtu":1280,"keepalive":25,"reserved":[1,2,3],"allowed-ips":["0.0.0.0/0","::/0"],"dns":["1.1.1.1","2606:4700:4700::1111"],"remote-dns-resolve":true,"udp":true,"peers":[{"server":"loon-wg.example.com","port":51820,"ip":"10.0.0.2","ipv6":"fd00::2","public-key":"public-key","pre-shared-key":"","allowed-ips":["0.0.0.0/0","::/0"],"reserved":[1,2,3]}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxies := ParseText(tc.input)
			if len(proxies) != 1 {
				t.Fatalf("expected 1 proxy, got %d", len(proxies))
			}
			got, err := json.Marshal(proxies[0].Fields())
			if err != nil {
				t.Fatal(err)
			}
			var want map[string]any
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
			var gotMap map[string]any
			if err := json.Unmarshal(got, &gotMap); err != nil {
				t.Fatal(err)
			}
			for k, v := range want {
				gv, ok := gotMap[k]
				if !ok {
					t.Errorf("missing key %q", k)
					continue
				}
				gj, _ := json.Marshal(gv)
				wj, _ := json.Marshal(v)
				if string(gj) != string(wj) {
					t.Errorf("key %q = %s, want %s", k, gj, wj)
				}
			}
			_ = got
		})
	}
}

func TestLoonSubStoreRejections(t *testing.T) {
	rejected := []string{
		`Loon Hysteria2 Hop Range=hysteria2,loon-hy2.example.com,443,"secret",hop-interval=15-30`,
		`Loon ShadowTLS Invalid=shadowsocks,loon-invalid.example.com,8388,aes-128-gcm,"secret",shadow-tls-password=shadow-pass,shadow-tls-sni=mask.example.com,shadow-tls-version=1,alpn="h2"`,
	}
	for _, input := range rejected {
		if proxies := ParseText(input); len(proxies) != 0 {
			t.Errorf("expected 0 proxies for %q, got %d", input, len(proxies))
		}
	}
}

// TestLoonSurgeFallthrough verifies that lines the Surge parser rejects are
// handed over to the Loon parser (and vice versa), matching the Sub-Store
// parser ordering.
func TestLoonSurgeFallthrough(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantType string
	}{
		{
			name:     "loon-style vmess without username",
			input:    `Loon VMess=vmess,loon-vmess.example.com,443,auto,"11111111-1111-1111-1111-111111111111",path=/ws`,
			wantType: "vmess",
		},
		{
			name:     "surge http line with loon-only over-tls",
			input:    `Surge HTTP=http,loon-http.example.com,8443,user,"pass",over-tls=true`,
			wantType: "http",
		},
		{
			name:     "surge socks5 with loon-only tls-name",
			input:    `Surge SOCKS5=socks5,loon-socks.example.com,1080,user,"pass",tls-name=sni.example.com`,
			wantType: "socks5",
		},
		{
			name:     "surge vmess line stays in surge parser",
			input:    `Surge VMess=vmess,surge-vmess.example.com,443,username=11111111-1111-1111-1111-111111111111,tls=true,vmess-aead=true`,
			wantType: "vmess",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxies := ParseText(tc.input)
			if len(proxies) != 1 {
				t.Fatalf("expected 1 proxy, got %d", len(proxies))
			}
			if got := proxies[0].Type(); got != tc.wantType {
				t.Errorf("type = %q, want %q", got, tc.wantType)
			}
		})
	}

	// the surge-parsed vmess line must carry the uuid from username
	proxies := ParseText(`Surge VMess=vmess,surge-vmess.example.com,443,username=11111111-1111-1111-1111-111111111111,tls=true,vmess-aead=true`)
	if got := proxies[0].GetString("uuid"); got != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("surge vmess uuid = %q", got)
	}
}

func TestLoonTLSProfile(t *testing.T) {
	cases := [][2]string{
		{`Loon default=vmess,loon-default.example.com,443,auto,"11111111-1111-1111-1111-111111111111",over-tls=true,tls-profile=default,alterId=0`, `{"_loon_tls_profile":"default"}`},
		{`Loon chrome=vmess,loon-chrome.example.com,443,auto,"11111111-1111-1111-1111-111111111111",over-tls=true,tls-profile=chrome,alterId=0`, `{"_loon_tls_profile":"chrome","client-fingerprint":"chrome"}`},
		{`Loon ios18=vmess,loon-ios18.example.com,443,auto,"11111111-1111-1111-1111-111111111111",over-tls=true,tls-profile=ios18,alterId=0`, `{"_loon_tls_profile":"ios18","client-fingerprint":"ios"}`},
		{`Loon unknown=vmess,loon-unknown.example.com,443,auto,"11111111-1111-1111-1111-111111111111",over-tls=true,tls-profile=unknown-browser,alterId=0`, `{"_loon_tls_profile":"unknown-browser"}`},
	}
	for _, tc := range cases {
		proxies := ParseText(tc[0])
		if len(proxies) != 1 {
			t.Errorf("expected 1 proxy, got %d for %q", len(proxies), tc[0])
			continue
		}
		got, _ := json.Marshal(proxies[0].Fields())
		var want, gotMap map[string]any
		json.Unmarshal([]byte(tc[1]), &want)
		json.Unmarshal(got, &gotMap)
		for k, v := range want {
			gj, _ := json.Marshal(gotMap[k])
			wj, _ := json.Marshal(v)
			if string(gj) != string(wj) {
				t.Errorf("key %q = %s, want %s", k, gj, wj)
			}
		}
	}
}

