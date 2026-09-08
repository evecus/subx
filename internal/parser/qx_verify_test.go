package parser

import (
	"encoding/json"
	"testing"
)

// TestQXSubStoreCases mirrors the Quantumult X raw-input cases from
// Sub-Store's v2ray-and-platforms.spec.js (expectSubset semantics).
func TestQXSubStoreCases(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "shadowsocks over-tls",
			input: `shadowsocks=qx-ss-tls.example.com:443,method=aes-128-gcm,password=secret,obfs=over-tls,obfs-host=a.com,tls-verification=false,udp-relay=true,fast-open=true,tag=QX SS Over TLS`,
			want:  `{"type":"ss","name":"QX SS Over TLS","server":"qx-ss-tls.example.com","port":443,"cipher":"aes-128-gcm","password":"secret","tls":true,"sni":"a.com","skip-cert-verify":true,"udp":true,"tfo":true}`,
		},
		{
			name:  "shadowsocks over-tls verified",
			input: `shadowsocks=qx-ss-tls-verified.example.com:443,method=aes-128-gcm,password=secret,obfs=over-tls,obfs-host=verify.example.com,tls-verification=true,tag=QX SS Over TLS Verified`,
			want:  `{"type":"ss","name":"QX SS Over TLS Verified","server":"qx-ss-tls-verified.example.com","port":443,"cipher":"aes-128-gcm","password":"secret","tls":true,"sni":"verify.example.com","skip-cert-verify":false}`,
		},
		{
			name:  "vless non-boolean tls-verification",
			input: `vless=qx-vless-verify-name.example.com:443,method=none,password=11111111-1111-4111-8111-111111111111,obfs=wss,tls-verification=true.example.com,tag=QX VLESS Verify Name`,
			want:  `{"type":"vless","name":"QX VLESS Verify Name","server":"qx-vless-verify-name.example.com","port":443,"cipher":"none","uuid":"11111111-1111-4111-8111-111111111111","name-cert-verify":"true.example.com","tls":true}`,
		},
		{
			name:  "shadowsocks over-tls without obfs-host",
			input: `shadowsocks=qx-ss-tls-no-host.example.com:443,method=aes-128-gcm,password=secret,obfs=over-tls,udp-relay=true,tag=QX SS Over TLS No Host`,
			want:  `{"type":"ss","name":"QX SS Over TLS No Host","server":"qx-ss-tls-no-host.example.com","port":443,"cipher":"aes-128-gcm","password":"secret","tls":true,"udp":true}`,
		},
		{
			name:  "shadowsocks legacy obfs tls",
			input: `shadowsocks=qx-ss-obfs.example.com:8388,method=aes-128-gcm,password=secret,obfs=tls,obfs-host=obfs.example.com,tag=QX SS Obfs TLS`,
			want:  `{"type":"ss","name":"QX SS Obfs TLS","server":"qx-ss-obfs.example.com","port":8388,"cipher":"aes-128-gcm","password":"secret","plugin":"obfs","plugin-opts":{"mode":"tls","host":"obfs.example.com"}}`,
		},
		{
			name:  "shadowsocks http obfs plain token",
			input: `shadowsocks=qx-ss-http-plain.example.com:8388,method=aes-128-gcm,password=secret,obfs=http,obfs-host=plain.example.com,obfs-uri=/plain,tag=QX SS HTTP`,
			want:  `{"type":"ss","name":"QX SS HTTP","server":"qx-ss-http-plain.example.com","port":8388,"cipher":"aes-128-gcm","password":"secret","plugin":"obfs","_qx_obfs_http":"http","plugin-opts":{"mode":"http","host":"plain.example.com","path":"/plain"}}`,
		},
		{
			name:  "shadowsocks vemss-http token",
			input: `shadowsocks=qx-ss-http.example.com:8388,method=aes-128-gcm,password=secret,obfs=vemss-http,obfs-host=obfs.example.com,obfs-uri=/resource,tag=QX SS VMess HTTP`,
			want:  `{"type":"ss","name":"QX SS VMess HTTP","server":"qx-ss-http.example.com","port":8388,"cipher":"aes-128-gcm","password":"secret","plugin":"obfs","_qx_obfs_http":"vemss-http","plugin-opts":{"mode":"http","host":"obfs.example.com","path":"/resource"}}`,
		},
		{
			name:  "shadowsocks shadowsocks-http token",
			input: `shadowsocks=qx-ss-shadowsocks-http.example.com:8388,method=aes-128-gcm,password=secret,obfs=shadowsocks-http,obfs-host=shadow.example.com,obfs-uri=/shadow,tag=QX SS Shadowsocks HTTP`,
			want:  `{"type":"ss","name":"QX SS Shadowsocks HTTP","server":"qx-ss-shadowsocks-http.example.com","port":8388,"cipher":"aes-128-gcm","password":"secret","plugin":"obfs","_qx_obfs_http":"shadowsocks-http","plugin-opts":{"mode":"http","host":"shadow.example.com","path":"/shadow"}}`,
		},
		{
			name:  "shadowsocks v2ray-plugin wss",
			input: `shadowsocks=qx-ss.example.com:8388,method=aes-128-gcm,password=secret,obfs=wss,obfs-host=obfs.example.com,obfs-uri=/ws,udp-relay=true,fast-open=true,tag=QX SS`,
			want:  `{"type":"ss","name":"QX SS","server":"qx-ss.example.com","port":8388,"cipher":"aes-128-gcm","password":"secret","udp":true,"tfo":true,"plugin":"v2ray-plugin","plugin-opts":{"mode":"websocket","tls":true,"host":"obfs.example.com","path":"/ws"}}`,
		},
		{
			name:  "shadowsocksr",
			input: `shadowsocks=qx-ssr.example.com:8389,method=aes-256-cfb,password=secret,ssr-protocol=auth_chain_b,ssr-protocol-param=device-id,obfs=tls1.2_ticket_fastauth,obfs-host=cdn.example.com,tag=QX SSR`,
			want:  `{"type":"ssr","name":"QX SSR","server":"qx-ssr.example.com","port":8389,"cipher":"aes-256-cfb","password":"secret","protocol":"auth_chain_b","protocol-param":"device-id","obfs":"tls1.2_ticket_fastauth","obfs-param":"cdn.example.com"}`,
		},
		{
			name:  "vmess websocket tls",
			input: `vmess=qx-vmess.example.com:443,method=chacha20,password=11111111-1111-4111-8111-111111111111,obfs=wss,obfs-host=cdn.example.com,obfs-uri=/vmess,tls-verification=false,tls-host=sni.example.com,aead=true,udp-relay=true,tag=QX VMess`,
			want:  `{"type":"vmess","name":"QX VMess","server":"qx-vmess.example.com","port":443,"cipher":"chacha20","uuid":"11111111-1111-4111-8111-111111111111","aead":true,"alterId":0,"tls":true,"sni":"sni.example.com","skip-cert-verify":true,"udp":true,"network":"ws","ws-opts":{"path":"/vmess","headers":{"Host":"cdn.example.com"}}}`,
		},
		{
			name:  "vmess http obfs plain token",
			input: `vmess=qx-vmess-http-plain.example.com:80,method=none,password=11111111-1111-4111-8111-111111111111,obfs=http,obfs-host=plain.example.com,obfs-uri=/http,tag=QX VMess HTTP`,
			want:  `{"type":"vmess","name":"QX VMess HTTP","server":"qx-vmess-http-plain.example.com","port":80,"cipher":"none","uuid":"11111111-1111-4111-8111-111111111111","alterId":0,"network":"http","_qx_obfs_http":"http","http-opts":{"path":["/http"],"headers":{"Host":["plain.example.com"]}}}`,
		},
		{
			name:  "vmess vemss-http token",
			input: `vmess=qx-vmess-vemss-http.example.com:80,method=none,password=11111111-1111-4111-8111-111111111111,obfs=vemss-http,obfs-host=vemss.example.com,obfs-uri=/vemss,tag=QX VMess VMess HTTP`,
			want:  `{"type":"vmess","name":"QX VMess VMess HTTP","server":"qx-vmess-vemss-http.example.com","port":80,"cipher":"none","uuid":"11111111-1111-4111-8111-111111111111","alterId":0,"network":"http","_qx_obfs_http":"vemss-http","http-opts":{"path":["/vemss"],"headers":{"Host":["vemss.example.com"]}}}`,
		},
		{
			name:  "vmess shadowsocks-http token",
			input: `vmess=qx-vmess-http.example.com:80,method=none,password=11111111-1111-4111-8111-111111111111,obfs=shadowsocks-http,obfs-host=cdn.example.com,obfs-uri=/resource/file,tag=QX VMess Shadowsocks HTTP`,
			want:  `{"type":"vmess","name":"QX VMess Shadowsocks HTTP","server":"qx-vmess-http.example.com","port":80,"cipher":"none","uuid":"11111111-1111-4111-8111-111111111111","alterId":0,"network":"http","_qx_obfs_http":"shadowsocks-http","http-opts":{"path":["/resource/file"],"headers":{"Host":["cdn.example.com"]}}}`,
		},
		{
			name:  "vless vmess-http token",
			input: `vless=qx-vless-http.example.com:80,method=none,password=11111111-1111-4111-8111-111111111111,obfs=vmess-http,obfs-host=vless.example.com,obfs-uri=/vless-http,tag=QX VLESS HTTP`,
			want:  `{"type":"vless","name":"QX VLESS HTTP","server":"qx-vless-http.example.com","port":80,"cipher":"none","uuid":"11111111-1111-4111-8111-111111111111","network":"http","_qx_obfs_http":"vmess-http","http-opts":{"path":["/vless-http"],"headers":{"Host":["vless.example.com"]}}}`,
		},
		{
			name:  "vless reality websocket",
			input: `vless=qx-vless.example.com:443,method=none,password=11111111-1111-4111-8111-111111111111,obfs=wss,obfs-host=cdn.example.com,obfs-uri=/vless,tls-verification=false,tls-host=sni.example.com,reality-base64-pubkey=pubkey,reality-hex-shortid=08,vless-flow=xtls-rprx-vision,tag=QX VLESS`,
			want:  `{"type":"vless","name":"QX VLESS","server":"qx-vless.example.com","port":443,"cipher":"none","uuid":"11111111-1111-4111-8111-111111111111","tls":true,"sni":"sni.example.com","skip-cert-verify":true,"flow":"xtls-rprx-vision","network":"ws","ws-opts":{"path":"/vless","headers":{"Host":"cdn.example.com"}},"reality-opts":{"public-key":"pubkey","short-id":"08"}}`,
		},
		{
			name:  "vless over-tls obfs-host alias",
			input: `vless=qx-vless-overtls.example.com:37001,method=none,password=11111111-1111-4111-8111-111111111111,obfs=over-tls,obfs-host=tls-name.example.com,tls13=true,tls-verification=false,reality-base64-pubkey=pubkey,reality-hex-shortid=01ab,vless-flow=xtls-rprx-vision,fast-open=false,udp-relay=true,tag=QX VLESS Over TLS Alias`,
			want:  `{"type":"vless","name":"QX VLESS Over TLS Alias","server":"qx-vless-overtls.example.com","port":37001,"cipher":"none","uuid":"11111111-1111-4111-8111-111111111111","tls":true,"sni":"tls-name.example.com","skip-cert-verify":true,"flow":"xtls-rprx-vision","udp":true,"tfo":false,"reality-opts":{"public-key":"pubkey","short-id":"01ab"}}`,
		},
		{
			name:  "vless over-tls explicit tls-host wins",
			input: `vless=qx-vless-overtls-priority.example.com:443,method=none,password=11111111-1111-4111-8111-111111111111,obfs=over-tls,obfs-host=tls-alias.example.com,tls-host=explicit-sni.example.com,tls-verification=false,vless-flow=xtls-rprx-vision,tag=QX VLESS Over TLS Explicit`,
			want:  `{"type":"vless","name":"QX VLESS Over TLS Explicit","server":"qx-vless-overtls-priority.example.com","port":443,"cipher":"none","uuid":"11111111-1111-4111-8111-111111111111","tls":true,"sni":"explicit-sni.example.com","skip-cert-verify":true,"flow":"xtls-rprx-vision"}`,
		},
		{
			name:  "anytls standard tls",
			input: `anytls=example.com:443,password=pwd,over-tls=true,tls-host=apple.com,udp-relay=true,tag=anytls-standard-tls-01`,
			want:  `{"type":"anytls","name":"anytls-standard-tls-01","server":"example.com","port":443,"password":"pwd","tls":true,"sni":"apple.com","udp":true}`,
		},
		{
			name:  "anytls reality",
			input: `anytls=example.com:443,password=pwd,over-tls=true,tls-host=apple.com,reality-base64-pubkey=k4Uxez0sjl8bKaZH2Vgi8-WDFshML51QkxKFLWFIONk,reality-hex-shortid=0123456789abcdef,tag=anytls-reality-tls-01`,
			want:  `{"type":"anytls","name":"anytls-reality-tls-01","server":"example.com","port":443,"password":"pwd","tls":true,"sni":"apple.com","reality-opts":{"public-key":"k4Uxez0sjl8bKaZH2Vgi8-WDFshML51QkxKFLWFIONk","short-id":"0123456789abcdef"}}`,
		},
		{
			name:  "trojan websocket tls",
			input: `trojan=qx-trojan.example.com:443,password=secret,obfs=wss,obfs-host=cdn.example.com,obfs-uri=/trojan,tls-verification=false,tls-host=sni.example.com,tls-cert-sha256=fingerprint,tag=QX Trojan`,
			want:  `{"type":"trojan","name":"QX Trojan","server":"qx-trojan.example.com","port":443,"password":"secret","tls":true,"sni":"sni.example.com","skip-cert-verify":true,"tls-fingerprint":"fingerprint","network":"ws","ws-opts":{"path":"/trojan","headers":{"Host":"cdn.example.com"}}}`,
		},
		{
			name:  "http over tls",
			input: `http=qx-http.example.com:8443,username=user,password=pass,over-tls=true,tls-host=sni.example.com,tls-verification=false,fast-open=true,tag=QX HTTP`,
			want:  `{"type":"http","name":"QX HTTP","server":"qx-http.example.com","port":8443,"username":"user","password":"pass","tls":true,"sni":"sni.example.com","skip-cert-verify":true,"tfo":true}`,
		},
		{
			name:  "socks5 over tls",
			input: `socks5=qx-socks.example.com:1080,username=user,password=pass,over-tls=true,tls-host=sni.example.com,tls-verification=false,udp-relay=true,tag=QX SOCKS5`,
			want:  `{"type":"socks5","name":"QX SOCKS5","server":"qx-socks.example.com","port":1080,"username":"user","password":"pass","tls":true,"sni":"sni.example.com","skip-cert-verify":true,"udp":true}`,
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
			var want, gotMap map[string]any
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
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
		})
	}
}

// TestQXSubStoreRejections mirrors the QX grammar rules that throw, and
// lines whose type or address is invalid: they are dropped.
func TestQXSubStoreRejections(t *testing.T) {
	rejections := []string{
		// udp-over-tcp is only accepted for shadowsocks
		`trojan=qx-trojan.example.com:443,password=secret,udp-over-tcp=sp.v1,tag=x`,
		`vmess=qx-vmess.example.com:443,password=11111111-1111-4111-8111-111111111111,udp-over-tcp=sp.v2,tag=x`,
		`http=qx-http.example.com:443,username=user,password=pass,udp-over-tcp=true,tag=x`,
		// invalid udp-over-tcp value for shadowsocks
		`shadowsocks=qx-ss.example.com:443,method=aes-128-gcm,password=secret,udp-over-tcp=invalid,tag=x`,
		// no address
		`shadowsocks=example.com,method=aes-128-gcm,password=secret,tag=x`,
		`shadowsocks=qx-ss.example.com,method=aes-128-gcm,password=secret,tag=x`,
		// invalid port
		`vmess=qx-vmess.example.com:99999,password=11111111-1111-4111-8111-111111111111,tag=x`,
		`vless=qx-vless.example.com:80abc,method=none,password=11111111-1111-4111-8111-111111111111,tag=x`,
		// "ss" and "wireguard" are not QX line types
		`ss=qx-ss.example.com:443,method=aes-128-gcm,password=secret,tag=x`,
		`wireguard=qx-wg.example.com,443,private-key=x,tag=x`,
	}
	for _, input := range rejections {
		if proxies := ParseText(input); len(proxies) != 0 {
			t.Errorf("expected 0 proxies for %q, got %d", input, len(proxies))
		}
	}
}

// TestQXTLSVerificationToSkipCertVerify covers the QX tls-verification
// boolean inversion and the aead=false alterId switch.
func TestQXTLSVerificationToSkipCertVerify(t *testing.T) {
	proxies := ParseText(`vmess=qx-vmess.example.com:443,method=none,password=11111111-1111-4111-8111-111111111111,over-tls=true,aead=false,tag=QX VMess Legacy`)
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	if got := proxies[0].GetInt("alterId"); got != 1 {
		t.Errorf("alterId = %d, want 1", got)
	}
	if got := proxies[0].GetBool("aead"); got {
		t.Errorf("aead = true, want false")
	}
	if got := proxies[0].GetBool("tls"); !got {
		t.Errorf("tls = false, want true")
	}
}
