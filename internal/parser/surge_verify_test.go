package parser

import (
	"encoding/json"
	"testing"
)

// TestSurgeSubStoreCases mirrors the Surge raw-input cases from Sub-Store's
// v2ray-and-platforms.spec.js (expectSubset semantics).
func TestSurgeSubStoreCases(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "direct",
			input: `Surge Direct = direct, udp-relay=true`,
			want:  `{"type":"direct","name":"Surge Direct","udp":true}`,
		},
		{
			name:  "anytls",
			input: `Surge AnyTLS = anytls,surge-anytls.example.com,443,password=secret,sni=sni.example.com,skip-cert-verify=true,reuse=true`,
			want:  `{"type":"anytls","name":"Surge AnyTLS","server":"surge-anytls.example.com","port":443,"password":"secret","tls":true,"sni":"sni.example.com","skip-cert-verify":true,"reuse":true}`,
		},
		{
			name:  "trust-tunnel headers",
			input: `Surge TrustTunnel = trust-tunnel,surge-trust.example.com,443,username=user,password=secret,headers=X-Client:Surge;X-Token:abc,sni=sni.example.com,skip-cert-verify=true,reuse=true`,
			want:  `{"type":"trusttunnel","name":"Surge TrustTunnel","server":"surge-trust.example.com","port":443,"username":"user","password":"secret","tls":true,"headers":{"X-Client":"Surge","X-Token":"abc"},"sni":"sni.example.com","skip-cert-verify":true,"reuse":true}`,
		},
		{
			name:  "trust-tunnel max-streams double quoted",
			input: `Surge TrustTunnel Max Streams = trust-tunnel,surge-trust.example.com,443,username=user,password=secret,headers=X-Client:Surge,max-streams="3",sni=sni.example.com,skip-cert-verify=true,reuse=true`,
			want:  `{"type":"trusttunnel","name":"Surge TrustTunnel Max Streams","server":"surge-trust.example.com","port":443,"username":"user","password":"secret","tls":true,"headers":{"X-Client":"Surge"},"max-streams":3,"sni":"sni.example.com","skip-cert-verify":true,"reuse":true}`,
		},
		{
			name:  "trust-tunnel max-streams single quoted",
			input: `Surge TrustTunnel Single Max Streams = trust-tunnel,surge-trust-single.example.com,443,max-streams='2'`,
			want:  `{"type":"trusttunnel","name":"Surge TrustTunnel Single Max Streams","server":"surge-trust-single.example.com","port":443,"tls":true,"max-streams":2}`,
		},
		{
			name:  "h2-connect dynamic headers",
			input: `Surge H2 = h2-connect,h2.example.com,443,headers=X-Padding:<random-string(16-32)>,sni=sni.example.com,skip-cert-verify=true`,
			want:  `{"type":"h2-connect","name":"Surge H2","server":"h2.example.com","port":443,"tls":true,"headers":{"X-Padding":"<random-string(16-32)>"},"sni":"sni.example.com","skip-cert-verify":true}`,
		},
		{
			name:  "h2-connect max-streams",
			input: `Surge H2 Max Streams = h2-connect,h2.example.com,443,headers=X-Padding:<random-string(16-32)>,max-streams=1,sni=sni.example.com,skip-cert-verify=true`,
			want:  `{"type":"h2-connect","name":"Surge H2 Max Streams","server":"h2.example.com","port":443,"tls":true,"headers":{"X-Padding":"<random-string(16-32)>"},"max-streams":1,"sni":"sni.example.com","skip-cert-verify":true}`,
		},
		{
			name:  "http nested quoted headers",
			input: `1=http,163.177.17.6,443,headers="Host:153.3.236.22:443;X-T5-Auth:683556433;Connection:Keep-Alive;User-Agent:"okhttp/3.11.0 Dalvik/2.1.0 (Linux; U; Android 11; Redmi K30 5G Build/RKQ1.200826.002) baiduboxapp/11.0.5.12 (Baidu; P1 11)""`,
			want:  `{"type":"http","name":"1","server":"163.177.17.6","port":443,"headers":{"Host":"153.3.236.22:443","X-T5-Auth":"683556433","Connection":"Keep-Alive","User-Agent":"okhttp/3.11.0 Dalvik/2.1.0 (Linux; U; Android 11; Redmi K30 5G Build/RKQ1.200826.002) baiduboxapp/11.0.5.12 (Baidu; P1 11)"}}`,
		},
		{
			name:  "quoted header keys and values",
			input: `Surge Quoted Headers = https,quoted.example.com,443,headers='Host':'153.3.236.22:443';"X-T5-Auth":"683556433";Connection:"Keep-Alive";"User-Agent":"okhttp/3.11.0 Dalvik/2.1.0 (Linux; U; Android 11; Redmi K30 5G Build/RKQ1.200826.002) baiduboxapp/11.0.5.12 (Baidu; P1 11)",sni=sni.example.com`,
			want:  `{"type":"http","name":"Surge Quoted Headers","server":"quoted.example.com","port":443,"tls":true,"headers":{"Host":"153.3.236.22:443","X-T5-Auth":"683556433","Connection":"Keep-Alive","User-Agent":"okhttp/3.11.0 Dalvik/2.1.0 (Linux; U; Android 11; Redmi K30 5G Build/RKQ1.200826.002) baiduboxapp/11.0.5.12 (Baidu; P1 11)"},"sni":"sni.example.com"}`,
		},
		{
			name:  "nested header values with commas",
			input: `Surge Nested Headers = https,nested.example.com,443,headers="Host:"nested.example.com" ; X-Comma:"a,b" ; User-Agent:"client/1.0 (Linux; U; Android 11)"",sni=sni.example.com`,
			want:  `{"type":"http","name":"Surge Nested Headers","server":"nested.example.com","port":443,"tls":true,"headers":{"Host":"nested.example.com","X-Comma":"a,b","User-Agent":"client/1.0 (Linux; U; Android 11)"},"sni":"sni.example.com"}`,
		},
		{
			name:  "nested header values with quote characters",
			input: `Surge Nested Quote Headers = https,quote.example.com,443,headers="X-Quote:"a"b";X-Semi:"x;y"",sni=sni.example.com`,
			want:  `{"type":"http","name":"Surge Nested Quote Headers","server":"quote.example.com","port":443,"tls":true,"headers":{"X-Quote":"a\"b","X-Semi":"x;y"},"sni":"sni.example.com"}`,
		},
		{
			name:  "unwrapped headers with quoted keys",
			input: `Surge Quoted Key Start = http,quoted-key.example.com,8080,headers='Host':'quoted-key.example.com';"X-Token":"abc",test-url=http://example.com`,
			want:  `{"type":"http","name":"Surge Quoted Key Start","server":"quoted-key.example.com","port":8080,"headers":{"Host":"quoted-key.example.com","X-Token":"abc"},"test-url":"http://example.com"}`,
		},
		{
			name:  "ssh positional auth",
			input: `Surge SSH = ssh,surge-ssh.example.com,22,user,pass,server-fingerprint=sshfp`,
			want:  `{"type":"ssh","name":"Surge SSH","server":"surge-ssh.example.com","port":22,"username":"user","password":"pass","server-fingerprint":"sshfp"}`,
		},
		{
			name:  "ss obfs",
			input: `Surge SS = ss,surge-ss.example.com,8388,encrypt-method=aes-128-gcm,password=secret,obfs=tls,obfs-host=obfs.example.com,obfs-uri=/tls`,
			want:  `{"type":"ss","name":"Surge SS","server":"surge-ss.example.com","port":8388,"cipher":"aes-128-gcm","password":"secret","plugin":"obfs","plugin-opts":{"mode":"tls","host":"obfs.example.com","path":"/tls"}}`,
		},
		{
			name:  "vmess websocket tls",
			input: `Surge VMess = vmess,surge-vmess.example.com,443,username=11111111-1111-1111-1111-111111111111,ws=true,ws-path=/vmess,ws-headers=Host:cdn.example.com,skip-cert-verify=true,sni=sni.example.com,tls=true,vmess-aead=true,udp-relay=true`,
			want:  `{"type":"vmess","name":"Surge VMess","server":"surge-vmess.example.com","port":443,"uuid":"11111111-1111-1111-1111-111111111111","aead":true,"alterId":0,"tls":true,"sni":"sni.example.com","skip-cert-verify":true,"udp":true,"network":"ws","ws-opts":{"path":"/vmess","headers":{"Host":"cdn.example.com"}}}`,
		},
		{
			name:  "vmess chacha20 canonicalized",
			input: `Surge VMess Chacha = vmess,surge-vmess-chacha.example.com,443,username=11111111-1111-1111-1111-111111111111,encrypt-method=chacha20-ietf-poly1305,vmess-aead=true`,
			want:  `{"type":"vmess","name":"Surge VMess Chacha","server":"surge-vmess-chacha.example.com","port":443,"uuid":"11111111-1111-1111-1111-111111111111","cipher":"chacha20-poly1305","aead":true,"alterId":0}`,
		},
		{
			name:  "vmess invalid method defaults to auto",
			input: `Surge VMess Invalid = vmess,surge-vmess-invalid.example.com,443,username=11111111-1111-1111-1111-111111111111,encrypt-method=none,vmess-aead=true`,
			want:  `{"type":"vmess","name":"Surge VMess Invalid","server":"surge-vmess-invalid.example.com","port":443,"uuid":"11111111-1111-1111-1111-111111111111","cipher":"auto","aead":true,"alterId":0}`,
		},
		{
			name:  "vmess ws headers with pipe and nested quotes",
			input: `Surge VMess WS Headers = vmess,surge-vmess.example.com,443,username=11111111-1111-1111-1111-111111111111,ws=true,ws-path=/vmess,ws-headers="Host:"cdn.example.com" | X-Comma:"a,b" | User-Agent:"okhttp/3.11.0 Dalvik/2.1.0 (Linux; U; Android 11)"",skip-cert-verify=true,sni=sni.example.com,tls=true,vmess-aead=true`,
			want:  `{"type":"vmess","name":"Surge VMess WS Headers","server":"surge-vmess.example.com","port":443,"uuid":"11111111-1111-1111-1111-111111111111","aead":true,"alterId":0,"tls":true,"sni":"sni.example.com","skip-cert-verify":true,"network":"ws","ws-opts":{"path":"/vmess","headers":{"Host":"cdn.example.com","X-Comma":"a,b","User-Agent":"okhttp/3.11.0 Dalvik/2.1.0 (Linux; U; Android 11)"}}}`,
		},
		{
			name:  "trojan websocket tls",
			input: `Surge Trojan = trojan,surge-trojan.example.com,443,password=secret,ws=true,ws-path=/trojan,ws-headers=Host:cdn.example.com,skip-cert-verify=true,sni=sni.example.com,tls=true`,
			want:  `{"type":"trojan","name":"Surge Trojan","server":"surge-trojan.example.com","port":443,"password":"secret","tls":true,"sni":"sni.example.com","skip-cert-verify":true,"network":"ws","ws-opts":{"path":"/trojan","headers":{"Host":"cdn.example.com"}}}`,
		},
		{
			name:  "https auth",
			input: `Surge HTTPS = https,surge-http.example.com,8443,user,pass,headers=X-Token:abc,sni=sni.example.com,skip-cert-verify=true`,
			want:  `{"type":"http","name":"Surge HTTPS","server":"surge-http.example.com","port":8443,"username":"user","password":"pass","tls":true,"headers":{"X-Token":"abc"},"sni":"sni.example.com","skip-cert-verify":true}`,
		},
		{
			name:  "socks5 tls",
			input: `Surge SOCKS5 = socks5-tls,surge-socks.example.com,1080,user,pass,sni=sni.example.com,skip-cert-verify=true,udp-relay=true`,
			want:  `{"type":"socks5","name":"Surge SOCKS5","server":"surge-socks.example.com","port":1080,"username":"user","password":"pass","tls":true,"sni":"sni.example.com","skip-cert-verify":true,"udp":true}`,
		},
		{
			name:  "snell obfs",
			input: `Surge Snell = snell,surge-snell.example.com,443,psk=secret,version=3,obfs=tls,obfs-host=obfs.example.com,obfs-uri=/snell`,
			want:  `{"type":"snell","name":"Surge Snell","server":"surge-snell.example.com","port":443,"psk":"secret","version":3,"obfs-opts":{"mode":"tls","host":"obfs.example.com","path":"/snell"}}`,
		},
		{
			name:  "snell v6 mode",
			input: `Surge Snell v6 = snell,surge-snell.example.com,443,psk=secret,version=6,mode=unshaped,udp-relay=true`,
			want:  `{"type":"snell","name":"Surge Snell v6","server":"surge-snell.example.com","port":443,"psk":"secret","version":6,"mode":"unshaped","udp":true}`,
		},
		{
			name:  "snell shadow-tls alpn",
			input: `Surge Snell ShadowTLS ALPN = snell,surge-snell-alpn.example.com,443,psk=secret,version=5,alpn="h2,http/1.1",shadow-tls-password=shadow-pass,shadow-tls-sni=mask.example.com,shadow-tls-version=3`,
			want:  `{"type":"snell","name":"Surge Snell ShadowTLS ALPN","server":"surge-snell-alpn.example.com","port":443,"psk":"secret","version":5,"plugin":"shadow-tls","plugin-opts":{"host":"mask.example.com","password":"shadow-pass","version":3,"alpn":["h2","http/1.1"]}}`,
		},
		{
			name:  "tuic v5",
			input: `Surge TUIC = tuic-v5,surge-tuic.example.com,443,uuid=11111111-1111-1111-1111-111111111111,password=secret,sni=sni.example.com,skip-cert-verify=true,alpn=h3,ecn=true,port-hopping=9000;9002-9004`,
			want:  `{"type":"tuic","name":"Surge TUIC","server":"surge-tuic.example.com","port":443,"version":5,"uuid":"11111111-1111-1111-1111-111111111111","password":"secret","sni":"sni.example.com","skip-cert-verify":true,"alpn":["h3"],"ecn":true,"ports":"9000,9002-9004"}`,
		},
		{
			name:  "wireguard section",
			input: `Surge WG = wireguard,section-name=wireguard-cellular`,
			want:  `{"type":"wireguard-surge","name":"Surge WG","section-name":"wireguard-cellular"}`,
		},
		{
			name:  "hysteria2",
			input: `Surge Hysteria2 = hysteria2,surge-hy2.example.com,443,password=secret,sni=peer.example.com,skip-cert-verify=true,download-bandwidth=100,ecn=true,salamander-password=mask,port-hopping=8443-8445`,
			want:  `{"type":"hysteria2","name":"Surge Hysteria2","server":"surge-hy2.example.com","port":443,"password":"secret","sni":"peer.example.com","skip-cert-verify":true,"down":"100","ecn":true,"obfs":"salamander","obfs-password":"mask","ports":"8443-8445"}`,
		},
		{
			name:  "hysteria2 gecko obfs",
			input: `Surge Hysteria2 Gecko = hysteria2,surge-hy2.example.com,443,password=secret,gecko-password="mask",sni=peer.example.com`,
			want:  `{"type":"hysteria2","name":"Surge Hysteria2 Gecko","server":"surge-hy2.example.com","port":443,"password":"secret","obfs":"gecko","obfs-password":"mask","sni":"peer.example.com"}`,
		},
		{
			name:  "external with repeated args and addresses",
			input: `Surge External = external, exec="/usr/bin/ssh", local-port="1080", args="-D", args="localhost:1080", addresses="[2001:db8::1]", addresses="1.1.1.1"`,
			want:  `{"type":"external","name":"Surge External","exec":"/usr/bin/ssh","local-port":"1080","args":["-D","localhost:1080"],"addresses":["2001:db8::1","1.1.1.1"]}`,
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

func TestSurgeSubStoreIterations(t *testing.T) {
	// alpn quoted lists for TLS protocol lines
	alpnCases := []string{
		`Surge VMess ALPN = vmess,vmess-alpn.example.com,443,username=11111111-1111-1111-1111-111111111111,tls=true,vmess-aead=true,alpn="http/1.1,h2,h3"`,
		`Surge Trojan ALPN = trojan,trojan-alpn.example.com,443,password=secret,alpn='http/1.1,h2,h3'`,
		`Surge HTTPS ALPN = https,https-alpn.example.com,443,alpn="http/1.1,h2,h3"`,
		`Surge H2 ALPN = h2-connect,h2-alpn.example.com,443,alpn='http/1.1,h2,h3'`,
		`Surge SOCKS5 ALPN = socks5-tls,socks-alpn.example.com,1080,alpn="http/1.1,h2,h3"`,
		`Surge AnyTLS ALPN = anytls,anytls-alpn.example.com,443,password=secret,alpn='http/1.1,h2,h3'`,
		`Surge TrustTunnel ALPN = trust-tunnel,trust-alpn.example.com,443,alpn="http/1.1,h2,h3"`,
		`Surge TUIC ALPN = tuic-v5,tuic-alpn.example.com,443,uuid=11111111-1111-1111-1111-111111111111,password=secret,alpn='http/1.1,h2,h3'`,
		`Surge Hysteria2 ALPN = hysteria2,hy2-alpn.example.com,443,password=secret,alpn="http/1.1,h2,h3"`,
	}
	for _, input := range alpnCases {
		proxies := ParseText(input)
		if len(proxies) != 1 {
			t.Errorf("expected 1 proxy for %q, got %d", input, len(proxies))
			continue
		}
		got := proxies[0].Get("alpn")
		want := []any{"http/1.1", "h2", "h3"}
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(want)
		if string(gj) != string(wj) {
			t.Errorf("alpn = %s, want %s (input %q)", gj, wj, input)
		}
	}

	// server-cert-verify-name for TLS protocol lines
	verifyCases := []string{
		`Surge VMess Verify Name = vmess,vmess-verify.example.com,443,username=11111111-1111-1111-1111-111111111111,tls=true,vmess-aead=true,server-cert-verify-name=verify.example.com`,
		`Surge Trojan Verify Name = trojan,trojan-verify.example.com,443,password=secret,server-cert-verify-name='verify.example.com'`,
		`Surge HTTPS Verify Name = https,https-verify.example.com,443,sni=sni.example.com,server-cert-verify-name="verify.example.com"`,
		`Surge H2 Verify Name = h2-connect,h2-verify.example.com,443,server-cert-verify-name='verify.example.com'`,
		`Surge SOCKS5 Verify Name = socks5-tls,socks-verify.example.com,1080,server-cert-verify-name="verify.example.com"`,
		`Surge AnyTLS Verify Name = anytls,anytls-verify.example.com,443,password=secret,server-cert-verify-name=verify.example.com`,
		`Surge TrustTunnel Verify Name = trust-tunnel,trust-verify.example.com,443,server-cert-verify-name='verify.example.com'`,
		`Surge TUIC Verify Name = tuic,tuic-verify.example.com,443,token=secret,server-cert-verify-name="verify.example.com"`,
		`Surge TUIC v5 Verify Name = tuic-v5,tuic-v5-verify.example.com,443,uuid=11111111-1111-1111-1111-111111111111,password=secret,server-cert-verify-name=verify.example.com`,
		`Surge Hysteria2 Verify Name = hysteria2,hy2-verify.example.com,443,password=secret,server-cert-verify-name='verify.example.com'`,
	}
	for _, input := range verifyCases {
		proxies := ParseText(input)
		if len(proxies) != 1 {
			t.Errorf("expected 1 proxy for %q, got %d", input, len(proxies))
			continue
		}
		if got := proxies[0].GetString("name-cert-verify"); got != "verify.example.com" {
			t.Errorf("name-cert-verify = %q, want verify.example.com (input %q)", got, input)
		}
	}

	// Surge shadow-tls version 1 is rejected
	if proxies := ParseText(`Surge ShadowTLS Invalid = snell,surge-invalid.example.com,443,psk=secret,version=5,shadow-tls-password=shadow-pass,shadow-tls-sni=mask.example.com,shadow-tls-version=1,alpn="h2"`); len(proxies) != 0 {
		t.Errorf("expected 0 proxies for shadow-tls version 1, got %d", len(proxies))
	}
}
