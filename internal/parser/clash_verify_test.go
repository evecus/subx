package parser

import (
	"encoding/json"
	"strings"
	"testing"
)

// checkPipelineSubset is checkSubset with the full Preprocess pipeline
// (mirroring ProxyUtils.parse -> parseAll in the reference helpers).
func checkPipelineSubset(t *testing.T, raw string, want map[string]any) {
	t.Helper()
	proxies := ParseText(Preprocess(raw))
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

// checkPipelineAbsent asserts a top-level key is absent after the full
// Preprocess + ParseText pipeline.
func checkPipelineAbsent(t *testing.T, raw, key string) {
	t.Helper()
	proxies := ParseText(Preprocess(raw))
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	gotB, _ := json.Marshal(proxies[0].Fields())
	var got map[string]any
	if err := json.Unmarshal(gotB, &got); err != nil {
		t.Fatal(err)
	}
	if v, ok := got[key]; ok {
		t.Errorf("expected %q to be absent, got %v", key, v)
	}
}

// TestClashPipeline mirrors the pipeline coverage from Sub-Store's
// pipeline.spec.js.
func TestClashPipeline(t *testing.T) {
	t.Run("base64 subscription", func(t *testing.T) {
		raw := b64(strings.Join([]string{
			"https://alice:pa%24%24@https.example.com#HTTPS%20Default",
			"socks://" + uqe(b64("bob:secret")) + "@socks.example.com:1080#SOCKS",
		}, "\n"))
		proxies := ParseText(Preprocess(raw))
		if len(proxies) != 2 {
			t.Fatalf("expected 2 proxies, got %d", len(proxies))
		}
		wants := []map[string]any{
			{
				"type":     "http",
				"name":     "HTTPS Default",
				"server":   "https.example.com",
				"port":     443,
				"tls":      true,
				"username": "alice",
				"password": "pa$$",
			},
			{
				"type":     "socks5",
				"name":     "SOCKS",
				"server":   "socks.example.com",
				"port":     1080,
				"username": "bob",
				"password": "secret",
			},
		}
		for i, want := range wants {
			gotB, _ := json.Marshal(proxies[i].Fields())
			var got map[string]any
			if err := json.Unmarshal(gotB, &got); err != nil {
				t.Fatal(err)
			}
			for k, v := range want {
				if !deepSubset(got[k], v) {
					t.Errorf("proxy %d key %q = %v, want %v", i, k, got[k], v)
				}
			}
		}
	})

	t.Run("SSD subscription", func(t *testing.T) {
		payload := map[string]any{
			"port":       8388,
			"encryption": "aes-128-gcm",
			"password":   "shared-secret",
			"servers": []any{
				map[string]any{
					"server":         "ssd.example.com",
					"remarks":        "SSD Node",
					"plugin":         "obfs-local",
					"plugin_options": "obfs=http;obfs-host=cdn.example.com",
				},
			},
		}
		b, _ := json.Marshal(payload)
		checkPipelineSubset(t, "ssd://"+b64(string(b)), map[string]any{
			"type":     "ss",
			"name":     "SSD Node",
			"server":   "ssd.example.com",
			"port":     8388,
			"cipher":   "aes-128-gcm",
			"password": "shared-secret",
			"plugin":   "obfs",
			"plugin-opts": map[string]any{
				"mode": "http",
				"host": "cdn.example.com",
			},
		})
	})

	t.Run("[Proxy] block extraction", func(t *testing.T) {
		raw := "[General]\nskip-proxy = 192.168.0.0/16\n\n[Proxy]\nDirect = direct\nHTTP = http,full-config.example.com,8080,username=user,password=pass\n\n[Rule]\nFINAL,DIRECT\n"
		proxies := ParseText(Preprocess(raw))
		if len(proxies) != 2 {
			t.Fatalf("expected 2 proxies, got %d", len(proxies))
		}
		gotB, _ := json.Marshal(proxies[0].Fields())
		var got map[string]any
		_ = json.Unmarshal(gotB, &got)
		if got["type"] != "direct" || got["name"] != "Direct" {
			t.Errorf("first proxy = %v, want {type: direct, name: Direct}", got)
		}
		gotB, _ = json.Marshal(proxies[1].Fields())
		_ = json.Unmarshal(gotB, &got)
		want := map[string]any{
			"type":     "http",
			"name":     "HTTP",
			"server":   "full-config.example.com",
			"port":     8080,
			"username": "user",
			"password": "pass",
		}
		for k, v := range want {
			if !deepSubset(got[k], v) {
				t.Errorf("key %q = %v, want %v", k, got[k], v)
			}
		}
	})

	t.Run("full Clash YAML document", func(t *testing.T) {
		raw := "proxies:\n  - name: clash-vless\n    type: vless\n    server: clash.example.com\n    port: 443\n    uuid: " + vlessTestUUID + "\n    servername: sni.example.com\n    reality-opts:\n      public-key: pubkey\n      short-id: '08'\n  - name: clash-http\n    type: http\n    server: http.clash.example.com\n    port: 8080\n    benchmark-url: https://check.example.com\n    benchmark-timeout: 9\n"
		proxies := ParseText(Preprocess(raw))
		if len(proxies) != 2 {
			t.Fatalf("expected 2 proxies, got %d", len(proxies))
		}
		wants := []map[string]any{
			{
				"type":    "vless",
				"name":    "clash-vless",
				"server":  "clash.example.com",
				"port":    443,
				"uuid":    vlessTestUUID,
				"sni":     "sni.example.com",
				"reality-opts": map[string]any{
					"public-key": "pubkey",
					"short-id":   "08",
				},
			},
			{
				"type":         "http",
				"name":         "clash-http",
				"server":       "http.clash.example.com",
				"port":         8080,
				"test-url":     "https://check.example.com",
				"test-timeout": 9,
			},
		}
		for i, want := range wants {
			gotB, _ := json.Marshal(proxies[i].Fields())
			var got map[string]any
			if err := json.Unmarshal(gotB, &got); err != nil {
				t.Fatal(err)
			}
			for k, v := range want {
				gv, ok := got[k]
				if !ok {
					t.Errorf("proxy %d missing key %q", i, k)
					continue
				}
				if !deepSubset(gv, v) {
					t.Errorf("proxy %d key %q = %v, want %v", i, k, gv, v)
				}
			}
		}
	})

	t.Run("hop-interval range split", func(t *testing.T) {
		checkSubset(t, mustJSON(map[string]any{
			"name":         "hy2-range-inline",
			"type":         "hysteria2",
			"server":       "hy2.example.com",
			"port":         443,
			"password":     "secret",
			"hop-interval": "15-30",
		}), map[string]any{
			"name":             "hy2-range-inline",
			"type":             "hysteria2",
			"hop-interval":     15,
			"hop-interval-max": 30,
		})
	})

	t.Run("invalid vmess cipher defaults to auto", func(t *testing.T) {
		checkSubset(t, mustJSON(map[string]any{
			"name":   "vmess-invalid-cipher",
			"type":   "vmess",
			"server": "vmess.example.com",
			"port":   443,
			"uuid":   vlessTestUUID,
			"cipher": "aes-128-ctr",
		}), map[string]any{
			"type":   "vmess",
			"name":   "vmess-invalid-cipher",
			"cipher": "auto",
		})
	})

	t.Run("invalid hop-interval values dropped", func(t *testing.T) {
		invalidValues := []any{
			"0", 0, "-5", -5, "15.5", 15.5, "15,30", "abc", "",
			"   ", "0-15", "15-0", "30-15", "15-30-45", "15--30",
			true, []any{15, 30}, map[string]any{"min": 15, "max": 30},
		}
		for _, value := range invalidValues {
			line := mustJSON(map[string]any{
				"name":             "hy2-invalid",
				"type":             "hysteria2",
				"server":           "hy2.example.com",
				"port":             443,
				"password":         "secret",
				"hop-interval":     value,
				"hop-interval-max": 999,
			})
			checkPipelineAbsent(t, line, "hop-interval")
			checkPipelineAbsent(t, line, "hop-interval-max")
		}
	})

	t.Run("xudp preferred over packet-addr", func(t *testing.T) {
		checkSubset(t, mustJSON(map[string]any{
			"name":         "vless-legacy-packet-conflict",
			"type":         "vless",
			"server":       "vless.example.com",
			"port":         443,
			"uuid":         vlessTestUUID,
			"xudp":         true,
			"packet-addr":  true,
		}), map[string]any{
			"type":            "vless",
			"name":            "vless-legacy-packet-conflict",
			"packet-encoding": "xudp",
		})
	})

	t.Run("every Clash-supported proxy type", func(t *testing.T) {
		supportedTypes := []string{
			"tailscale", "trusttunnel", "naive", "anytls", "mieru", "masque",
			"sudoku", "juicity", "ss", "ssr", "vmess", "socks5", "http",
			"snell", "trojan", "tuic", "vless", "hysteria", "hysteria2",
			"wireguard", "ssh", "direct",
		}
		for _, typ := range supportedTypes {
			line := mustJSON(map[string]any{
				"name":   typ + "-inline",
				"type":   typ,
				"server": typ + ".example.com",
				"port":   443,
			})
			checkSubset(t, line, map[string]any{
				"name": typ + "-inline",
				"type": typ,
			})
		}
	})

	t.Run("unsupported type rejected", func(t *testing.T) {
		line := mustJSON(map[string]any{
			"name":   "unsupported-inline",
			"type":   "not-a-real-type",
			"server": "zt.example.com",
		})
		proxies := ParseText(line)
		if len(proxies) != 0 {
			t.Fatalf("expected 0 proxies for unsupported type, got %d", len(proxies))
		}
	})
}
