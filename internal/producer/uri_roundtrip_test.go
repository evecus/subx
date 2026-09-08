package producer

import (
	"encoding/base64"
	"strings"
	"testing"

	"substore/internal/parser"
)

// Round-trip checks that prove the URI producers emit correct, parseable
// links after the Sub-Store-aligned rewrite.
func TestURIRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		link string
		want string // substring expected in the produced URI (query params)
	}{
		{
			"vmess-ws",
			"vmess://eyJ2IjoiMiIsInBzIjoiVk0tV1MiLCJhZGQiOiIxLjIuMy40IiwicG9ydCI6ODQ0MywiaWQiOiJhYWFhLWJiYmItY2NjYy1kZGRkLWVlZWUiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiY2RuLmZvby5jb20iLCJwYXRoIjoiL3dzIiwidGxzIjoidGxzIiwic25pIjoiY2RuLmZvby5jb20ifQ==",
			"\"ps\":\"VM-WS\"",
		},
		{
			"vless-reality",
			"vless://aabbccdd-1234-5678-90ab-cdef01234567@1.2.3.4:443?security=reality&type=tcp&sni=www.microsoft.com&fp=chrome&pbk=abc123&sid=01&flow=xtls-rprx-vision#VL-REALITY",
			"pbk=abc123",
		},
		{
			"vless-ws",
			"vless://aabbccdd-1234-5678-90ab-cdef01234567@1.2.3.4:443?security=tls&type=ws&path=%2Fws&host=cdn.foo.com&sni=cdn.foo.com#VL-WS",
			"type=ws",
		},
		{
			"ss-plugin",
			"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388/?plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dwww.bing.com#SS-OBFS",
			"plugin=simple-obfs",
		},
		{
			"hysteria2",
			"hysteria2://pass123@1.2.3.4:443?sni=www.foo.com&insecure=1&obfs=salamander&obfs-password=obfs-pass#HY2",
			"obfs=salamander",
		},
		{
			"hysteria",
			"hysteria://1.2.3.4:443?up=100&down=200&peer=www.foo.com&auth=secret#HY1",
			"upmbps=100",
		},
		{
			"trojan",
			"trojan://pass@1.2.3.4:443?sni=cdn.foo.com#TROJAN",
			"sni=cdn.foo.com",
		},
	}
	for _, c := range cases {
		proxies := parser.ParseText(c.link)
		if len(proxies) != 1 {
			t.Errorf("%s: expected 1 proxy, got %d", c.name, len(proxies))
			continue
		}
		out := ToURI(proxies[0])
		// the produced link must re-parse to exactly one proxy
		again := parser.ParseText(out)
		if len(again) != 1 {
			t.Errorf("%s: produced link does not re-parse: %s", c.name, out)
			continue
		}
		// vmess payload is base64(JSON); decode before substring check
		check := out
		if strings.HasPrefix(out, "vmess://") {
			if b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(out, "vmess://")); err == nil {
				check = string(b)
			}
		}
		if c.want != "" && !strings.Contains(check, c.want) {
			t.Errorf("%s: output missing %q in %s", c.name, c.want, out)
		}
	}
}
