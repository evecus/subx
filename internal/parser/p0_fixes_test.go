package parser

import (
	"strings"
	"testing"
)

// Regression tests for the P0 fixes (see subx audit report).
func TestP0FixesTmp(t *testing.T) {
	// 1. ss plugin=simple-obfs without obfs-host must not panic
	line := "ss://YWVzLTI1Ni1nY206dGVzdA==@1.2.3.4:8388?plugin=" + percentEncode("simple-obfs;obfs=http") + "#test"
	proxies := ParseText(line)
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	if got := proxies[0].GetString("plugin"); got != "obfs" {
		t.Fatalf("plugin = %q, want obfs", got)
	}
	if _, ok := proxies[0].GetMap("plugin-opts")["host"]; ok {
		t.Fatalf("unexpected host in plugin-opts")
	}

	// 2. hysteria1: missing port defaults to 443, trailing slash tolerated
	for _, l := range []string{"hy://1.2.3.4?auth=x#h1", "hysteria://1.2.3.4:443/?auth=x#h2"} {
		ps := ParseText(l)
		if len(ps) != 1 {
			t.Fatalf("%s: expected 1 proxy, got %d", l, len(ps))
		}
		if ps[0].GetInt("port") != 443 {
			t.Fatalf("%s: port = %v, want 443", l, ps[0].Get("port"))
		}
	}

	// 3. anytls reuses the VLESS parser: sni/reality survive
	ps := ParseText("anytls://pass@1.2.3.4:443?sni=example.com&pbk=PUBKEY&sid=ab#at")
	if len(ps) != 1 {
		t.Fatalf("anytls: expected 1 proxy, got %d", len(ps))
	}
	p := ps[0]
	if p.Type() != "anytls" || p.GetString("sni") != "example.com" || p.GetString("password") != "pass" {
		t.Fatalf("anytls fields wrong: type=%s sni=%s", p.Type(), p.GetString("sni"))
	}
	reality := p.GetMap("reality-opts")
	if reality == nil || reality["public-key"] != "PUBKEY" || reality["short-id"] != "ab" {
		t.Fatalf("anytls reality-opts = %v", reality)
	}

	// 4. ssr accepts both protoparam and protocolparam aliases
	inner := "1.2.3.4:443:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:cGFzcw==/?remarks=" + b64ForTest("n") + "&"
	psr := ParseText("ssr://" + base64Std(inner+"protoparam="+b64ForTest("123:abc")))
	if len(psr) != 1 || psr[0].GetString("protocol-param") != "123:abc" {
		t.Fatalf("ssr protoparam alias failed: %+v", psr)
	}
	psr = ParseText("ssr://" + base64Std(inner+"protocolparam="+b64ForTest("456:def")))
	if len(psr) != 1 || psr[0].GetString("protocol-param") != "456:def" {
		t.Fatalf("ssr protocolparam alias failed: %+v", psr)
	}
}

func b64ForTest(s string) string {
	return strings.TrimRight(base64Std(s), "=")
}

func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteString("%")
			const hexDigits = "0123456789ABCDEF"
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0xF])
		}
	}
	return b.String()
}
