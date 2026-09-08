package producer

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"substore/internal/model"
)

func decVmessPayload(t *testing.T, uri string) map[string]any {
	t.Helper()
	payload := strings.TrimPrefix(strings.TrimSpace(uri), "vmess://")
	dec, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode vmess payload: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(dec, &obj); err != nil {
		t.Fatalf("unmarshal vmess payload: %v", err)
	}
	return obj
}

func newVmess(name string) *model.Proxy {
	p := model.NewProxy()
	p.Set("type", "vmess")
	p.Set("name", name)
	p.Set("server", "1.2.3.4")
	p.Set("port", 443)
	p.Set("uuid", "00000000-0000-0000-0000-000000000000")
	p.Set("cipher", "auto")
	return p
}

// Item 1: vmess with empty transport values must omit host/path keys while
// keeping the literal keys (v/ps/add/port/id/aid/scy/net/tls/type).
func TestP2VmessOmitsEmptyTransportKeys(t *testing.T) {
	p := newVmess("plain")
	uri, err := ProduceURI([]*model.Proxy{p}, nil)
	if err != nil {
		t.Fatalf("ProduceURI: %v", err)
	}
	obj := decVmessPayload(t, uri)
	for _, key := range []string{"v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "tls"} {
		if _, ok := obj[key]; !ok {
			t.Errorf("vmess JSON missing literal key %q: %v", key, obj)
		}
	}
	for _, key := range []string{"host", "path", "sni", "fp", "alpn"} {
		if _, ok := obj[key]; ok {
			t.Errorf("vmess JSON should omit empty %q: %v", key, obj)
		}
	}

	// grpc without service-name/authority: path/host omitted, type=gun kept.
	g := newVmess("grpc")
	g.Set("network", "grpc")
	g.Set("grpc-opts", map[string]any{})
	uri2, err := ProduceURI([]*model.Proxy{g}, nil)
	if err != nil {
		t.Fatalf("ProduceURI grpc: %v", err)
	}
	obj2 := decVmessPayload(t, uri2)
	if _, ok := obj2["path"]; ok {
		t.Errorf("grpc vmess should omit empty path: %v", obj2)
	}
	if _, ok := obj2["host"]; ok {
		t.Errorf("grpc vmess should omit empty host: %v", obj2)
	}
	if obj2["type"] != "gun" {
		t.Errorf("grpc vmess type = %v, want gun", obj2["type"])
	}
}

// Item 2: hysteria numeric params must render like JS ToString, not 1e+06.
func TestP2HysteriaNumericParams(t *testing.T) {
	p := model.NewProxy()
	p.Set("type", "hysteria")
	p.Set("name", "h1")
	p.Set("server", "1.2.3.4")
	p.Set("port", 443)
	p.Set("auth-str", "pass")
	p.Set("up", float64(1000000))
	p.Set("down", json.Number("2000000"))
	uri, err := ProduceURI([]*model.Proxy{p}, nil)
	if err != nil {
		t.Fatalf("ProduceURI: %v", err)
	}
	if !strings.Contains(uri, "upmbps=1000000") {
		t.Errorf("hysteria uri missing upmbps=1000000: %s", uri)
	}
	if !strings.Contains(uri, "downmbps=2000000") {
		t.Errorf("hysteria uri missing downmbps=2000000: %s", uri)
	}
	if strings.Contains(uri, "e+06") {
		t.Errorf("hysteria uri leaks scientific notation: %s", uri)
	}
}

// Item 3: anytls output must not carry a uuid parameter.
func TestP2AnytlsNoUUIDParam(t *testing.T) {
	p := model.NewProxy()
	p.Set("type", "anytls")
	p.Set("name", "a1")
	p.Set("server", "1.2.3.4")
	p.Set("port", 443)
	p.Set("password", "secret")
	p.Set("skip-cert-verify", true)
	uri, err := ProduceURI([]*model.Proxy{p}, nil)
	if err != nil {
		t.Fatalf("ProduceURI: %v", err)
	}
	if strings.Contains(uri, "uuid=") {
		t.Errorf("anytls uri should not contain uuid=: %s", uri)
	}
	if !strings.HasPrefix(strings.TrimSpace(uri), "anytls://") {
		t.Errorf("anytls uri prefix wrong: %s", uri)
	}
}

// Item 4: _vcn present but not an array falls back to name-cert-verify.
func TestP2VcnFallbackToNameCertVerify(t *testing.T) {
	for _, typ := range []string{"vless", "trojan"} {
		p := model.NewProxy()
		p.Set("type", typ)
		p.Set("name", "n1")
		p.Set("server", "1.2.3.4")
		p.Set("port", 443)
		p.Set("uuid", "00000000-0000-0000-0000-000000000000")
		p.Set("password", "pw")
		p.Set("_vcn", "not-an-array")
		p.Set("name-cert-verify", "mycert")
		uri, err := ProduceURI([]*model.Proxy{p}, nil)
		if err != nil {
			t.Fatalf("%s ProduceURI: %v", typ, err)
		}
		if !strings.Contains(uri, "vcn=mycert") {
			t.Errorf("%s uri should fall back to name-cert-verify: %s", typ, uri)
		}
	}
}

// Item 5a: h2-opts headers.Host arrays must be preserved as arrays.
func TestP2ClashH2HostArrayKept(t *testing.T) {
	p := newVmess("h2")
	p.Set("network", "h2")
	p.Set("h2-opts", map[string]any{
		"host":    []any{"a.com", "b.com"},
		"path":    "/",
	})
	list := clashMapProxies([]*model.Proxy{p}, nil, clashPlatformMeta, "external")
	if len(list) != 1 {
		t.Fatalf("expected 1 mapped proxy, got %d", len(list))
	}
	h2Opts, ok := list[0]["h2-opts"].(map[string]any)
	if !ok {
		t.Fatalf("h2-opts missing: %v", list[0])
	}
	host, ok := h2Opts["host"].([]any)
	if !ok {
		t.Fatalf("h2 host should stay an array, got %T %v", h2Opts["host"], h2Opts["host"])
	}
	if len(host) != 2 || host[0] != "a.com" || host[1] != "b.com" {
		t.Errorf("h2 host array corrupted: %v", host)
	}
}

// Item 5b: ws-opts.v2ray-http-upgrade uses truthiness (string "true" counts).
func TestP2ClashWSUpgradeTruthy(t *testing.T) {
	p := newVmess("ws")
	p.Set("network", "ws")
	p.Set("ws-opts", map[string]any{"v2ray-http-upgrade": "true"})
	if clashFilterOriginal(p) {
		t.Errorf("clash filter should reject truthy string v2ray-http-upgrade")
	}
	if clashFilterStash(p) {
		t.Errorf("stash filter should reject truthy string v2ray-http-upgrade")
	}
}

// Item 5c: hysteria auth_str is copied to auth-str but kept in the output.
func TestP2HysteriaAuthStrKept(t *testing.T) {
	p := model.NewProxy()
	p.Set("type", "hysteria")
	p.Set("name", "h1")
	p.Set("server", "1.2.3.4")
	p.Set("port", 443)
	p.Set("auth_str", "pass123")
	clashMapProxies([]*model.Proxy{p}, nil, clashPlatformMeta, "external")
	if p.GetString("auth-str") != "pass123" {
		t.Errorf("auth-str not set from auth_str: %v", p.Get("auth-str"))
	}
	if p.Get("auth_str") == nil {
		t.Errorf("auth_str should be kept (clashmeta.js:221-226)")
	}
}

// Item 5d: meta internal output keeps underscore fields unless the
// delete-underscore-fields option is set.
func TestP2MetaInternalUnderscoreFields(t *testing.T) {
	p := newVmess("u1")
	p.Set("_subName", "sub-a")

	clashMapProxies([]*model.Proxy{p.Clone()}, nil, clashPlatformMeta, "internal")
	// the call above maps in place on a clone; verify via returned list
	p2 := newVmess("u2")
	p2.Set("_subName", "sub-a")
	list := clashMapProxies([]*model.Proxy{p2}, nil, clashPlatformMeta, "internal")
	if len(list) != 1 {
		t.Fatalf("expected 1 mapped proxy, got %d", len(list))
	}
	if _, ok := list[0]["_subName"]; !ok {
		t.Errorf("internal meta output should keep underscore fields")
	}

	p3 := newVmess("u3")
	p3.Set("_subName", "sub-a")
	list2 := clashMapProxies([]*model.Proxy{p3}, map[string]any{"delete-underscore-fields": true}, clashPlatformMeta, "internal")
	if len(list2) != 1 {
		t.Fatalf("expected 1 mapped proxy, got %d", len(list2))
	}
	if _, ok := list2[0]["_subName"]; ok {
		t.Errorf("delete-underscore-fields should drop underscore fields")
	}
}

// Item 5e: snell with obfs-opts mode shadow-tls (no plugin) also goes
// through getMihomoShadowTlsOpts on meta.
func TestP2SnellObfsShadowTlsRebuild(t *testing.T) {
	p := model.NewProxy()
	p.Set("type", "snell")
	p.Set("name", "s1")
	p.Set("server", "1.2.3.4")
	p.Set("port", 443)
	p.Set("psk", "key")
	p.Set("version", 2)
	p.Set("obfs-opts", map[string]any{
		"mode":     "shadow-tls",
		"host":     "example.com",
		"password": "pw",
		"version":  3,
	})
	list := clashMapProxies([]*model.Proxy{p}, nil, clashPlatformMeta, "external")
	if len(list) != 1 {
		t.Fatalf("expected 1 mapped proxy, got %d", len(list))
	}
	if _, ok := list[0]["plugin"]; ok {
		t.Errorf("plugin should be deleted")
	}
	if _, ok := list[0]["plugin-opts"]; ok {
		t.Errorf("plugin-opts should be deleted")
	}
	obfs, ok := list[0]["obfs-opts"].(map[string]any)
	if !ok {
		t.Fatalf("obfs-opts missing: %v", list[0])
	}
	if obfs["mode"] != "shadow-tls" || obfs["host"] != "example.com" || obfs["password"] != "pw" {
		t.Errorf("obfs-opts not rebuilt from shadow-tls source: %v", obfs)
	}
}

// Item 6: JSON output must not HTML-escape <, >, &.
func TestP2JSONNoHTMLEscape(t *testing.T) {
	p := model.NewProxy()
	p.Set("type", "ss")
	p.Set("name", "<a>&b")
	p.Set("server", "1.2.3.4")
	p.Set("port", 443)
	p.Set("cipher", "aes-256-cfb")
	p.Set("password", "pw")
	out, err := ProduceJSON([]*model.Proxy{p}, nil)
	if err != nil {
		t.Fatalf("ProduceJSON: %v", err)
	}
	if strings.Contains(out, "\\u003c") || strings.Contains(out, "\\u003e") || strings.Contains(out, "\\u0026") {
		t.Errorf("JSON output must not HTML-escape: %s", out)
	}
	if !strings.Contains(out, "<a>&b") {
		t.Errorf("JSON output lost raw characters: %s", out)
	}
}

// Item 7: surfboard hysteria2 skips empty obfs-password.
func TestP2SurfboardHysteria2EmptyObfsPassword(t *testing.T) {
	p := model.NewProxy()
	p.Set("type", "hysteria2")
	p.Set("name", "h2")
	p.Set("server", "1.2.3.4")
	p.Set("port", 443)
	p.Set("password", "pw")
	p.Set("obfs", "salamander")
	p.Set("obfs-password", "")
	out, err := ProduceSurfboard([]*model.Proxy{p}, nil)
	if err != nil {
		t.Fatalf("ProduceSurfboard: %v", err)
	}
	if strings.Contains(out, "salamander-password") {
		t.Errorf("empty obfs-password must not emit salamander-password: %s", out)
	}
}
