package processor

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"substore/internal/model"
)

// ---- test helpers -----------------------------------------------------------

func resetResolveCache() {
	resolveResourceCache = newTTLCache()
}

func makeProxy(name, server string, port int) *model.Proxy {
	return model.ProxyFromMap(map[string]any{
		"name":   name,
		"type":   "ss",
		"server": server,
		"port":   port,
		"cipher": "aes-128-gcm",
	})
}

// dohTestServer spins up an httptest DoH server. respond receives the decoded
// query and returns the raw wire-format response to send back.
func dohTestServer(t *testing.T, respond func(q *dnsmessage.Message) ([]byte, int)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			t.Errorf("missing ?dns= parameter")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			t.Errorf("invalid base64url dns payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var q dnsmessage.Message
		if err := q.Unpack(raw); err != nil {
			t.Errorf("failed to unpack dns query: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		wire, status := respond(&q)
		w.WriteHeader(status)
		_, _ = w.Write(wire)
	}))
}

// buildAResponse encodes a DNS response carrying A records for the first
// question of the query.
func buildAResponse(q *dnsmessage.Message, ips ...string) []byte {
	name := mustDNSName(q.Questions[0].Name.String())
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               q.ID,
		Response:         true,
		RecursionDesired: true,
		RCode:            dnsmessage.RCodeSuccess,
	})
	_ = b.StartAnswers()
	for _, ip := range ips {
		addr := netip.MustParseAddr(ip)
		a := addr.As4()
		_ = b.AResource(dnsmessage.ResourceHeader{
			Name:  name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		}, dnsmessage.AResource{A: a})
	}
	wire, err := b.Finish()
	if err != nil {
		panic(err)
	}
	return wire
}

func buildAAAAResponse(q *dnsmessage.Message, ips ...string) []byte {
	name := mustDNSName(q.Questions[0].Name.String())
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               q.ID,
		Response:         true,
		RecursionDesired: true,
		RCode:            dnsmessage.RCodeSuccess,
	})
	_ = b.StartAnswers()
	for _, ip := range ips {
		addr := netip.MustParseAddr(ip)
		a := addr.As16()
		_ = b.AAAAResource(dnsmessage.ResourceHeader{
			Name:  name,
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		}, dnsmessage.AAAAResource{AAAA: a})
	}
	wire, err := b.Finish()
	if err != nil {
		panic(err)
	}
	return wire
}

func mustDNSName(domain string) dnsmessage.Name {
	name, err := dnsName(domain)
	if err != nil {
		panic(err)
	}
	return name
}

func runResolveOperator(t *testing.T, args map[string]any, proxies []*model.Proxy) ([]*model.Proxy, error) {
	t.Helper()
	factory, ok := Get("Resolve Domain Operator")
	if !ok {
		t.Fatalf("Resolve Domain Operator not registered")
	}
	proc, err := factory(args, nil)
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}
	return proc(proxies)
}

func findProxy(proxies []*model.Proxy, name string) *model.Proxy {
	for _, p := range proxies {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

// ---- tests ------------------------------------------------------------------

func TestResolveDomainCustomDoH(t *testing.T) {
	resetResolveCache()
	requests := 0
	srv := dohTestServer(t, func(q *dnsmessage.Message) ([]byte, int) {
		requests++
		if len(q.Questions) != 1 {
			t.Errorf("expected 1 question, got %d", len(q.Questions))
		}
		if q.Questions[0].Type != dnsmessage.TypeA {
			t.Errorf("expected A query, got %v", q.Questions[0].Type)
		}
		return buildAResponse(q, "1.2.3.4", "5.6.7.8"), http.StatusOK
	})
	defer srv.Close()

	proxies := []*model.Proxy{
		makeProxy("a", "example.com", 443),
		makeProxy("b", "example.com", 443), // deduplicated
		makeProxy("ip", "9.9.9.9", 443),
		makeProxy("noresolve", "skip.com", 443),
	}
	proxies[3].Set("_no-resolve", true)
	proxies[3].Set("server", "skip.com")

	out, err := runResolveOperator(t, map[string]any{
		"provider": "Custom",
		"url":      srv.URL,
		"type":     "IPv4",
	}, proxies)
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	if requests != 1 {
		t.Fatalf("expected 1 DNS request (dedup), got %d", requests)
	}

	a := findProxy(out, "a")
	if got := a.Server(); got != "1.2.3.4" && got != "5.6.7.8" {
		t.Errorf("a server = %q, want a resolved IP", got)
	}
	if a.GetString("_domain") != "example.com" {
		t.Errorf("a _domain = %q", a.GetString("_domain"))
	}
	if a.GetInt("port") != 443 {
		t.Errorf("a port = %d, want 443", a.GetInt("port"))
	}
	if got, _ := a.Get("_resolved_ips").([]string); len(got) != 2 {
		t.Errorf("a _resolved_ips = %v", a.Get("_resolved_ips"))
	}
	if !isIPStr(a.GetString("_IPv4")) || !isIPStr(a.GetString("_IP")) {
		t.Errorf("a _IPv4=%q _IP=%q", a.GetString("_IPv4"), a.GetString("_IP"))
	}
	if !truthyAny(a.Get("resolved")) {
		t.Errorf("a.resolved should be true")
	}

	// Dedup: b shares the same result fields.
	b := findProxy(out, "b")
	if b.GetString("_domain") != "example.com" {
		t.Errorf("b _domain = %q", b.GetString("_domain"))
	}

	// IP node untouched but marked resolved=false.
	ipNode := findProxy(out, "ip")
	if ipNode.Server() != "9.9.9.9" {
		t.Errorf("ip server changed: %q", ipNode.Server())
	}
	if ipNode.Has("_domain") {
		t.Errorf("ip node should not get _domain")
	}
	if truthyAny(ipNode.Get("resolved")) {
		t.Errorf("ip node resolved should be falsy")
	}

	// _no-resolve node untouched.
	nr := findProxy(out, "noresolve")
	if nr.Server() != "skip.com" {
		t.Errorf("no-resolve server changed: %q", nr.Server())
	}
	if nr.Has("_resolved_ips") {
		t.Errorf("no-resolve node should not have _resolved_ips")
	}
}

func TestResolveDomainCustomDoHFailure(t *testing.T) {
	resetResolveCache()
	srv := dohTestServer(t, func(q *dnsmessage.Message) ([]byte, int) {
		// Respond with a message carrying no answers.
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
			ID: q.ID, Response: true, RCode: dnsmessage.RCodeSuccess,
		})
		wire, _ := b.Finish()
		return wire, http.StatusOK
	})
	defer srv.Close()

	proxies := []*model.Proxy{makeProxy("a", "example.com", 443)}
	out, err := runResolveOperator(t, map[string]any{
		"provider": "Custom",
		"url":      srv.URL,
		"type":     "IPv4",
	}, proxies)
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	p := findProxy(out, "a")
	if p.Server() != "example.com" {
		t.Errorf("server should be unchanged, got %q", p.Server())
	}
	if truthyAny(p.Get("resolved")) {
		t.Errorf("resolved should be false")
	}
	if p.Has("_resolved_ips") {
		t.Errorf("_resolved_ips should not be set")
	}
}

func TestResolveDomainEDNSClientSubnet(t *testing.T) {
	resetResolveCache()
	var gotOption bool
	srv := dohTestServer(t, func(q *dnsmessage.Message) ([]byte, int) {
		gotOption = false
		for _, extra := range q.Additionals {
			if extra.Header.Type != dnsmessage.TypeOPT {
				continue
			}
			opt, ok := extra.Body.(*dnsmessage.OPTResource)
			if !ok {
				continue
			}
			for _, o := range opt.Options {
				if o.Code == 8 && len(o.Data) >= 4 {
					// family=1 (IPv4), source prefix 24, scope 0, 3 addr bytes.
					if o.Data[0] == 0 && o.Data[1] == 1 && o.Data[2] == 24 && o.Data[3] == 0 && len(o.Data) == 7 {
						gotOption = true
					}
				}
			}
		}
		return buildAResponse(q, "1.2.3.4"), http.StatusOK
	})
	defer srv.Close()

	proxies := []*model.Proxy{makeProxy("a", "example.com", 443)}
	_, err := runResolveOperator(t, map[string]any{
		"provider": "Custom",
		"url":      srv.URL,
		"type":     "IPv4",
		"edns":     "9.9.9.9",
	}, proxies)
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	if !gotOption {
		t.Errorf("expected EDNS CLIENT_SUBNET option in query")
	}
}

func TestResolveDomainCacheTTL(t *testing.T) {
	resetResolveCache()
	requests := 0
	srv := dohTestServer(t, func(q *dnsmessage.Message) ([]byte, int) {
		requests++
		return buildAResponse(q, "1.2.3.4"), http.StatusOK
	})
	defer srv.Close()

	args := map[string]any{
		"provider": "Custom",
		"url":      srv.URL,
		"type":     "IPv4",
		"cacheTtl": 60,
	}
	for i := 0; i < 3; i++ {
		proxies := []*model.Proxy{makeProxy("a", "example.com", 443)}
		if _, err := runResolveOperator(t, args, proxies); err != nil {
			t.Fatalf("operator error: %v", err)
		}
	}
	if requests != 1 {
		t.Fatalf("expected cached runs to hit cache, requests = %d", requests)
	}

	// cache=disabled bypasses reads.
	args["cache"] = "disabled"
	proxies := []*model.Proxy{makeProxy("a", "example.com", 443)}
	if _, err := runResolveOperator(t, args, proxies); err != nil {
		t.Fatalf("operator error: %v", err)
	}
	if requests != 2 {
		t.Fatalf("cache=disabled should re-resolve, requests = %d", requests)
	}
}

func TestResolveDomainIP4P(t *testing.T) {
	resetResolveCache()
	srv := dohTestServer(t, func(q *dnsmessage.Message) ([]byte, int) {
		if q.Questions[0].Type != dnsmessage.TypeAAAA {
			t.Errorf("expected AAAA query, got %v", q.Questions[0].Type)
		}
		// 2001::1f90:3c46:5c6e -> port 0x1f90=8080, ip 60.70.92.110
		return buildAAAAResponse(q, "2001::1f90:3c46:5c6e"), http.StatusOK
	})
	defer srv.Close()

	proxies := []*model.Proxy{makeProxy("a", "example.com", 443)}
	out, err := runResolveOperator(t, map[string]any{
		"provider": "Custom",
		"url":      srv.URL,
		"type":     "IP4P",
	}, proxies)
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	p := findProxy(out, "a")
	if p.GetString("_IP4P") != "2001::1f90:3c46:5c6e" {
		t.Errorf("_IP4P = %q", p.GetString("_IP4P"))
	}
	if p.Server() != "60.70.92.110" {
		t.Errorf("server = %q, want 60.70.92.110", p.Server())
	}
	if p.GetInt("port") != 8080 {
		t.Errorf("port = %d, want 8080", p.GetInt("port"))
	}
	if p.GetString("_domain") != "example.com" {
		t.Errorf("_domain = %q", p.GetString("_domain"))
	}
	if p.GetString("_IPv4") != "60.70.92.110" {
		t.Errorf("_IPv4 = %q", p.GetString("_IPv4"))
	}
	if p.GetString("_IP") != "60.70.92.110" {
		t.Errorf("_IP = %q", p.GetString("_IP"))
	}
	if !truthyAny(p.Get("resolved")) {
		t.Errorf("resolved should be true")
	}
}

func TestResolveDomainFilters(t *testing.T) {
	resetResolveCache()
	srv := dohTestServer(t, func(q *dnsmessage.Message) ([]byte, int) {
		name := q.Questions[0].Name.String()
		if strings.HasPrefix(name, "ok.") {
			return buildAResponse(q, "1.2.3.4"), http.StatusOK
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: q.ID, Response: true})
		wire, _ := b.Finish()
		return wire, http.StatusOK
	})
	defer srv.Close()

	baseProxies := func() []*model.Proxy {
		return []*model.Proxy{
			makeProxy("resolved", "ok.example.com", 443),
			makeProxy("failed", "fail.example.com", 443),
			makeProxy("ip", "9.9.9.9", 443),
			makeProxy("noresolve", "skip.example.com", 443),
		}
	}
	proxies := baseProxies()
	proxies[3].Set("_no-resolve", true)

	out, err := runResolveOperator(t, map[string]any{
		"provider": "Custom",
		"url":      srv.URL,
		"type":     "IPv4",
		"filter":   "removeFailed",
	}, proxies)
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	for _, p := range out {
		if p.Name() == "failed" {
			t.Errorf("removeFailed should drop unresolved node")
		}
	}
	if len(out) != 3 {
		t.Errorf("removeFailed kept %d nodes, want 3", len(out))
	}

	out, err = runResolveOperator(t, map[string]any{
		"provider": "Custom",
		"url":      srv.URL,
		"type":     "IPv4",
		"filter":   "IPOnly",
	}, baseProxies())
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	// "resolved" now carries an IP after resolution, so it passes IPOnly too.
	if len(out) != 2 || findProxy(out, "ip") == nil || findProxy(out, "resolved") == nil {
		t.Errorf("IPOnly kept %d nodes, want 'ip' + 'resolved'", len(out))
	}

	out, err = runResolveOperator(t, map[string]any{
		"provider": "Custom",
		"url":      srv.URL,
		"type":     "IPv4",
		"filter":   "IPv4Only",
	}, baseProxies())
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	if len(out) != 2 || findProxy(out, "ip") == nil || findProxy(out, "resolved") == nil {
		t.Errorf("IPv4Only kept %d nodes, want 'ip' + 'resolved'", len(out))
	}

	out, err = runResolveOperator(t, map[string]any{
		"provider": "Custom",
		"url":      srv.URL,
		"type":     "IPv4",
		"filter":   "IPv6Only",
	}, baseProxies())
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("IPv6Only kept %d nodes, want 0", len(out))
	}
}

func TestResolveDomainCustomMultiURLRace(t *testing.T) {
	resetResolveCache()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	good := dohTestServer(t, func(q *dnsmessage.Message) ([]byte, int) {
		return buildAResponse(q, "1.2.3.4"), http.StatusOK
	})
	defer good.Close()

	proxies := []*model.Proxy{makeProxy("a", "example.com", 443)}
	out, err := runResolveOperator(t, map[string]any{
		"provider": "Custom",
		"url":      bad.URL + "\n" + good.URL,
		"type":     "IPv4",
	}, proxies)
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	p := findProxy(out, "a")
	if p.Server() != "1.2.3.4" {
		t.Errorf("server = %q, want 1.2.3.4 (raced past failing DNS)", p.Server())
	}
}

func TestResolveDomainCustomUDPAndTCP(t *testing.T) {
	resetResolveCache()

	// UDP DNS server.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if err := q.Unpack(buf[:n]); err != nil {
				continue
			}
			wire := buildAResponse(&q, "10.0.0.1")
			_, _ = pc.WriteTo(wire, addr)
		}
	}()
	udpAddr := pc.LocalAddr().String()

	// TCP DNS server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 2)
				if _, err := readFull(c, buf); err != nil {
					return
				}
				length := int(buf[0])<<8 | int(buf[1])
				msg := make([]byte, length)
				if _, err := readFull(c, msg); err != nil {
					return
				}
				var q dnsmessage.Message
				if err := q.Unpack(msg); err != nil {
					return
				}
				resp := buildAResponse(&q, "10.0.0.2")
				out := make([]byte, 2+len(resp))
				out[0] = byte(len(resp) >> 8)
				out[1] = byte(len(resp))
				copy(out[2:], resp)
				_, _ = c.Write(out)
			}(conn)
		}
	}()
	tcpAddr := ln.Addr().String()

	// Each transport is exercised with a single-URL Custom provider so the
	// result is deterministic (with multiple URLs the first success wins).
	udpProxies := []*model.Proxy{makeProxy("udp", "example.com", 443)}
	out, err := runResolveOperator(t, map[string]any{
		"provider": "Custom",
		"url":      "udp://" + udpAddr,
		"type":     "IPv4",
	}, udpProxies)
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	if p := findProxy(out, "udp"); p.Server() != "10.0.0.1" {
		t.Errorf("udp server = %q, want 10.0.0.1", p.Server())
	}

	tcpProxies := []*model.Proxy{makeProxy("tcp", "example.org", 443)}
	out, err = runResolveOperator(t, map[string]any{
		"provider": "Custom",
		"url":      "tcp://" + tcpAddr,
		"type":     "IPv4",
	}, tcpProxies)
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	if p := findProxy(out, "tcp"); p.Server() != "10.0.0.2" {
		t.Errorf("tcp server = %q, want 10.0.0.2", p.Server())
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func TestResolveDomainAliTencentIPAPI(t *testing.T) {
	resetResolveCache()

	aliSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("name") != "example.com" || q.Get("type") != "A" || q.Get("short") != "1" {
			t.Errorf("ali query params: %v", r.URL.RawQuery)
		}
		if r.Header.Get("accept") != "application/dns-json" {
			t.Errorf("ali accept header: %q", r.Header.Get("accept"))
		}
		if !strings.HasPrefix(q.Get("edns_client_subnet"), "9.9.9.9/24") {
			t.Errorf("ali edns_client_subnet: %q", q.Get("edns_client_subnet"))
		}
		_, _ = w.Write([]byte(`["1.2.3.4","5.6.7.8"]`))
	}))
	defer aliSrv.Close()
	oldAli := aliDNSURL
	aliDNSURL = aliSrv.URL
	defer func() { aliDNSURL = oldAli }()

	proxies := []*model.Proxy{makeProxy("a", "example.com", 443)}
	out, err := runResolveOperator(t, map[string]any{
		"provider": "Ali",
		"type":     "IPv4",
		"edns":     "9.9.9.9",
	}, proxies)
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	p := findProxy(out, "a")
	if p.Server() != "1.2.3.4" && p.Server() != "5.6.7.8" {
		t.Errorf("ali server = %q", p.Server())
	}
	if got, _ := p.Get("_resolved_ips").([]string); len(got) != 2 {
		t.Errorf("ali _resolved_ips = %v", p.Get("_resolved_ips"))
	}

	resetResolveCache()
	tencentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("dn") != "example.com" || q.Get("type") != "A" {
			t.Errorf("tencent query params: %v", r.URL.RawQuery)
		}
		if !strings.HasPrefix(q.Get("ip"), "9.9.9.9") {
			t.Errorf("tencent ip param: %q", q.Get("ip"))
		}
		_, _ = w.Write([]byte(`1.2.3.4,30;5.6.7.8,30`))
	}))
	defer tencentSrv.Close()
	oldTencent := tencentDNSURL
	tencentDNSURL = tencentSrv.URL
	defer func() { tencentDNSURL = oldTencent }()

	proxies = []*model.Proxy{makeProxy("a", "example.com", 443)}
	out, err = runResolveOperator(t, map[string]any{
		"provider": "Tencent",
		"type":     "IPv4",
		"edns":     "9.9.9.9",
	}, proxies)
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	p = findProxy(out, "a")
	if p.Server() != "1.2.3.4" && p.Server() != "5.6.7.8" {
		t.Errorf("tencent server = %q", p.Server())
	}

	resetResolveCache()
	ipapiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/example.com") {
			t.Errorf("ip-api path: %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"status":"success","query":"1.2.3.4"}`))
	}))
	defer ipapiSrv.Close()
	oldIPAPI := ipAPIURL
	ipAPIURL = ipapiSrv.URL
	defer func() { ipAPIURL = oldIPAPI }()

	proxies = []*model.Proxy{makeProxy("a", "example.com", 443)}
	out, err = runResolveOperator(t, map[string]any{
		"provider": "IP-API",
		"type":     "IPv4",
	}, proxies)
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	p = findProxy(out, "a")
	if p.Server() != "1.2.3.4" {
		t.Errorf("ip-api server = %q", p.Server())
	}
}

func TestResolveDomainGoogleCloudflare(t *testing.T) {
	resetResolveCache()

	gSrv := dohTestServer(t, func(q *dnsmessage.Message) ([]byte, int) {
		return buildAResponse(q, "1.2.3.4"), http.StatusOK
	})
	defer gSrv.Close()
	oldGoogle := googleDoHURL
	googleDoHURL = gSrv.URL
	defer func() { googleDoHURL = oldGoogle }()

	cfSrv := dohTestServer(t, func(q *dnsmessage.Message) ([]byte, int) {
		return buildAResponse(q, "5.6.7.8"), http.StatusOK
	})
	defer cfSrv.Close()
	oldCF := cloudflareDoHUR
	cloudflareDoHUR = cfSrv.URL
	defer func() { cloudflareDoHUR = oldCF }()

	proxies := []*model.Proxy{
		makeProxy("g", "example.com", 443),
		makeProxy("cf", "example.org", 443),
	}
	out, err := runResolveOperator(t, map[string]any{
		"provider": "Google",
		"type":     "IPv4",
	}, proxies)
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	if p := findProxy(out, "g"); p.Server() != "1.2.3.4" {
		t.Errorf("google server = %q", p.Server())
	}

	proxies = []*model.Proxy{makeProxy("cf", "example.org", 443)}
	out, err = runResolveOperator(t, map[string]any{
		"provider": "Cloudflare",
		"type":     "IPv4",
	}, proxies)
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	if p := findProxy(out, "cf"); p.Server() != "5.6.7.8" {
		t.Errorf("cloudflare server = %q", p.Server())
	}
}

func TestResolveDomainConcurrency(t *testing.T) {
	resetResolveCache()
	srv := dohTestServer(t, func(q *dnsmessage.Message) ([]byte, int) {
		return buildAResponse(q, "1.2.3.4"), http.StatusOK
	})
	defer srv.Close()

	proxies := make([]*model.Proxy, 0, 30)
	for i := 0; i < 30; i++ {
		proxies = append(proxies, makeProxy(fmt.Sprintf("n%d", i), fmt.Sprintf("n%d.example.com", i), 443))
	}
	out, err := runResolveOperator(t, map[string]any{
		"provider":    "Custom",
		"url":         srv.URL,
		"type":        "IPv4",
		"concurrency": 5,
	}, proxies)
	if err != nil {
		t.Fatalf("operator error: %v", err)
	}
	if len(out) != 30 {
		t.Fatalf("kept %d nodes, want 30", len(out))
	}
	for _, p := range out {
		if p.Server() != "1.2.3.4" {
			t.Errorf("%s server = %q", p.Name(), p.Server())
		}
	}
}

func TestResolveDomainInvalidConfig(t *testing.T) {
	resetResolveCache()
	cases := []map[string]any{
		{"provider": "Unknown"},
		{"provider": "IP-API", "type": "IPv6"},
		{"provider": "IP-API", "type": "IP4P"},
		{"provider": "Custom", "url": "   "},
		{"provider": "Google", "edns": "not-an-ip"},
		{"provider": "Google", "concurrency": 0},
		{"provider": "Google", "concurrency": "abc"},
		{"provider": "Google", "timeout": 0},
		{"provider": "Google", "cacheTtl": 0},
		// dnsConcurrency is only validated for the Custom provider (like the original).
		{"provider": "Custom", "url": "https://1.1.1.1/dns-query", "dnsConcurrency": -1},
	}
	for i, args := range cases {
		proc := resolveDomainOperator(args)
		_, err := proc(nil)
		if err == nil {
			t.Errorf("case %d: expected error for args %v", i, args)
		}
	}
}

func TestResolveDomainDefaultEdns(t *testing.T) {
	resetResolveCache()
	var sawSubnetParam bool
	aliSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Query().Get("edns_client_subnet"), defaultEdnsSubnet) {
			sawSubnetParam = true
		}
		_, _ = w.Write([]byte(`["1.2.3.4"]`))
	}))
	defer aliSrv.Close()
	oldAli := aliDNSURL
	aliDNSURL = aliSrv.URL
	defer func() { aliDNSURL = oldAli }()

	proxies := []*model.Proxy{makeProxy("a", "example.com", 443)}
	if _, err := runResolveOperator(t, map[string]any{"provider": "Ali"}, proxies); err != nil {
		t.Fatalf("operator error: %v", err)
	}
	if !sawSubnetParam {
		t.Errorf("expected default edns %s to be used", defaultEdnsSubnet)
	}
}

func TestParseDnsResolver(t *testing.T) {
	cases := []struct {
		raw      string
		protocol string
		host     string
		port     int
		wantErr  bool
	}{
		{raw: "https://dns.google/dns-query", protocol: "doh"},
		{raw: "http://1.1.1.1/dns-query", protocol: "doh"},
		{raw: "1.1.1.1", protocol: "udp", host: "1.1.1.1", port: 53},
		{raw: "udp://1.1.1.1:5353", protocol: "udp", host: "1.1.1.1", port: 5353},
		{raw: "tcp://1.1.1.1", protocol: "tcp", host: "1.1.1.1", port: 53},
		{raw: "tls://1.1.1.1", protocol: "tls", host: "1.1.1.1", port: 853},
		{raw: "quic://1.1.1.1", wantErr: true},
		{raw: "udp://1.1.1.1/path", wantErr: true},
		{raw: "udp://1.1.1.1?x=1", wantErr: true},
		{raw: "", wantErr: true},
	}
	for _, c := range cases {
		got, err := parseDnsResolver(c.raw)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseDnsResolver(%q) expected error", c.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDnsResolver(%q) unexpected error: %v", c.raw, err)
			continue
		}
		if got.protocol != c.protocol {
			t.Errorf("parseDnsResolver(%q) protocol = %q, want %q", c.raw, got.protocol, c.protocol)
		}
		if c.host != "" && got.host != c.host {
			t.Errorf("parseDnsResolver(%q) host = %q, want %q", c.raw, got.host, c.host)
		}
		if c.port != 0 && got.port != c.port {
			t.Errorf("parseDnsResolver(%q) port = %d, want %d", c.raw, got.port, c.port)
		}
	}
}
