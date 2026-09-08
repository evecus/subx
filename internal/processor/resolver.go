package processor

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Resolve Domain helpers, mirroring the original implementation in
// Sub-Store-master/backend/src/core/proxy-utils/processors/index.js
// (DOMAIN_RESOLVERS, resourceCache and related helpers).

const (
	defaultResolveDomainConcurrency         = 10
	defaultResolveDomainCustomDNSConcurrency = 2
	resolveDomainConcurrencyWarnThreshold   = 20
	defaultResolveDomainTimeoutMS           = 8000
	defaultResolveCacheTTL                  = time.Hour // DEFAULT_CACHE_TTL in constants.js
)

// ---- resource cache (TTL) -------------------------------------------------

type ttlEntry struct {
	expiresAt time.Time
	data      any
}

type ttlCache struct {
	mu      sync.Mutex
	entries map[string]ttlEntry
}

func newTTLCache() *ttlCache {
	return &ttlCache{entries: map[string]ttlEntry{}}
}

func (c *ttlCache) get(id string) any {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if !ok {
		return nil
	}
	if time.Now().After(e.expiresAt) {
		delete(c.entries, id)
		return nil
	}
	return e.data
}

func (c *ttlCache) set(id string, data any, ttl time.Duration) {
	if ttl <= 0 {
		ttl = defaultResolveCacheTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[id] = ttlEntry{expiresAt: time.Now().Add(ttl), data: data}
}

// resolveResourceCache mirrors the original singleton resourceCache.
var resolveResourceCache = newTTLCache()

// customDNSResult mirrors packCustomDnsCachedResult: { result, resolverUrl }.
type customDNSResult struct {
	Result      []string
	ResolverURL string
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ---- normalized helpers ----------------------------------------------------

func isIPv4Str(s string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	return err == nil && addr.Is4()
}

func isIPv6Str(s string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	return err == nil && addr.Is6()
}

func isIPStr(s string) bool {
	_, err := netip.ParseAddr(strings.TrimSpace(s))
	return err == nil
}

func normalizeResolveDomainConcurrency(concurrency any) (int, error) {
	if s, ok := concurrency.(string); ok && strings.TrimSpace(s) == "" {
		concurrency = nil
	}
	if concurrency == nil {
		return defaultResolveDomainConcurrency, nil
	}
	parsed, err := toIntStrict(concurrency)
	if err != nil || parsed < 1 {
		return 0, errors.New("域名解析并发数应为大于 0 的整数")
	}
	return parsed, nil
}

func normalizeResolveDomainCustomDNSConcurrency(concurrency any) (int, error) {
	if s, ok := concurrency.(string); ok && strings.TrimSpace(s) == "" {
		concurrency = nil
	}
	if concurrency == nil {
		return defaultResolveDomainCustomDNSConcurrency, nil
	}
	parsed, err := toIntStrict(concurrency)
	if err != nil || parsed < 1 {
		return 0, errors.New("多 DNS 并发数应为大于 0 的整数")
	}
	return parsed, nil
}

// normalizeResolveDomainTimeout returns the request timeout in milliseconds.
func normalizeResolveDomainTimeout(timeout any) (int, error) {
	if s, ok := timeout.(string); ok && strings.TrimSpace(s) == "" {
		timeout = nil
	}
	if timeout == nil {
		return defaultResolveDomainTimeoutMS, nil
	}
	parsed, err := toIntStrict(timeout)
	if err != nil || parsed < 1 {
		return 0, errors.New("DNS 超时应为大于 0 的整数")
	}
	return parsed, nil
}

// normalizeResolveDomainCacheTtl returns the cache TTL in seconds (0 when unset).
func normalizeResolveDomainCacheTtl(cacheTtl any) (int, error) {
	if s, ok := cacheTtl.(string); ok && strings.TrimSpace(s) == "" {
		cacheTtl = nil
	}
	if cacheTtl == nil {
		return 0, nil
	}
	parsed, err := toIntStrict(cacheTtl)
	if err != nil || parsed < 1 {
		return 0, errors.New("域名解析缓存时长应为大于 0 的整数")
	}
	return parsed, nil
}

func toIntStrict(v any) (int, error) {
	switch t := v.(type) {
	case int:
		return t, nil
	case int64:
		return int(t), nil
	case float64:
		if t != float64(int(t)) {
			return 0, fmt.Errorf("not an integer: %v", t)
		}
		return int(t), nil
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			return 0, err
		}
		return int(n), nil
	case string:
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(t), "%d", &n); err != nil {
			return 0, err
		}
		return n, nil
	}
	return 0, fmt.Errorf("not an integer: %v", v)
}

func parseCustomDnsUrls(rawURL string) ([]string, error) {
	var urls []string
	for _, item := range strings.Split(rawURL, "\n") {
		item = strings.TrimSpace(item)
		if item != "" {
			urls = append(urls, item)
		}
	}
	if len(urls) == 0 {
		return nil, errors.New("自定义 DNS 不能为空")
	}
	return urls, nil
}

func normalizeCustomDnsUrlList(rawURL string) (string, error) {
	urls, err := parseCustomDnsUrls(rawURL)
	if err != nil {
		return "", err
	}
	return strings.Join(urls, "\n"), nil
}

// ---- concurrency helpers ---------------------------------------------------

type resolveTask struct {
	id     string
	domain string
}

func resolveDomainsWithConcurrency(tasks []resolveTask, concurrency int, fn func(resolveTask)) {
	if len(tasks) == 0 {
		return
	}
	workers := concurrency
	if workers > len(tasks) {
		workers = len(tasks)
	}
	if workers < 1 {
		workers = 1
	}
	ch := make(chan resolveTask)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range ch {
				fn(t)
			}
		}()
	}
	for _, t := range tasks {
		ch <- t
	}
	close(ch)
	wg.Wait()
}

// resolveWithCustomDNSConcurrency races the given resolver URLs with the given
// concurrency and returns the first successful result, mirroring
// resolveWithCustomDnsConcurrency in the original.
func resolveWithCustomDNSConcurrency(urls []string, concurrency int, fn func(string) ([]string, error)) ([]string, string, error) {
	if len(urls) == 0 {
		return nil, "", errors.New("No answers")
	}
	workers := concurrency
	if workers > len(urls) {
		workers = len(urls)
	}
	if workers < 1 {
		workers = 1
	}
	type outcome struct {
		idx int
		ips []string
		err error
	}
	taskCh := make(chan int)
	outCh := make(chan outcome, len(urls))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range taskCh {
				ips, err := fn(urls[idx])
				outCh <- outcome{idx: idx, ips: ips, err: err}
			}
		}()
	}
	for idx := range urls {
		taskCh <- idx
	}
	close(taskCh)
	go func() {
		wg.Wait()
		close(outCh)
	}()

	finished := 0
	var errs []string
	for out := range outCh {
		finished++
		if out.err == nil {
			return out.ips, urls[out.idx], nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", urls[out.idx], out.err))
		if finished == len(urls) {
			break
		}
	}
	if len(errs) > 0 {
		return nil, "", errors.New(strings.Join(errs, "; "))
	}
	return nil, "", errors.New("No answers")
}

// ---- custom DNS resolver url parsing (parseDnsResolver in dns.js) ----------

type dnsServerURL struct {
	protocol string // "doh" | "udp" | "tcp" | "tls"
	url      string // for doh
	host     string
	port     int
}

const dnsDefaultPort = 53
const dnsTLsDefaultPort = 853

func parseDnsResolver(raw string) (*dnsServerURL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("自定义 DNS 不能为空")
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") {
		return &dnsServerURL{protocol: "doh", url: raw}, nil
	}
	protocol := ""
	if m := splitScheme(raw); m != "" {
		protocol = strings.ToLower(m)
		if protocol != "udp" && protocol != "tcp" && protocol != "tls" {
			return nil, fmt.Errorf("自定义 DNS 不支持 %s 协议", m)
		}
	}
	value := raw
	if protocol == "" {
		if isIPv6Str(raw) {
			value = "udp://[" + raw + "]"
		} else {
			value = "udp://" + raw
		}
		protocol = "udp"
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("自定义 DNS 地址格式无效: %s", raw)
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("自定义 DNS 地址格式无效: %s", raw)
	}
	host := u.Hostname()
	defaultPort := dnsDefaultPort
	if protocol == "tls" {
		defaultPort = dnsTLsDefaultPort
	}
	port := defaultPort
	if p := u.Port(); p != "" {
		port = 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil, fmt.Errorf("自定义 DNS 端口号应为 1-65535 的整数")
			}
			port = port*10 + int(c-'0')
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("自定义 DNS 端口号应为 1-65535 的整数")
		}
	}
	return &dnsServerURL{protocol: protocol, host: host, port: port}, nil
}

func splitScheme(raw string) string {
	idx := strings.Index(raw, "://")
	if idx <= 0 {
		return ""
	}
	scheme := raw[:idx]
	for _, c := range scheme {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'
		if !ok {
			return ""
		}
	}
	return scheme
}

// resolveDnsURL mirrors resolveDns in dns.js: dispatches to DoH or the
// UDP/TCP/TLS wire transports based on the resolver URL scheme.
func resolveDnsURL(rawURL, domain, answerType, edns string, timeoutMS int, insecure bool) ([]string, error) {
	resolver, err := parseDnsResolver(rawURL)
	if err != nil {
		return nil, err
	}
	switch resolver.protocol {
	case "doh":
		return dohResolve(resolver.url, domain, answerType, edns, timeoutMS, insecure)
	case "udp", "tcp", "tls":
		query, err := buildDNSQuery(domain, answerType, edns)
		if err != nil {
			return nil, err
		}
		var body []byte
		switch resolver.protocol {
		case "udp":
			body, err = dnsQueryUDP(resolver.host, resolver.port, query, timeoutMS)
		case "tcp":
			body, err = dnsQueryStream(resolver.host, resolver.port, query, timeoutMS, false, insecure)
		case "tls":
			body, err = dnsQueryStream(resolver.host, resolver.port, query, timeoutMS, true, insecure)
		}
		if err != nil {
			return nil, err
		}
		answers, err := decodeDNSAnswers(body, answerType)
		if err != nil {
			return nil, err
		}
		if len(answers) == 0 {
			return nil, errors.New("No answers")
		}
		return answers, nil
	}
	return nil, fmt.Errorf("自定义 DNS 不支持 %s 协议", resolver.protocol)
}

// ---- providers (DOMAIN_RESOLVERS in the original) --------------------------

// Overridable provider endpoints (kept as variables for testability; values
// match the original hardcoded URLs).
var (
	googleDoHURL    = "https://8.8.4.4/dns-query"
	cloudflareDoHUR = "https://1.0.0.1/dns-query"
	aliDNSURL       = "http://223.6.6.6/resolve"
	tencentDNSURL   = "http://119.28.28.28/d"
	ipAPIURL        = "http://ip-api.com/json"
)

// dnsResolveFunc resolves one domain. It returns the resolved IPs and, for
// the Custom provider, the winning resolver URL.
type dnsResolveFunc func(domain, dnsType string, noCache bool, timeoutMS int, edns, customURL string, insecure bool, dnsConcurrency int, cacheTtlSec int) ([]string, string, error)

var domainResolvers = map[string]dnsResolveFunc{
	"Custom":     resolveProviderCustom,
	"Google":     resolveProviderGoogle,
	"IP-API":     resolveProviderIPAPI,
	"Cloudflare": resolveProviderCloudflare,
	"Ali":        resolveProviderAli,
	"Tencent":    resolveProviderTencent,
}

func resolveProviderCustom(domain, dnsType string, noCache bool, timeoutMS int, edns, customURL string, insecure bool, dnsConcurrency int, cacheTtlSec int) ([]string, string, error) {
	urls, err := parseCustomDnsUrls(customURL)
	if err != nil {
		return nil, "", err
	}
	normalizedURL := strings.Join(urls, "\n")
	insecurePrefix := ""
	if insecure {
		insecurePrefix = "INSECURE:"
	}
	id := md5Hex("CUSTOM:" + insecurePrefix + normalizedURL + ":" + domain + ":" + dnsType)
	if !noCache {
		if cached := resolveResourceCache.get(id); cached != nil {
			if cr, ok := cached.(*customDNSResult); ok {
				return cr.Result, cr.ResolverURL, nil
			}
		}
	}
	answerType := answerTypeFor(dnsType)
	resolveURL := func(resolverURL string) ([]string, error) {
		ips, err := resolveDnsURL(resolverURL, domain, answerType, edns, timeoutMS, insecure)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("No answers")
		}
		return ips, nil
	}
	var result []string
	var resolverURL string
	if len(urls) == 1 {
		result, err = resolveURL(urls[0])
		resolverURL = urls[0]
	} else {
		result, resolverURL, err = resolveWithCustomDNSConcurrency(urls, dnsConcurrency, resolveURL)
	}
	if err != nil {
		return nil, "", err
	}
	resolveResourceCache.set(id, &customDNSResult{Result: result, ResolverURL: resolverURL}, time.Duration(cacheTtlSec)*time.Second)
	return result, resolverURL, nil
}

func cachedOrResolve(id string, noCache bool, cacheTtlSec int, fetch func() ([]string, error)) ([]string, error) {
	if !noCache {
		if cached := resolveResourceCache.get(id); cached != nil {
			if ips, ok := cached.([]string); ok {
				return ips, nil
			}
		}
	}
	result, err := fetch()
	if err != nil {
		return nil, err
	}
	resolveResourceCache.set(id, result, time.Duration(cacheTtlSec)*time.Second)
	return result, nil
}

func resolveProviderGoogle(domain, dnsType string, noCache bool, timeoutMS int, edns, _ string, _ bool, _ int, cacheTtlSec int) ([]string, string, error) {
	id := md5Hex("GOOGLE:" + domain + ":" + dnsType)
	ips, err := cachedOrResolve(id, noCache, cacheTtlSec, func() ([]string, error) {
		return dohResolve(googleDoHURL, domain, answerTypeFor(dnsType), edns, timeoutMS, false)
	})
	return ips, "", err
}

func resolveProviderCloudflare(domain, dnsType string, noCache bool, timeoutMS int, edns, _ string, _ bool, _ int, cacheTtlSec int) ([]string, string, error) {
	id := md5Hex("CLOUDFLARE:" + domain + ":" + dnsType)
	ips, err := cachedOrResolve(id, noCache, cacheTtlSec, func() ([]string, error) {
		return dohResolve(cloudflareDoHUR, domain, answerTypeFor(dnsType), edns, timeoutMS, false)
	})
	return ips, "", err
}

func resolveProviderIPAPI(domain, dnsType string, noCache bool, timeoutMS int, _, _ string, _ bool, _ int, cacheTtlSec int) ([]string, string, error) {
	if dnsType == "IPv6" {
		return nil, "", fmt.Errorf("域名解析服务提供方 IP-API 不支持 IPv6")
	}
	id := md5Hex("IP-API:" + domain)
	ips, err := cachedOrResolve(id, noCache, cacheTtlSec, func() ([]string, error) {
		body, err := httpGetString(ipAPIURL+"/"+url.PathEscape(domain)+"?lang=zh-CN", timeoutMS, false, nil)
		if err != nil {
			return nil, err
		}
		var parsed struct {
			Status string `json:"status"`
			Query  string `json:"query"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, err
		}
		if parsed.Status != "success" {
			return nil, fmt.Errorf("Status is %s", parsed.Status)
		}
		if parsed.Query == "" || parsed.Query == "0" {
			return nil, errors.New("No answers")
		}
		return []string{parsed.Query}, nil
	})
	return ips, "", err
}

func resolveProviderAli(domain, dnsType string, noCache bool, timeoutMS int, edns, _ string, _ bool, _ int, cacheTtlSec int) ([]string, string, error) {
	id := md5Hex("ALI:" + domain + ":" + dnsType)
	ips, err := cachedOrResolve(id, noCache, cacheTtlSec, func() ([]string, error) {
		prefix := ednsSourcePrefixV4
		if !isIPv4Str(edns) {
			prefix = ednsSourcePrefixV6
		}
		reqURL := fmt.Sprintf("%s?edns_client_subnet=%s/%d&name=%s&type=%s&short=1",
			aliDNSURL, edns, prefix, url.QueryEscape(domain), answerTypeFor(dnsType))
		body, err := httpGetString(reqURL, timeoutMS, false, map[string]string{
			"accept": "application/dns-json",
		})
		if err != nil {
			return nil, err
		}
		var answers []string
		if err := json.Unmarshal(body, &answers); err != nil {
			return nil, err
		}
		if len(answers) == 0 {
			return nil, errors.New("No answers")
		}
		return answers, nil
	})
	return ips, "", err
}

func resolveProviderTencent(domain, dnsType string, noCache bool, timeoutMS int, edns, _ string, _ bool, _ int, cacheTtlSec int) ([]string, string, error) {
	id := md5Hex("TENCENT:" + domain + ":" + dnsType)
	ips, err := cachedOrResolve(id, noCache, cacheTtlSec, func() ([]string, error) {
		reqURL := fmt.Sprintf("%s?ip=%s&type=%s&dn=%s",
			tencentDNSURL, edns, answerTypeFor(dnsType), url.QueryEscape(domain))
		body, err := httpGetString(reqURL, timeoutMS, false, map[string]string{
			"accept": "application/dns-json",
		})
		if err != nil {
			return nil, err
		}
		var answers []string
		for _, part := range strings.Split(string(body), ";") {
			answers = append(answers, strings.Split(part, ",")[0])
		}
		if len(answers) == 0 || strings.Join(answers, ",") == "0" {
			return nil, errors.New("No answers")
		}
		return answers, nil
	})
	return ips, "", err
}
