package processor

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"substore/internal/model"
)

func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	return rand.Intn(n)
}

func scriptFilter(_ any, _ *Context) Processor {
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		// Script filtering is not supported; the filter is a no-op.
		return proxies, nil
	}
}

func scriptOperator(_ any, _ *Context) Processor {
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		// Script operators are not supported; the operator is a no-op.
		return proxies, nil
	}
}

// ---- Resolve Domain Operator ------------------------------------------------
//
// Faithful port of ResolveDomainOperator in
// Sub-Store-master/backend/src/core/proxy-utils/processors/index.js
// (roughly lines 1122-1350).

const (
	ip4pPattern      = `^2001::[^:]+:[^:]+:[^:]+$`
	defaultEdnsSubnet = "223.6.6.6"
)

var ip4pRe = regexp.MustCompile(ip4pPattern)

type resolveDomainConfig struct {
	provider          string
	dnsType           string // "IPv4" or "IPv6"
	filter            string
	cacheDisabled     bool
	timeoutMS         int
	edns              string
	concurrency       int
	customURL         string
	customDNSCount    int
	customDNSInsecure bool
	dnsConcurrency    int
	cacheTtlSec       int
}

// cachedResolve mirrors the operator-level `results` entries: the resolved IP
// list plus (for Custom) the winning resolver URL.
type cachedResolve struct {
	ips         []string
	resolverURL string
}

// resolveDomainOperator is registered as "Resolve Domain Operator". Invalid
// configuration is reported when the processor runs (the Go registry
// signature does not allow construction-time errors).
func resolveDomainOperator(args any) Processor {
	cfg, err := newResolveDomainConfig(args)
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		if err != nil {
			return nil, err
		}
		return cfg.run(proxies)
	}
}

func newResolveDomainConfig(args any) (*resolveDomainConfig, error) {
	m := toMap(args)
	cfg := &resolveDomainConfig{}

	cfg.provider, _ = m["provider"].(string)
	if _, ok := domainResolvers[cfg.provider]; !ok {
		return nil, fmt.Errorf("找不到域名解析服务提供方: %s", cfg.provider)
	}

	typeArg, _ := m["type"].(string)
	if (typeArg == "IPv6" || typeArg == "IP4P") && cfg.provider == "IP-API" {
		return nil, fmt.Errorf("域名解析服务提供方 %s 不支持 %s", cfg.provider, typeArg)
	}
	cfg.dnsType = "IPv4"
	if typeArg == "IPv6" || typeArg == "IP4P" {
		cfg.dnsType = "IPv6"
	}

	cfg.filter, _ = m["filter"].(string)
	cfg.cacheDisabled = fmt.Sprint(m["cache"]) == "disabled"

	timeoutMS, err := normalizeResolveDomainTimeout(m["timeout"])
	if err != nil {
		return nil, err
	}
	cfg.timeoutMS = timeoutMS

	cacheTtlSec, err := normalizeResolveDomainCacheTtl(m["cacheTtl"])
	if err != nil {
		return nil, err
	}
	cfg.cacheTtlSec = cacheTtlSec

	edns, _ := m["edns"].(string)
	if edns == "" {
		edns = defaultEdnsSubnet
	}
	if !isIPStr(edns) {
		return nil, errors.New("域名解析 EDNS 应为 IP")
	}
	cfg.edns = edns

	concurrency, err := normalizeResolveDomainConcurrency(m["concurrency"])
	if err != nil {
		return nil, err
	}
	cfg.concurrency = concurrency

	if cfg.provider == "Custom" {
		customURL, err := normalizeCustomDnsUrlList(fmt.Sprint(m["url"]))
		if err != nil {
			return nil, err
		}
		cfg.customURL = customURL
		urls, _ := parseCustomDnsUrls(customURL)
		cfg.customDNSCount = len(urls)
		dnsConcurrency, err := normalizeResolveDomainCustomDNSConcurrency(m["dnsConcurrency"])
		if err != nil {
			return nil, err
		}
		cfg.dnsConcurrency = dnsConcurrency
		switch v := m["tlsSkipCertVerify"].(type) {
		case bool:
			cfg.customDNSInsecure = v
		case string:
			cfg.customDNSInsecure = v == "enabled"
		}
	} else {
		cfg.customDNSCount = 1
		cfg.dnsConcurrency = 1
	}

	totalConcurrency := cfg.concurrency * min(cfg.dnsConcurrency, cfg.customDNSCount)
	if totalConcurrency > resolveDomainConcurrencyWarnThreshold {
		log.Printf("WARNING: 域名解析总并发数上限 %d 超过建议值 %d, 可能导致代理 App TCP 连接数激增",
			totalConcurrency, resolveDomainConcurrencyWarnThreshold)
	}

	resolverInfo := ""
	if cfg.provider == "Custom" {
		if cfg.customDNSCount > 1 {
			resolverInfo = fmt.Sprintf("%d custom DNS", cfg.customDNSCount)
		} else {
			resolverInfo = cfg.customURL
		}
		if cfg.customDNSInsecure {
			resolverInfo += " tlsSkipCertVerify=enabled"
		}
	}
	log.Printf("Domain Resolver: [%s] %s %s %s concurrency=%d",
		typeArg, cfg.provider, cfg.edns, resolverInfo, cfg.concurrency)

	return cfg, nil
}

func (c *resolveDomainConfig) resolverCacheID(domain string) string {
	switch c.provider {
	case "Custom":
		insecurePrefix := ""
		if c.customDNSInsecure {
			insecurePrefix = "INSECURE:"
		}
		return md5Hex("CUSTOM:" + insecurePrefix + c.customURL + ":" + domain + ":" + c.dnsType)
	case "Google":
		return md5Hex("GOOGLE:" + domain + ":" + c.dnsType)
	case "IP-API":
		return md5Hex("IP-API:" + domain)
	case "Cloudflare":
		return md5Hex("CLOUDFLARE:" + domain + ":" + c.dnsType)
	case "Ali":
		return md5Hex("ALI:" + domain + ":" + c.dnsType)
	case "Tencent":
		return md5Hex("TENCENT:" + domain + ":" + c.dnsType)
	}
	return ""
}

func (c *resolveDomainConfig) getCachedResult(domain string) *cachedResolve {
	if c.cacheDisabled {
		return nil
	}
	id := c.resolverCacheID(domain)
	if id == "" {
		return nil
	}
	cached := resolveResourceCache.get(id)
	if cached == nil {
		return nil
	}
	if c.provider == "Custom" {
		if cr, ok := cached.(*customDNSResult); ok {
			return &cachedResolve{ips: cr.Result, resolverURL: cr.ResolverURL}
		}
		return nil
	}
	if ips, ok := cached.([]string); ok {
		return &cachedResolve{ips: ips}
	}
	return nil
}

func (c *resolveDomainConfig) run(proxies []*model.Proxy) ([]*model.Proxy, error) {
	// Normalize `no-resolve` into `_no-resolve`.
	for _, p := range proxies {
		if !p.Has("_no-resolve") {
			if v := p.Get("no-resolve"); v != nil && toBoolValue(v) {
				p.Set("_no-resolve", v)
			}
		}
	}

	// Collect unique domains to resolve, deduplicated by cache id.
	results := map[string]*cachedResolve{}
	seen := map[string]bool{}
	var domains []resolveTask
	for _, p := range proxies {
		server := p.Server()
		if isIPStr(server) {
			continue
		}
		if truthyAny(p.Get("_no-resolve")) {
			continue
		}
		id := c.resolverCacheID(server)
		if seen[id] {
			continue
		}
		seen[id] = true
		if cached := c.getCachedResult(server); cached != nil {
			results[id] = cached
			log.Printf("Using cached resolved domain: %s ➟ %v", server, cached.ips)
		} else {
			domains = append(domains, resolveTask{id: id, domain: server})
		}
	}

	resolveDomainsWithConcurrency(domains, c.concurrency, func(t resolveTask) {
		ips, resolverURL, err := c.resolveDomain(t.domain)
		if err != nil {
			log.Printf("Failed to resolve domain: %s with resolver [%s]: %v", t.domain, c.provider, err)
			return
		}
		results[t.id] = &cachedResolve{ips: ips, resolverURL: resolverURL}
		log.Printf("Successfully resolved domain: %s ➟ %v", t.domain, ips)
	})

	// Write results back to the proxies.
	for _, p := range proxies {
		if truthyAny(p.Get("_no-resolve")) {
			continue
		}
		id := c.resolverCacheID(p.Server())
		res, ok := results[id]
		if !ok || len(res.ips) == 0 {
			if !truthyAny(p.Get("resolved")) {
				p.Set("resolved", false)
			}
			continue
		}
		p.Set("_resolved_ips", res.ips)
		ip := res.ips[randInt(len(res.ips))]
		if c.dnsType == "IPv6" && isIPv6Str(ip) {
			if addr, err := netip.ParseAddr(ip); err == nil {
				ip = addr.String()
			} else {
				log.Printf("Failed to parse IPv6 address: %s: %v", ip, err)
			}
			if ip4pRe.MatchString(ip) {
				p.Set("_IP4P", ip)
				server, port, ok := parseIP4P(ip)
				if ok {
					p.Set("_domain", p.Server())
					p.Set("server", server)
					p.Set("port", port)
					p.Set("resolved", true)
					p.Set("_IPv4", server)
					if !isIPStr(p.GetString("_IP")) {
						p.Set("_IP", server)
					}
				} else if !truthyAny(p.Get("resolved")) {
					p.Set("resolved", false)
				}
			} else {
				p.Set("_domain", p.Server())
				p.Set("server", ip)
				p.Set("resolved", true)
				p.Set("_"+c.dnsType, ip)
				if !isIPStr(p.GetString("_IP")) {
					p.Set("_IP", ip)
				}
			}
		} else {
			p.Set("_domain", p.Server())
			p.Set("server", ip)
			p.Set("resolved", true)
			p.Set("_"+c.dnsType, ip)
			if !isIPStr(p.GetString("_IP")) {
				p.Set("_IP", ip)
			}
		}
	}

	// Apply the result filter.
	switch c.filter {
	case "removeFailed":
		out := make([]*model.Proxy, 0, len(proxies))
		for _, p := range proxies {
			if isIPStr(p.Server()) || truthyAny(p.Get("_no-resolve")) || truthyAny(p.Get("resolved")) {
				out = append(out, p)
			}
		}
		return out, nil
	case "IPOnly":
		out := make([]*model.Proxy, 0, len(proxies))
		for _, p := range proxies {
			if isIPStr(p.Server()) {
				out = append(out, p)
			}
		}
		return out, nil
	case "IPv4Only":
		out := make([]*model.Proxy, 0, len(proxies))
		for _, p := range proxies {
			if isIPv4Str(p.Server()) {
				out = append(out, p)
			}
		}
		return out, nil
	case "IPv6Only":
		out := make([]*model.Proxy, 0, len(proxies))
		for _, p := range proxies {
			if isIPv6Str(p.Server()) {
				out = append(out, p)
			}
		}
		return out, nil
	default:
		return proxies, nil
	}
}

// resolveDomain dispatches to the configured provider, mirroring the
// DOMAIN_RESOLVERS call with (domain, type, noCache, timeout, edns, url,
// tlsSkipCertVerify, dnsConcurrency, cacheTtl).
func (c *resolveDomainConfig) resolveDomain(domain string) ([]string, string, error) {
	resolver, ok := domainResolvers[c.provider]
	if !ok {
		return nil, "", fmt.Errorf("找不到域名解析服务提供方: %s", c.provider)
	}
	return resolver(domain, c.dnsType, c.cacheDisabled, c.timeoutMS, c.edns,
		c.customURL, c.customDNSInsecure, c.dnsConcurrency, c.cacheTtlSec)
}

// parseIP4P decodes a Teleedom IP4P address "2001::<port-hex>:<ip-hex>", see
// parseIP4P in the original.
func parseIP4P(ip4p string) (string, int, bool) {
	defer func() { _ = recover() }()
	parts := strings.Split(ip4p, ":")
	if len(parts) < 5 {
		return "", 0, false
	}
	port, err := strconv.ParseUint(parts[2], 16, 32)
	if err != nil {
		log.Printf("IP4P 解析失败: %v", err)
		return "", 0, false
	}
	ipab, err := strconv.ParseUint(parts[3], 16, 32)
	if err != nil {
		log.Printf("IP4P 解析失败: %v", err)
		return "", 0, false
	}
	ipcd, err := strconv.ParseUint(parts[4], 16, 32)
	if err != nil {
		log.Printf("IP4P 解析失败: %v", err)
		return "", 0, false
	}
	server := fmt.Sprintf("%d.%d.%d.%d", ipab>>8, ipab&0xff, ipcd>>8, ipcd&0xff)
	if port <= 0 || port > 65535 {
		log.Printf("IP4P 解析失败: Invalid port number: %d", port)
		return "", 0, false
	}
	if !isIPv4Str(server) {
		log.Printf("IP4P 解析失败: Invalid IP address: %s", server)
		return "", 0, false
	}
	return server, int(port), true
}

// truthyAny reports JS-style truthiness for values stored on proxies.
func truthyAny(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case int:
		return t != 0
	case float64:
		return t != 0
	default:
		return true
	}
}

func fmt_str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
