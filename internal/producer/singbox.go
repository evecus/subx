package producer

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"substore/internal/model"
)

// ProduceSingBox mirrors the original Sub-Store sing-box producer
// (producers/sing-box.js): each proxy is converted to one or more sing-box
// outbounds/endpoints; failed nodes are skipped entirely. The final output is
// a JSON object {outbounds: [...], endpoints: [...]} where wireguard and
// tailscale entries land under endpoints.
func ProduceSingBox(proxies []*model.Proxy, options map[string]any) (string, error) {
	includeUnsupported := false
	if options != nil {
		includeUnsupported = sbTruthy(options["include-unsupported-proxy"])
	}
	list := make([]map[string]any, 0, len(proxies))
	for _, proxy := range proxies {
		start := len(list)
		items, err := singBoxProduceOne(proxy, includeUnsupported)
		if err != nil {
			// Mirror the JS try/catch: drop everything produced for this
			// node instead of emitting a broken config.
			list = list[:start]
			continue
		}
		list = append(list, items...)
	}
	outbounds := make([]any, 0, len(list))
	endpoints := make([]any, 0)
	for _, item := range list {
		if item["type"] == "wireguard" || item["type"] == "tailscale" {
			endpoints = append(endpoints, item)
		} else {
			outbounds = append(outbounds, item)
		}
	}
	categorized := map[string]any{"outbounds": outbounds, "endpoints": endpoints}
	b, err := jsonMarshalIndentNoEscape(categorized, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// singBoxProduceOne converts a single proxy, mirroring the produce() switch
// in sing-box.js including the stream shadow-tls chaining logic. It may
// return more than one outbound (ss + shadowtls).
func singBoxProduceOne(proxy *model.Proxy, includeUnsupported bool) ([]map[string]any, error) {
	var streamShadowTLSOutbound map[string]any

	shadowTLSPluginOpts := sbShadowTLSPluginOpts(proxy)
	shadowTLSEnabled := false
	if shadowTLSPluginOpts != nil {
		shadowTLSEnabled = sbTruthy(shadowTLSPluginOpts["password"]) ||
			(shadowTLSPluginOpts["version"] != nil && sbNumber(shadowTLSPluginOpts["version"]) != 0)
	}
	if shadowTLSEnabled {
		switch proxy.Type() {
		case "vmess", "vless", "trojan":
			if proxy.GetMap("reality-opts") != nil {
				return nil, fmt.Errorf("Platform sing-box cannot chain ShadowTLS with Reality for proxy %s", proxy.Name())
			}
			if (proxy.Type() == "vmess" || proxy.Type() == "vless") && proxy.GetString("network") == "h2" {
				return nil, fmt.Errorf("Platform sing-box cannot chain ShadowTLS with network h2 for proxy %s", proxy.Name())
			}
			if proxy.Type() == "vless" && proxy.GetString("flow") == "xtls-rprx-vision" {
				return nil, fmt.Errorf("Platform sing-box cannot chain ShadowTLS with flow xtls-rprx-vision for proxy %s", proxy.Name())
			}
			rawVersion := shadowTLSPluginOpts["version"]
			var parsedVersion float64
			if s, isStr := rawVersion.(string); isStr && strings.TrimSpace(s) == "" {
				// Number("") would be 0 but the JS code treats empty string
				// as NaN which fails the integer check.
				return nil, fmt.Errorf("Platform sing-box does not support shadow-tls version %s for proxy %s", str(rawVersion), proxy.Name())
			} else if rawVersion == nil {
				parsedVersion = 0
			} else {
				parsedVersion = sbNumber(rawVersion)
			}
			version := parsedVersion
			if version == 0 {
				version = 2
			}
			if math.IsNaN(version) || version != math.Trunc(version) || version < 1 || version > 3 {
				return nil, fmt.Errorf("Platform sing-box does not support shadow-tls version %s for proxy %s", str(rawVersion), proxy.Name())
			}
			opts, _ := cloneAny(shadowTLSPluginOpts).(map[string]any)
			opts["version"] = int(version)
			st, err := sbShadowTLSOutboundParser(proxy, opts)
			if err != nil {
				return nil, err
			}
			streamShadowTLSOutbound = st
		case "anytls":
			return nil, fmt.Errorf("Platform sing-box cannot replace AnyTLS TLS with ShadowTLS")
		}
	}

	if proxy.GetString("network") == "xhttp" {
		return nil, fmt.Errorf("Platform sing-box does not support network: %s", proxy.GetString("network"))
	}

	var items []map[string]any
	switch typ := proxy.Type(); typ {
	case "ssh":
		one, err := sbSSHParser(proxy)
		if err != nil {
			return nil, err
		}
		items = []map[string]any{one}
	case "http":
		one, err := sbHTTPParser(proxy)
		if err != nil {
			return nil, err
		}
		items = []map[string]any{one}
	case "socks5":
		if sbTruthy(proxy.Get("tls")) {
			return nil, fmt.Errorf("Platform sing-box does not support proxy type: %s with tls", typ)
		}
		one, err := sbSocks5Parser(proxy)
		if err != nil {
			return nil, err
		}
		items = []map[string]any{one}
	case "ss":
		if proxy.GetString("plugin") == "shadow-tls" {
			ssPart, stPart, err := sbShadowTLSParser(proxy)
			if err != nil {
				return nil, err
			}
			items = []map[string]any{ssPart, stPart}
		} else {
			one, err := sbSSParser(proxy)
			if err != nil {
				return nil, err
			}
			items = []map[string]any{one}
		}
	case "ssr":
		if !includeUnsupported {
			return nil, fmt.Errorf("Platform sing-box does not support proxy type: %s", typ)
		}
		one, err := sbSSRParser(proxy)
		if err != nil {
			return nil, err
		}
		items = []map[string]any{one}
	case "snell":
		one, err := sbSnellParser(proxy, includeUnsupported)
		if err != nil {
			return nil, err
		}
		items = []map[string]any{one}
		if stlOpts := sbShadowTLSPluginOpts(proxy); stlOpts != nil {
			st, err := sbShadowTLSOutboundParser(proxy, stlOpts)
			if err != nil {
				return nil, err
			}
			items = append(items, st)
		}
	case "vmess":
		nw := proxy.GetString("network")
		if nw != "" && nw != "tcp" && nw != "ws" && nw != "grpc" && nw != "h2" && nw != "http" {
			return nil, fmt.Errorf("Platform sing-box does not support proxy type: %s with network %s", typ, nw)
		}
		one, err := sbVMessParser(proxy)
		if err != nil {
			return nil, err
		}
		items = []map[string]any{one}
	case "vless":
		if enc := proxy.GetString("encryption"); enc != "" && enc != "none" {
			return nil, fmt.Errorf("VLESS encryption is not supported")
		}
		flow := proxy.GetString("flow")
		if flow != "" && flow != "xtls-rprx-vision" {
			return nil, fmt.Errorf("Platform sing-box does not support proxy type: %s with flow %s", typ, flow)
		}
		one, err := sbVLESSParser(proxy)
		if err != nil {
			return nil, err
		}
		items = []map[string]any{one}
	case "trojan":
		if flow := proxy.GetString("flow"); flow != "" {
			return nil, fmt.Errorf("Platform sing-box does not support proxy type: %s with flow %s", typ, flow)
		}
		one, err := sbTrojanParser(proxy)
		if err != nil {
			return nil, err
		}
		items = []map[string]any{one}
	case "naive":
		one, err := sbNaiveParser(proxy)
		if err != nil {
			return nil, err
		}
		items = []map[string]any{one}
	case "hysteria":
		one, err := sbHysteriaParser(proxy)
		if err != nil {
			return nil, err
		}
		items = []map[string]any{one}
	case "hysteria2":
		one, err := sbHysteria2Parser(proxy)
		if err != nil {
			return nil, err
		}
		items = []map[string]any{one}
	case "tuic":
		if token := proxy.GetString("token"); token != "" {
			return nil, fmt.Errorf("Platform sing-box does not support proxy type: TUIC v4")
		}
		one, err := sbTUIC5Parser(proxy)
		if err != nil {
			return nil, err
		}
		items = []map[string]any{one}
	case "wireguard":
		one, err := sbWireGuardParser(proxy)
		if err != nil {
			return nil, err
		}
		items = []map[string]any{one}
	case "anytls":
		one, err := sbAnytlsParser(proxy)
		if err != nil {
			return nil, err
		}
		items = []map[string]any{one}
	case "tailscale":
		items = []map[string]any{sbTailscaleParser(proxy)}
	default:
		return nil, fmt.Errorf("Platform sing-box does not support proxy type: %s", typ)
	}

	if streamShadowTLSOutbound != nil {
		outbound := items[0]
		outbound["detour"] = sbShadowTLSTag(proxy)
		delete(outbound, "tls")
		items = append(items, streamShadowTLSOutbound)
	}
	if includeUnsupported {
		if ncv := proxy.Get("name-cert-verify"); sbTruthy(ncv) {
			for _, item := range items {
				if tlsMap, ok := item["tls"].(map[string]any); ok {
					tlsMap["certificate_server_name"] = str(ncv)
				}
			}
		}
	}
	return items, nil
}

// ---------------------------------------------------------------------------
// generic helpers (mirror JS semantics)
// ---------------------------------------------------------------------------

// sbTruthy mirrors JS truthiness.
func sbTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0 && !math.IsNaN(t)
	case int:
		return t != 0
	case int64:
		return t != 0
	case json.Number:
		f, _ := t.Float64()
		return f != 0
	default:
		return true
	}
}

// sbParseInt mirrors JS parseInt(value, 10): leading integer prefix of the
// string form; ok=false means NaN.
func sbParseInt(v any) (int, bool) {
	s := str(v)
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' || s[i] == '\v' || s[i] == '\f') {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == start {
		return 0, false
	}
	n, err := strconv.ParseInt(s[start:i], 10, 64)
	if err != nil {
		return 0, false
	}
	if neg {
		n = -n
	}
	return int(n), true
}

// sbIntOrNull returns the parseInt result or nil (JSON null for NaN).
func sbIntOrNull(v any) any {
	if n, ok := sbParseInt(v); ok {
		return n
	}
	return nil
}

// sbNumber mirrors JS Number() for the value types that can appear here.
func sbNumber(v any) float64 {
	switch t := v.(type) {
	case bool:
		if t {
			return 1
		}
		return 0
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		if err != nil {
			return math.NaN()
		}
		return f
	}
	return math.NaN()
}

func sbNumEquals(v any, target float64) bool {
	switch t := v.(type) {
	case int:
		return float64(t) == target
	case int64:
		return float64(t) == target
	case float64:
		return t == target
	case json.Number:
		f, _ := t.Float64()
		return f == target
	}
	return false
}

// sbServerPortAny mirrors parseInt(`${proxy.port}`, 10): nil (JSON null)
// when the port is missing/unparseable.
func sbServerPortAny(p *model.Proxy) any { return sbIntOrNull(p.Get("port")) }

// sbCheckPort mirrors `if (server_port < 0 || server_port > 65535) throw`;
// nil (NaN) passes since NaN comparisons are false.
func sbCheckPort(v any) error {
	if n, ok := v.(int); ok && (n < 0 || n > 65535) {
		return fmt.Errorf("invalid port")
	}
	return nil
}

// sbTlsInit mirrors the per-parser tls seed object.
func sbTlsInit(enabled bool, p *model.Proxy) map[string]any {
	return map[string]any{"enabled": enabled, "server_name": p.Server(), "insecure": false}
}

// sbSetIf only writes non-nil values (JSON.stringify drops undefined).
func sbSetIf(m map[string]any, key string, v any) {
	if v != nil {
		m[key] = v
	}
}

// sbStrJS mirrors `${value}` template coercion (arrays join with ',').
func sbStrJS(v any) string {
	if arr, ok := v.([]any); ok {
		parts := make([]string, len(arr))
		for i, e := range arr {
			parts[i] = str(e)
		}
		return strings.Join(parts, ",")
	}
	return str(v)
}

func sbSortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sbSplitTrim(s, sep string) []any {
	parts := strings.Split(s, sep)
	out := make([]any, 0, len(parts))
	for _, part := range parts {
		out = append(out, strings.TrimSpace(part))
	}
	return out
}

// sbJSONString mirrors JSON.stringify without HTML escaping.
func sbJSONString(v any) string {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimRight(sb.String(), "\n")
}

// ---------------------------------------------------------------------------
// shared parsers (ip-version / domain-resolver / detour / network / tfo / smux)
// ---------------------------------------------------------------------------

var sbIPVersions = map[string]string{
	"ipv4":         "ipv4_only",
	"ipv6":         "ipv6_only",
	"v4-only":      "ipv4_only",
	"v6-only":      "ipv6_only",
	"ipv4-prefer":  "prefer_ipv4",
	"ipv6-prefer":  "prefer_ipv6",
	"prefer-v4":    "prefer_ipv4",
	"prefer-v6":    "prefer_ipv6",
}

func sbIPVersionParser(p *model.Proxy, out map[string]any) {
	strategy, ok := sbIPVersions[p.GetString("ip-version")]
	if !ok {
		return
	}
	if dns := p.Get("_dns_server"); dns != nil && str(dns) != "" {
		out["domain_resolver"] = map[string]any{"server": dns, "strategy": strategy}
	}
}

func sbDomainResolverParser(p *model.Proxy, out map[string]any) {
	dr := p.Get("_domain_resolver")
	if dr == nil {
		return
	}
	merged := map[string]any{}
	if existing, ok := out["domain_resolver"].(map[string]any); ok {
		for k, v := range existing {
			merged[k] = v
		}
	}
	switch t := dr.(type) {
	case string:
		merged["server"] = t
	case map[string]any:
		for k, v := range t {
			merged[k] = v
		}
	default:
		return
	}
	out["domain_resolver"] = merged
}

func sbDetourParser(p *model.Proxy, out map[string]any) {
	pick := p.Get("dialer-proxy")
	if !sbTruthy(pick) {
		pick = p.Get("detour")
	}
	if pick != nil {
		out["detour"] = pick
	}
}

func sbNetworkParser(p *model.Proxy, out map[string]any) {
	if nw, ok := p.Get("_network").(string); ok && (nw == "tcp" || nw == "udp") {
		out["network"] = nw
		return
	}
	if v, ok := p.Get("udp").(bool); ok && !v {
		out["network"] = "tcp"
	}
}

func sbTFOParser(p *model.Proxy, out map[string]any) {
	if sbTruthy(p.Get("tfo")) || sbTruthy(p.Get("tcp_fast_open")) || sbTruthy(p.Get("tcp-fast-open")) {
		out["tcp_fast_open"] = true
	}
}

func sbSmuxParser(smux map[string]any, out map[string]any) {
	if smux == nil || !sbTruthy(smux["enabled"]) {
		return
	}
	multiplex := map[string]any{"enabled": true}
	if sbTruthy(smux["protocol"]) {
		multiplex["protocol"] = smux["protocol"]
	}
	if sbTruthy(smux["max-connections"]) {
		multiplex["max_connections"] = sbIntOrNull(smux["max-connections"])
	}
	if sbTruthy(smux["max-streams"]) {
		multiplex["max_streams"] = sbIntOrNull(smux["max-streams"])
	}
	if sbTruthy(smux["min-streams"]) {
		multiplex["min_streams"] = sbIntOrNull(smux["min-streams"])
	}
	if sbTruthy(smux["padding"]) {
		multiplex["padding"] = true
	}
	if bo, ok := smux["brutal-opts"].(map[string]any); ok {
		if sbTruthy(bo["up"]) || sbTruthy(bo["down"]) {
			brutal := map[string]any{"enabled": true}
			if sbTruthy(bo["up"]) {
				brutal["up_mbps"] = sbIntOrNull(bo["up"])
			}
			if sbTruthy(bo["down"]) {
				brutal["down_mbps"] = sbIntOrNull(bo["down"])
			}
			multiplex["brutal"] = brutal
		}
	}
	out["multiplex"] = multiplex
}

func sbUDPOverTCP(p *model.Proxy) any {
	if sbTruthy(p.Get("uot")) {
		return true
	}
	if sbTruthy(p.Get("udp-over-tcp")) {
		version := 1
		if v := p.Get("udp-over-tcp-version"); sbTruthy(v) && !sbNumEquals(v, 1) {
			version = 2
		}
		return map[string]any{"enabled": true, "version": version}
	}
	return nil
}

// ---------------------------------------------------------------------------
// TLS (sing-box.js tlsParser)
// ---------------------------------------------------------------------------

var sbUTLSFingerprints = []string{
	"chrome", "firefox", "edge", "safari", "360", "qq",
	"ios", "android", "random", "randomized",
}

func sbGetUtlsFingerprint(value any) string {
	fp := strings.ToLower(strings.TrimSpace(str(value)))
	for _, f := range sbUTLSFingerprints {
		if fp == f {
			return fp
		}
	}
	return ""
}

// sbNormalizePemLines mirrors normalizePemLines in sing-box.js.
func sbNormalizePemLines(value any) []any {
	items, ok := value.([]any)
	if !ok {
		items = []any{value}
	}
	var lines []string
	for _, item := range items {
		normalized := strings.TrimSpace(strAny(item))
		normalized = strings.ReplaceAll(normalized, "\\r\n", "\n")
		normalized = strings.ReplaceAll(normalized, "\\n", "\n")
		if normalized == "" {
			continue
		}
		normalized = strings.ReplaceAll(normalized, "\r\n", "\n")
		for _, line := range strings.Split(normalized, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				lines = append(lines, trimmed)
			}
		}
	}
	if len(lines) == 0 {
		return nil
	}
	beginRe := regexp.MustCompile(`^-----BEGIN [A-Za-z0-9 -]+-----$`)
	out := make([]any, 0, len(lines)+2)
	for _, line := range lines {
		out = append(out, line)
	}
	for _, line := range lines {
		if beginRe.MatchString(line) {
			return out
		}
	}
	wrapped := make([]any, 0, len(lines)+2)
	wrapped = append(wrapped, "-----BEGIN ECH CONFIGS-----")
	wrapped = append(wrapped, out...)
	wrapped = append(wrapped, "-----END ECH CONFIGS-----")
	return wrapped
}

// sbTLSParser mirrors tlsParser in sing-box.js. The caller must have seeded
// out["tls"] (except ssh, which never calls it).
func sbTLSParser(p *model.Proxy, out map[string]any) {
	tlsMap, ok := out["tls"].(map[string]any)
	if !ok {
		return
	}
	if sbTruthy(p.Get("tls")) {
		tlsMap["enabled"] = true
	}
	if v := p.GetString("servername"); v != "" {
		tlsMap["server_name"] = v
	}
	if v := p.GetString("peer"); v != "" {
		tlsMap["server_name"] = v
	}
	if v := p.GetString("sni"); v != "" {
		tlsMap["server_name"] = v
	}
	if sbTruthy(p.Get("skip-cert-verify")) {
		tlsMap["insecure"] = true
	}
	if sbTruthy(p.Get("insecure")) {
		tlsMap["insecure"] = true
	}
	if sbTruthy(p.Get("disable-sni")) {
		tlsMap["disable_sni"] = true
	}
	switch alpn := p.Get("alpn").(type) {
	case string:
		tlsMap["alpn"] = []any{alpn}
	case []any:
		tlsMap["alpn"] = alpn
	}
	if v := p.Get("ca"); sbTruthy(v) {
		tlsMap["certificate_path"] = str(v)
	}
	if v := p.Get("ca_str"); sbTruthy(v) {
		tlsMap["certificate"] = []any{str(v)}
	}
	if v := p.Get("ca-str"); sbTruthy(v) {
		tlsMap["certificate"] = []any{str(v)}
	}
	if ro := p.GetMap("reality-opts"); ro != nil {
		reality := map[string]any{"enabled": true}
		if v := ro["public-key"]; sbTruthy(v) {
			reality["public_key"] = str(v)
		}
		if v := ro["short-id"]; sbTruthy(v) {
			reality["short_id"] = str(v)
		}
		tlsMap["reality"] = reality
		tlsMap["utls"] = map[string]any{"enabled": true}
	}
	if typ := p.Type(); typ != "hysteria" && typ != "hysteria2" && typ != "tuic" {
		if cf := p.Get("client-fingerprint"); sbTruthy(cf) && str(cf) != "" {
			if fp := sbGetUtlsFingerprint(cf); fp != "" {
				utls, _ := tlsMap["utls"].(map[string]any)
				if utls == nil {
					utls = map[string]any{}
				}
				utls["enabled"] = true
				utls["fingerprint"] = fp
				tlsMap["utls"] = utls
			}
		}
	}
	if m, ok := p.Get("_ech").(map[string]any); ok {
		tlsMap["ech"] = cloneAny(m)
	} else if eo := p.GetMap("ech-opts"); eo != nil {
		echMap, _ := tlsMap["ech"].(map[string]any)
		if echMap == nil {
			echMap = map[string]any{}
		}
		if v := eo["enable"]; v != nil {
			echMap["enabled"] = v
		}
		switch cfg := eo["config"].(type) {
		case []any:
			if lines := sbNormalizePemLines(cfg); lines != nil {
				echMap["config"] = lines
			}
		case string:
			if lines := sbNormalizePemLines(cfg); lines != nil {
				echMap["config"] = lines
			}
		}
		sbSetIf(echMap, "query_server_name", eo["query-server-name"])
		sbSetIf(echMap, "config_path", eo["config-path"])
		sbSetIf(echMap, "fragment", eo["fragment"])
		sbSetIf(echMap, "fragment_fallback_delay", eo["fragment-fallback-delay"])
		sbSetIf(echMap, "record_fragment", eo["record-fragment"])
		tlsMap["ech"] = echMap
	}
	if arr, ok := p.Get("_curve_preferences").([]any); ok {
		tlsMap["curve_preferences"] = arr
	}
	if sbTruthy(p.Get("_fragment")) {
		tlsMap["fragment"] = true
	}
	if v := p.Get("_fragment_fallback_delay"); sbTruthy(v) {
		tlsMap["fragment_fallback_delay"] = v
	}
	if sbTruthy(p.Get("_record_fragment")) {
		tlsMap["record_fragment"] = true
	}
	sbSetIf(tlsMap, "certificate", p.Get("_certificate"))
	sbSetIf(tlsMap, "certificate_path", p.Get("_certificate_path"))
	sbSetIf(tlsMap, "certificate_public_key_sha256", p.Get("_certificate_public_key_sha256"))
	sbSetIf(tlsMap, "client_certificate", p.Get("_client_certificate"))
	sbSetIf(tlsMap, "client_certificate_path", p.Get("_client_certificate_path"))
	sbSetIf(tlsMap, "client_key", p.Get("_client_key"))
	sbSetIf(tlsMap, "client_key_path", p.Get("_client_key_path"))
	if !sbTruthy(tlsMap["enabled"]) {
		delete(out, "tls")
	}
}

// ---------------------------------------------------------------------------
// transports (sing-box.js wsParser / h1Parser / h2Parser / grpcParser)
// ---------------------------------------------------------------------------

// sbHeaderArray normalizes a raw header map into key -> []any.
func sbHeaderArray(raw map[string]any) map[string]any {
	headers := map[string]any{}
	for _, k := range sbSortedKeys(raw) {
		value := raw[k]
		if s, isStr := value.(string); isStr && s == "" {
			continue
		}
		if arr, isArr := value.([]any); isArr {
			if len(arr) > 0 {
				headers[k] = cloneAny(arr)
			}
			continue
		}
		headers[k] = []any{str(value)}
	}
	return headers
}

// sbSplitHostHeader mirrors the `Host:${wsHost[0]}` multiline split; a line
// without ':' throws in JS, so it is an error here.
func sbSplitHostHeader(headers map[string]any) error {
	hostArr, ok := headers["Host"].([]any)
	if !ok {
		return fmt.Errorf("Host header is missing")
	}
	if len(hostArr) != 1 {
		return nil
	}
	for _, line := range strings.Split("Host:"+str(hostArr[0]), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			return fmt.Errorf("invalid Host header")
		}
		if strings.TrimSpace(value) == "" {
			continue
		}
		headers[strings.TrimSpace(key)] = sbSplitTrim(strings.TrimSpace(value), ",")
	}
	return nil
}

// sbGetPathQueryParam mirrors getPathQueryParam in transport-path.js.
func sbGetPathQueryParam(path, name string) string {
	qIdx := strings.IndexByte(path, '?')
	if qIdx == -1 {
		return ""
	}
	for _, part := range strings.Split(path[qIdx+1:], "&") {
		if part == "" {
			continue
		}
		key, val, _ := strings.Cut(part, "=")
		decKey, err := url.PathUnescape(key)
		if err != nil || decKey != name {
			continue
		}
		if val == "" {
			continue
		}
		decVal, _ := url.PathUnescape(val)
		return decVal
	}
	return ""
}

// sbGetSafeIntegerPathQueryParam mirrors getSafeIntegerPathQueryParam.
func sbGetSafeIntegerPathQueryParam(path, name string) (string, int, bool) {
	value := sbGetPathQueryParam(path, name)
	if n, ok := parseSafeIntegerValue(value); ok {
		return value, n, true
	}
	return "", 0, false
}

func sbWSParser(p *model.Proxy, out map[string]any) error {
	transport := map[string]any{"type": "ws"}
	headers := map[string]any{}
	transport["headers"] = headers
	if wsOpts := p.GetMap("ws-opts"); wsOpts != nil {
		wsPath := ""
		if v := wsOpts["path"]; v != nil {
			wsPath = str(v)
		}
		if v := wsOpts["early-data-header-name"]; v != nil {
			transport["early_data_header_name"] = v
		}
		if v := wsOpts["max-early-data"]; sbTruthy(v) {
			transport["max_early_data"] = sbIntOrNull(v)
		}
		if wsPath != "" {
			transport["path"] = wsPath
		}
		wsHeaders, _ := wsOpts["headers"].(map[string]any)
		if wsHeaders == nil {
			wsHeaders = map[string]any{}
		}
		if len(wsHeaders) > 0 {
			for k, v := range sbHeaderArray(wsHeaders) {
				headers[k] = v
			}
			if _, ok := headers["Host"]; !ok {
				// JS: undefined.length throws and the node is skipped.
				return fmt.Errorf("Host header is missing")
			}
			if err := sbSplitHostHeader(headers); err != nil {
				return err
			}
		}
	}
	if wsHeaders := p.Get("ws-headers"); wsHeaders != nil {
		raw, _ := wsHeaders.(map[string]any)
		if raw == nil {
			raw = map[string]any{}
		}
		h2 := sbHeaderArray(raw)
		if _, ok := h2["Host"]; !ok {
			return fmt.Errorf("Host header is missing")
		}
		if err := sbSplitHostHeader(h2); err != nil {
			return err
		}
		for k, v := range h2 {
			headers[k] = v
		}
	}
	if wp := p.Get("ws-path"); wp != nil && str(wp) != "" {
		transport["path"] = str(wp)
	}
	if path, ok := transport["path"].(string); ok {
		if _, maxEarlyData, hasED := sbGetSafeIntegerPathQueryParam(path, "ed"); hasED {
			clean, _ := extractPathQueryParam(path, "ed")
			transport["path"] = clean
			transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
			transport["max_early_data"] = maxEarlyData
		}
	}
	if tlsMap, ok := out["tls"].(map[string]any); ok && sbTruthy(tlsMap["insecure"]) {
		hostArr, ok := headers["Host"].([]any)
		if !ok || len(hostArr) == 0 {
			return fmt.Errorf("Host header is missing")
		}
		tlsMap["server_name"] = hostArr[0]
	}
	if wsOpts := p.GetMap("ws-opts"); wsOpts != nil && sbTruthy(wsOpts["v2ray-http-upgrade"]) {
		transport["type"] = "httpupgrade"
		if hostArr, ok := headers["Host"].([]any); ok && len(hostArr) > 0 {
			transport["host"] = hostArr[0]
			delete(headers, "Host")
		}
		if v, ok := transport["max_early_data"]; ok && sbTruthy(v) {
			delete(transport, "max_early_data")
		}
		if v, ok := transport["early_data_header_name"]; ok && sbTruthy(v) {
			delete(transport, "early_data_header_name")
		}
	}
	for k, v := range headers {
		if arr, ok := v.([]any); ok && len(arr) == 1 {
			headers[k] = arr[0]
		}
	}
	out["transport"] = transport
	return nil
}

func sbH1Parser(p *model.Proxy, out map[string]any) error {
	transport := map[string]any{"type": "http"}
	headers := map[string]any{}
	transport["headers"] = headers
	if httpOpts := p.GetMap("http-opts"); httpOpts != nil {
		if method := httpOpts["method"]; method != nil && str(method) != "" {
			transport["method"] = str(method)
		}
		switch h1Path := httpOpts["path"].(type) {
		case []any:
			if len(h1Path) > 0 {
				transport["path"] = sbStrJS(h1Path[0])
			}
		case nil:
		default:
			if s := str(h1Path); s != "" {
				transport["path"] = s
			}
		}
		h1Headers, _ := httpOpts["headers"].(map[string]any)
		for _, k := range sbSortedKeys(h1Headers) {
			value := h1Headers[k]
			if s, isStr := value.(string); isStr && s == "" {
				continue
			}
			if strings.ToLower(k) == "host" {
				host := value
				if _, isArr := host.([]any); !isArr {
					host = sbSplitTrim(str(host), ",")
				}
				if arr, ok := host.([]any); ok && len(arr) > 0 {
					transport["host"] = host
				}
				continue
			}
			if _, isArr := value.([]any); !isArr {
				value = sbSplitTrim(str(value), ",")
			}
			if arr, ok := value.([]any); ok && len(arr) > 0 {
				headers[k] = value
			}
		}
	}
	if v := p.Get("http-host"); sbTruthy(v) {
		host := v
		if _, isArr := host.([]any); !isArr {
			host = sbSplitTrim(str(host), ",")
		}
		if arr, ok := host.([]any); ok && len(arr) > 0 {
			transport["host"] = host
		}
	}
	if v := p.Get("http-path"); sbTruthy(v) {
		switch path := v.(type) {
		case []any:
			if len(path) > 0 {
				transport["path"] = sbStrJS(path[0])
			}
		default:
			transport["path"] = str(v)
		}
	}
	if tlsMap, ok := out["tls"].(map[string]any); ok && sbTruthy(tlsMap["insecure"]) {
		hostArr, ok := transport["host"].([]any)
		if !ok || len(hostArr) == 0 {
			return fmt.Errorf("http host is missing")
		}
		tlsMap["server_name"] = hostArr[0]
	}
	if hostArr, ok := transport["host"].([]any); ok && len(hostArr) == 1 {
		transport["host"] = hostArr[0]
	}
	for k, v := range headers {
		if arr, ok := v.([]any); ok && len(arr) == 1 {
			headers[k] = arr[0]
		}
	}
	out["transport"] = transport
	return nil
}

func sbH2Parser(p *model.Proxy, out map[string]any) error {
	transport := map[string]any{"type": "http"}
	if h2Opts := p.GetMap("h2-opts"); h2Opts != nil {
		if path := h2Opts["path"]; path != nil && sbStrJS(path) != "" {
			transport["path"] = sbStrJS(path)
		}
		if host := h2Opts["host"]; host != nil && sbStrJS(host) != "" {
			if _, isArr := host.([]any); !isArr {
				host = sbSplitTrim(sbStrJS(host), ",")
			}
			if arr, ok := host.([]any); ok && len(arr) > 0 {
				transport["host"] = host
			}
		}
	}
	if v := p.Get("h2-host"); v != nil && sbStrJS(v) != "" {
		if _, isArr := v.([]any); !isArr {
			v = sbSplitTrim(sbStrJS(v), ",")
		}
		if arr, ok := v.([]any); ok && len(arr) > 0 {
			transport["host"] = v
		}
	}
	if v := p.Get("h2-path"); v != nil && sbStrJS(v) != "" {
		transport["path"] = sbStrJS(v)
	}
	if tlsMap, ok := out["tls"].(map[string]any); ok {
		tlsMap["enabled"] = true
		if sbTruthy(tlsMap["insecure"]) {
			hostArr, ok := transport["host"].([]any)
			if !ok || len(hostArr) == 0 {
				return fmt.Errorf("h2 host is missing")
			}
			tlsMap["server_name"] = hostArr[0]
		}
	}
	hostArr, ok := transport["host"].([]any)
	if !ok {
		// JS: transport.host.length throws and the node is skipped.
		return fmt.Errorf("h2 host is missing")
	}
	if len(hostArr) == 1 {
		transport["host"] = hostArr[0]
	}
	out["transport"] = transport
	return nil
}

func sbGRPCParser(p *model.Proxy, out map[string]any) {
	transport := map[string]any{"type": "grpc"}
	if g := p.GetMap("grpc-opts"); g != nil {
		if sn := g["grpc-service-name"]; sn != nil && str(sn) != "" {
			transport["service_name"] = str(sn)
		}
	}
	out["transport"] = transport
}

// ---------------------------------------------------------------------------
// per-protocol parsers
// ---------------------------------------------------------------------------

func sbSSHParser(p *model.Proxy) (map[string]any, error) {
	out := map[string]any{
		"tag":         p.GetString("name"),
		"type":        "ssh",
		"server":      p.Server(),
		"server_port": sbServerPortAny(p),
	}
	if err := sbCheckPort(out["server_port"]); err != nil {
		return nil, err
	}
	if v := p.Get("username"); sbTruthy(v) {
		out["user"] = str(v)
	}
	if v := p.Get("password"); sbTruthy(v) {
		out["password"] = str(v)
	}
	if v := p.GetString("privateKey"); v != "" {
		out["private_key_path"] = v
	}
	if v := p.GetString("private-key"); v != "" {
		out["private_key_path"] = v
	}
	if v := p.Get("private-key-passphrase"); sbTruthy(v) {
		out["private_key_passphrase"] = str(v)
	}
	if v := p.GetString("server-fingerprint"); v != "" {
		out["host_key"] = []any{v}
		out["host_key_algorithms"] = []any{strings.Split(v, " ")[0]}
	}
	sbSetIf(out, "host_key", p.Get("host-key"))
	sbSetIf(out, "host_key_algorithms", p.Get("host-key-algorithms"))
	if sbTruthy(p.Get("fast-open")) {
		out["udp_fragment"] = true
	}
	sbTFOParser(p, out)
	sbDetourParser(p, out)
	sbIPVersionParser(p, out)
	sbDomainResolverParser(p, out)
	return out, nil
}

func sbHTTPParser(p *model.Proxy) (map[string]any, error) {
	out := map[string]any{
		"tag":         p.GetString("name"),
		"type":        "http",
		"server":      p.Server(),
		"server_port": sbServerPortAny(p),
		"tls":         sbTlsInit(false, p),
	}
	if err := sbCheckPort(out["server_port"]); err != nil {
		return nil, err
	}
	if v := p.Get("username"); sbTruthy(v) {
		out["username"] = str(v)
	}
	if v := p.Get("password"); sbTruthy(v) {
		out["password"] = str(v)
	}
	if headers := p.GetMap("headers"); headers != nil && len(headers) > 0 {
		h := map[string]any{}
		for _, k := range sbSortedKeys(headers) {
			h[k] = str(headers[k])
		}
		out["headers"] = h
	}
	if sbTruthy(p.Get("fast-open")) {
		out["udp_fragment"] = true
	}
	sbTFOParser(p, out)
	sbDetourParser(p, out)
	sbTLSParser(p, out)
	sbIPVersionParser(p, out)
	sbDomainResolverParser(p, out)
	return out, nil
}

func sbSocks5Parser(p *model.Proxy) (map[string]any, error) {
	out := map[string]any{
		"tag":         p.GetString("name"),
		"type":        "socks",
		"server":      p.Server(),
		"server_port": sbServerPortAny(p),
		"version":     "5",
	}
	if err := sbCheckPort(out["server_port"]); err != nil {
		return nil, err
	}
	if v := p.Get("username"); sbTruthy(v) {
		out["username"] = str(v)
	}
	if v := p.Get("password"); sbTruthy(v) {
		out["password"] = str(v)
	}
	if uot := sbUDPOverTCP(p); uot != nil {
		out["udp_over_tcp"] = uot
	}
	if sbTruthy(p.Get("fast-open")) {
		out["udp_fragment"] = true
	}
	sbNetworkParser(p, out)
	sbTFOParser(p, out)
	sbDetourParser(p, out)
	sbIPVersionParser(p, out)
	sbDomainResolverParser(p, out)
	return out, nil
}

func sbShadowTLSTag(p *model.Proxy) string { return p.GetString("name") + "_shadowtls" }

func sbShadowTLSPluginOpts(p *model.Proxy) map[string]any {
	if p.GetString("plugin") == "shadow-tls" {
		if opts := p.GetMap("plugin-opts"); opts != nil {
			return opts
		}
		return nil
	}
	if p.Type() == "snell" {
		if obfsOpts := p.GetMap("obfs-opts"); obfsOpts != nil && str(obfsOpts["mode"]) == "shadow-tls" {
			return map[string]any{
				"host":     obfsOpts["host"],
				"password": obfsOpts["password"],
				"version":  obfsOpts["version"],
				"alpn":     obfsOpts["alpn"],
			}
		}
	}
	return nil
}

func sbNormalizeALPN(alpn any) []any {
	if s, ok := alpn.(string); ok {
		out := []any{}
		for _, item := range strings.Split(s, ",") {
			t := strings.TrimSpace(item)
			if t != "" {
				out = append(out, t)
			}
		}
		return out
	}
	if arr, ok := alpn.([]any); ok {
		return arr
	}
	return nil
}

func sbShadowTLSOutboundParser(p *model.Proxy, pluginOpts map[string]any) (map[string]any, error) {
	if pluginOpts == nil {
		return nil, fmt.Errorf("shadow-tls plugin options are missing")
	}
	fingerprint := sbGetUtlsFingerprint(p.Get("client-fingerprint"))
	tlsMap := map[string]any{"enabled": true}
	sbSetIf(tlsMap, "server_name", pluginOpts["host"])
	st := map[string]any{
		"tag":         sbShadowTLSTag(p),
		"type":        "shadowtls",
		"server":      p.Server(),
		"server_port": sbServerPortAny(p),
		"tls":         tlsMap,
	}
	sbSetIf(st, "version", pluginOpts["version"])
	sbSetIf(st, "password", pluginOpts["password"])
	if sbTruthy(p.Get("skip-cert-verify")) {
		tlsMap["insecure"] = true
	}
	if fingerprint != "" {
		tlsMap["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
	}
	if err := sbCheckPort(st["server_port"]); err != nil {
		return nil, err
	}
	alpn := sbNormalizeALPN(pluginOpts["alpn"])
	if alpn == nil {
		alpn = sbNormalizeALPN(p.Get("alpn"))
	}
	if alpn != nil {
		tlsMap["alpn"] = alpn
	}
	if b, ok := p.Get("fast-open").(bool); ok && b {
		st["udp_fragment"] = true
	}
	sbTFOParser(p, st)
	sbDetourParser(p, st)
	sbIPVersionParser(p, st)
	sbDomainResolverParser(p, st)
	return st, nil
}

func sbShadowTLSParser(p *model.Proxy) (map[string]any, map[string]any, error) {
	pluginOpts := sbShadowTLSPluginOpts(p)
	ssPart := map[string]any{
		"tag":      p.GetString("name"),
		"type":     "shadowsocks",
		"method":   p.Get("cipher"),
		"password": p.Get("password"),
		"detour":   sbShadowTLSTag(p),
	}
	for _, k := range []string{"method", "password"} {
		if ssPart[k] == nil {
			delete(ssPart, k)
		}
	}
	if uot := sbUDPOverTCP(p); uot != nil {
		ssPart["udp_over_tcp"] = uot
	}
	sbNetworkParser(p, ssPart)
	sbSmuxParser(p.GetMap("smux"), ssPart)
	stPart, err := sbShadowTLSOutboundParser(p, pluginOpts)
	if err != nil {
		return nil, nil, err
	}
	return ssPart, stPart, nil
}

func sbSSParser(p *model.Proxy) (map[string]any, error) {
	out := map[string]any{
		"tag":         p.GetString("name"),
		"type":        "shadowsocks",
		"server":      p.Server(),
		"server_port": sbServerPortAny(p),
	}
	sbSetIf(out, "method", p.Get("cipher"))
	sbSetIf(out, "password", p.Get("password"))
	if err := sbCheckPort(out["server_port"]); err != nil {
		return nil, err
	}
	if uot := sbUDPOverTCP(p); uot != nil {
		out["udp_over_tcp"] = uot
	}
	if sbTruthy(p.Get("fast-open")) {
		out["udp_fragment"] = true
	}
	sbNetworkParser(p, out)
	sbTFOParser(p, out)
	sbDetourParser(p, out)
	sbSmuxParser(p.GetMap("smux"), out)
	sbIPVersionParser(p, out)
	sbDomainResolverParser(p, out)
	if plugin := p.Get("plugin"); sbTruthy(plugin) {
		optArr := []string{}
		switch str(plugin) {
		case "obfs":
			out["plugin"] = "obfs-local"
			opts := p.GetMap("plugin-opts")
			if opts == nil {
				return nil, fmt.Errorf("obfs plugin-opts are missing")
			}
			if obfsHost := p.Get("obfs-host"); sbTruthy(obfsHost) {
				opts["host"] = obfsHost
			}
			for _, k := range sbSortedKeys(opts) {
				switch k {
				case "mode":
					optArr = append(optArr, "obfs="+str(opts["mode"]))
				case "host":
					optArr = append(optArr, "obfs-host="+str(opts["host"]))
				default:
					optArr = append(optArr, k+"="+str(opts[k]))
				}
			}
		case "v2ray-plugin":
			out["plugin"] = "v2ray-plugin"
			opts := p.GetMap("plugin-opts")
			if opts == nil {
				return nil, fmt.Errorf("v2ray-plugin plugin-opts are missing")
			}
			if v := p.Get("ws-host"); sbTruthy(v) {
				opts["host"] = v
			}
			if v := p.Get("ws-path"); sbTruthy(v) {
				opts["path"] = v
			}
			for _, k := range sbSortedKeys(opts) {
				switch k {
				case "tls":
					if sbTruthy(opts["tls"]) {
						optArr = append(optArr, "tls")
					}
				case "host":
					optArr = append(optArr, "host="+str(opts["host"]))
				case "path":
					optArr = append(optArr, "path="+str(opts["path"]))
				case "headers":
					optArr = append(optArr, "headers="+sbJSONString(opts["headers"]))
				case "mux":
					mux := normalizePluginMuxValue(opts["mux"])
					if sbTruthy(mux) {
						out["multiplex"] = map[string]any{"enabled": true}
					}
					optArr = append(optArr, fmt.Sprintf("mux=%s", sbStrJS(mux)))
				default:
					optArr = append(optArr, k+"="+str(opts[k]))
				}
			}
		}
		out["plugin_opts"] = strings.Join(optArr, ";")
	}
	return out, nil
}

func sbSSRParser(p *model.Proxy) (map[string]any, error) {
	out := map[string]any{
		"tag":         p.GetString("name"),
		"type":        "shadowsocksr",
		"server":      p.Server(),
		"server_port": sbServerPortAny(p),
	}
	sbSetIf(out, "method", p.Get("cipher"))
	sbSetIf(out, "password", p.Get("password"))
	sbSetIf(out, "obfs", p.Get("obfs"))
	sbSetIf(out, "protocol", p.Get("protocol"))
	if err := sbCheckPort(out["server_port"]); err != nil {
		return nil, err
	}
	if v := p.Get("obfs-param"); sbTruthy(v) {
		out["obfs_param"] = v
	}
	if v := p.Get("protocol-param"); sbTruthy(v) && str(v) != "" {
		out["protocol_param"] = v
	}
	if sbTruthy(p.Get("fast-open")) {
		out["udp_fragment"] = true
	}
	sbNetworkParser(p, out)
	sbTFOParser(p, out)
	sbDetourParser(p, out)
	sbSmuxParser(p.GetMap("smux"), out)
	sbIPVersionParser(p, out)
	sbDomainResolverParser(p, out)
	return out, nil
}

// sbGetSnellVersion mirrors getSnellVersion: (value, present, isNaN).
func sbGetSnellVersion(version any) (int, bool, bool) {
	if version == nil {
		return 0, false, false
	}
	normalized := strings.TrimSpace(str(version))
	if !allDigits(normalized) {
		return 0, true, true
	}
	n, err := strconv.Atoi(normalized)
	if err != nil {
		return 0, true, true
	}
	return n, true, false
}

func sbSnellParser(p *model.Proxy, includeUnsupported bool) (map[string]any, error) {
	version, hasVersion, isNaN := sbGetSnellVersion(p.Get("version"))
	shadowTLSPluginOpts := sbShadowTLSPluginOpts(p)
	supportedMin := 4
	if includeUnsupported {
		supportedMin = 1
	}
	if hasVersion && (isNaN || version < supportedMin || version > 6) {
		return nil, fmt.Errorf("Platform sing-box does not support snell version %s", str(p.Get("version")))
	}
	outputVersion := version
	if !includeUnsupported && hasVersion && version == 5 {
		outputVersion = 4
	}
	out := map[string]any{
		"tag":         p.GetString("name"),
		"type":        "snell",
		"server":      p.Server(),
		"server_port": sbServerPortAny(p),
	}
	sbSetIf(out, "psk", p.Get("psk"))
	if err := sbCheckPort(out["server_port"]); err != nil {
		return nil, err
	}
	if hasVersion {
		out["version"] = outputVersion
	}
	if v := p.Get("_userkey"); sbTruthy(v) {
		out["userkey"] = v
	}
	if hasVersion && outputVersion == 6 {
		if v := p.Get("mode"); sbTruthy(v) {
			out["mode"] = v
		}
		if includeUnsupported {
			if v := p.Get("quic-proxy-mode"); sbTruthy(v) {
				out["quic_proxy_mode"] = true
			}
		}
	} else {
		mode := ""
		host := ""
		if obfsOpts := p.GetMap("obfs-opts"); obfsOpts != nil {
			mode = str(obfsOpts["mode"])
			host = str(obfsOpts["host"])
		}
		if mode != "" && mode != "shadow-tls" {
			out["obfs_mode"] = mode
		}
		if host != "" && mode != "shadow-tls" {
			out["obfs_host"] = host
		}
	}
	if sbTruthy(p.Get("reuse")) && (p.Get("version") == nil || (!isNaN && version >= 4)) {
		out["reuse"] = true
	}
	sbNetworkParser(p, out)
	if shadowTLSPluginOpts != nil {
		out["detour"] = sbShadowTLSTag(p)
		delete(out, "server")
		delete(out, "server_port")
	} else {
		if sbTruthy(p.Get("fast-open")) {
			out["udp_fragment"] = true
		}
		sbTFOParser(p, out)
		sbDetourParser(p, out)
		sbIPVersionParser(p, out)
		sbDomainResolverParser(p, out)
	}
	return out, nil
}

var sbPacketEncodings = map[string]bool{"": true, "packetaddr": true, "xudp": true}

func sbVmessVlessPacketEncoding(p *model.Proxy, out map[string]any) {
	if v := p.Get("packet-encoding"); v != nil {
		pe := strings.ToLower(strings.TrimSpace(str(v)))
		if sbPacketEncodings[pe] {
			out["packet_encoding"] = pe
		}
	} else if sbTruthy(p.Get("xudp")) {
		out["packet_encoding"] = "xudp"
	} else if sbTruthy(p.Get("packet-addr")) {
		out["packet_encoding"] = "packetaddr"
	}
}

func sbVmessProtocolOptions(p *model.Proxy, out map[string]any) {
	sbVmessVlessPacketEncoding(p, out)
	if v := p.Get("global-padding"); v != nil {
		out["global_padding"] = sbTruthy(v)
	}
	if v := p.Get("authenticated-length"); v != nil {
		out["authenticated_length"] = sbTruthy(v)
	}
}

func sbVMessParser(p *model.Proxy) (map[string]any, error) {
	out := map[string]any{
		"tag":         p.GetString("name"),
		"type":        "vmess",
		"server":      p.Server(),
		"server_port": sbServerPortAny(p),
		"security":    vmessSecurityCommon(p.GetString("cipher")),
		"alter_id":    sbIntOrNull(p.Get("alterId")),
		"tls":         sbTlsInit(false, p),
	}
	sbSetIf(out, "uuid", p.Get("uuid"))
	if err := sbCheckPort(out["server_port"]); err != nil {
		return nil, err
	}
	sbVmessProtocolOptions(p, out)
	if sbTruthy(p.Get("fast-open")) {
		out["udp_fragment"] = true
	}
	var err error
	switch p.GetString("network") {
	case "ws":
		err = sbWSParser(p, out)
	case "h2":
		err = sbH2Parser(p, out)
	case "http":
		err = sbH1Parser(p, out)
	case "grpc":
		sbGRPCParser(p, out)
	}
	if err != nil {
		return nil, err
	}
	sbNetworkParser(p, out)
	sbTFOParser(p, out)
	sbDetourParser(p, out)
	sbTLSParser(p, out)
	sbSmuxParser(p.GetMap("smux"), out)
	sbIPVersionParser(p, out)
	sbDomainResolverParser(p, out)
	return out, nil
}

func sbVLESSParser(p *model.Proxy) (map[string]any, error) {
	out := map[string]any{
		"tag":         p.GetString("name"),
		"type":        "vless",
		"server":      p.Server(),
		"server_port": sbServerPortAny(p),
		"tls":         sbTlsInit(false, p),
	}
	sbSetIf(out, "uuid", p.Get("uuid"))
	if err := sbCheckPort(out["server_port"]); err != nil {
		return nil, err
	}
	sbVmessVlessPacketEncoding(p, out)
	if sbTruthy(p.Get("fast-open")) {
		out["udp_fragment"] = true
	}
	sbSetIf(out, "flow", p.Get("flow"))
	var err error
	switch p.GetString("network") {
	case "ws":
		err = sbWSParser(p, out)
	case "h2":
		err = sbH2Parser(p, out)
	case "http":
		err = sbH1Parser(p, out)
	case "grpc":
		sbGRPCParser(p, out)
	}
	if err != nil {
		return nil, err
	}
	sbNetworkParser(p, out)
	sbTFOParser(p, out)
	sbDetourParser(p, out)
	sbSmuxParser(p.GetMap("smux"), out)
	sbTLSParser(p, out)
	sbIPVersionParser(p, out)
	sbDomainResolverParser(p, out)
	return out, nil
}

func sbTrojanParser(p *model.Proxy) (map[string]any, error) {
	out := map[string]any{
		"tag":         p.GetString("name"),
		"type":        "trojan",
		"server":      p.Server(),
		"server_port": sbServerPortAny(p),
		"tls":         sbTlsInit(true, p),
	}
	sbSetIf(out, "password", p.Get("password"))
	if err := sbCheckPort(out["server_port"]); err != nil {
		return nil, err
	}
	if sbTruthy(p.Get("fast-open")) {
		out["udp_fragment"] = true
	}
	switch p.GetString("network") {
	case "grpc":
		sbGRPCParser(p, out)
	case "ws":
		if err := sbWSParser(p, out); err != nil {
			return nil, err
		}
	}
	sbNetworkParser(p, out)
	sbTFOParser(p, out)
	sbDetourParser(p, out)
	sbTLSParser(p, out)
	sbSmuxParser(p.GetMap("smux"), out)
	sbIPVersionParser(p, out)
	sbDomainResolverParser(p, out)
	return out, nil
}

func sbNaiveParser(p *model.Proxy) (map[string]any, error) {
	out := map[string]any{
		"tag":         p.GetString("name"),
		"type":        "naive",
		"server":      p.Server(),
		"server_port": sbServerPortAny(p),
		"tls":         sbTlsInit(true, p),
	}
	if err := sbCheckPort(out["server_port"]); err != nil {
		return nil, err
	}
	if v := p.Get("username"); sbTruthy(v) {
		out["username"] = str(v)
	}
	if v := p.Get("password"); sbTruthy(v) {
		out["password"] = str(v)
	}
	if uot := sbUDPOverTCP(p); uot != nil {
		out["udp_over_tcp"] = uot
	}
	if n, ok := sbParseInt(p.Get("insecure-concurrency")); ok && n >= 0 {
		out["insecure_concurrency"] = n
	}
	if v := p.Get("extra-headers"); sbTruthy(v) {
		out["extra_headers"] = v
	}
	if v := p.Get("quic"); sbTruthy(v) {
		out["quic"] = true
	}
	if v := p.Get("quic-congestion-control"); sbTruthy(v) {
		out["quic_congestion_control"] = v
	}
	if sbTruthy(p.Get("fast-open")) {
		out["udp_fragment"] = true
	}
	sbTFOParser(p, out)
	sbDetourParser(p, out)
	sbTLSParser(p, out)
	sbSmuxParser(p.GetMap("smux"), out)
	sbIPVersionParser(p, out)
	sbDomainResolverParser(p, out)
	if tlsMap, ok := out["tls"].(map[string]any); ok && sbTruthy(tlsMap["insecure"]) {
		delete(tlsMap, "insecure")
	}
	return out, nil
}

var sbBpsRegexp = regexp.MustCompile(`^[0-9]+[ \t]*[KMGT]*[Bb]ps$`)

func sbHopInterval(v any) any {
	s := str(v)
	if allDigits(s) {
		return s + "s"
	}
	return s
}

// sbServerPorts mirrors `ports.split(/\s*,\s*/)` → ["1:3","5:5"].
func sbServerPorts(ports string) []any {
	out := []any{}
	for _, part := range strings.Split(ports, ",") {
		p := strings.TrimSpace(part)
		rangeStr := strings.TrimSpace(regexp.MustCompile(`\s*-\s*`).ReplaceAllString(p, ":"))
		if strings.Contains(rangeStr, ":") {
			out = append(out, rangeStr)
		} else {
			out = append(out, rangeStr+":"+rangeStr)
		}
	}
	return out
}

func sbHysteriaParser(p *model.Proxy) (map[string]any, error) {
	out := map[string]any{
		"tag":                   p.GetString("name"),
		"type":                  "hysteria",
		"server":                p.Server(),
		"server_port":           sbServerPortAny(p),
		"disable_mtu_discovery": false,
		"tls":                   sbTlsInit(true, p),
	}
	if err := sbCheckPort(out["server_port"]); err != nil {
		return nil, err
	}
	if v := p.Get("hop-interval"); sbTruthy(v) {
		out["hop_interval"] = sbHopInterval(v)
	}
	if v := p.Get("ports"); sbTruthy(v) {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("invalid ports for proxy %s", p.Name())
		}
		out["server_ports"] = sbServerPorts(s)
	}
	if v := p.Get("auth_str"); sbTruthy(v) {
		out["auth_str"] = str(v)
	}
	if v := p.Get("auth-str"); sbTruthy(v) {
		out["auth_str"] = str(v)
	}
	if sbTruthy(p.Get("fast-open")) {
		out["udp_fragment"] = true
	}
	up := str(p.Get("up"))
	if sbBpsRegexp.MatchString(up) && !strings.HasSuffix(up, "Mbps") {
		out["up"] = up
	} else {
		out["up_mbps"] = sbIntOrNull(p.Get("up"))
	}
	down := str(p.Get("down"))
	if sbBpsRegexp.MatchString(down) && !strings.HasSuffix(down, "Mbps") {
		out["down"] = down
	} else {
		out["down_mbps"] = sbIntOrNull(p.Get("down"))
	}
	if v := p.Get("obfs"); sbTruthy(v) {
		out["obfs"] = v
	}
	if v := p.Get("recv_window_conn"); sbTruthy(v) {
		out["recv_window_conn"] = v
	}
	if v := p.Get("recv-window-conn"); sbTruthy(v) {
		out["recv_window_conn"] = v
	}
	if v := p.Get("recv_window"); sbTruthy(v) {
		out["recv_window"] = v
	}
	if v := p.Get("recv-window"); sbTruthy(v) {
		out["recv_window"] = v
	}
	if v := p.Get("disable_mtu_discovery"); sbTruthy(v) {
		switch t := v.(type) {
		case bool:
			out["disable_mtu_discovery"] = t
		case int:
			if t == 1 {
				out["disable_mtu_discovery"] = true
			}
		case float64:
			if t == 1 {
				out["disable_mtu_discovery"] = true
			}
		case json.Number:
			if f, _ := t.Float64(); f == 1 {
				out["disable_mtu_discovery"] = true
			}
		}
	}
	sbNetworkParser(p, out)
	sbTLSParser(p, out)
	sbDetourParser(p, out)
	sbTFOParser(p, out)
	sbSmuxParser(p.GetMap("smux"), out)
	sbIPVersionParser(p, out)
	sbDomainResolverParser(p, out)
	return out, nil
}

func sbHysteria2Parser(p *model.Proxy) (map[string]any, error) {
	out := map[string]any{
		"tag":         p.GetString("name"),
		"type":        "hysteria2",
		"server":      p.Server(),
		"server_port": sbServerPortAny(p),
		"obfs":        map[string]any{},
		"tls":         sbTlsInit(true, p),
	}
	sbSetIf(out, "password", p.Get("password"))
	if err := sbCheckPort(out["server_port"]); err != nil {
		return nil, err
	}
	if v := p.Get("hop-interval"); sbTruthy(v) {
		out["hop_interval"] = sbHopInterval(v)
	}
	if v := p.Get("ports"); sbTruthy(v) {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("invalid ports for proxy %s", p.Name())
		}
		out["server_ports"] = sbServerPorts(s)
	}
	if v := p.Get("up"); sbTruthy(v) {
		out["up_mbps"] = sbIntOrNull(v)
	}
	if v := p.Get("down"); sbTruthy(v) {
		out["down_mbps"] = sbIntOrNull(v)
	}
	obfsMap := out["obfs"].(map[string]any)
	obfs := p.GetString("obfs")
	if obfs == "salamander" || obfs == "gecko" {
		obfsMap["type"] = obfs
	}
	if obfs == "gecko" {
		minRaw := p.Get("obfs-min-packet-size")
		maxRaw := p.Get("obfs-max-packet-size")
		hasMin := minRaw != nil && str(minRaw) != ""
		hasMax := maxRaw != nil && str(maxRaw) != ""
		if hasMin || hasMax {
			minPacketSize, minOK := 0, false
			rawMax, maxOK := 0, false
			if hasMin {
				minPacketSize, minOK = parseSafeIntegerValue(minRaw)
			}
			if hasMax {
				rawMax, maxOK = parseSafeIntegerValue(maxRaw)
			}
			maxPacketSize := rawMax
			if maxOK && rawMax > 2048 {
				maxPacketSize = 2048
			}
			effectiveMin := 512
			if minOK {
				effectiveMin = minPacketSize
			}
			effectiveMax := 1200
			if maxOK {
				effectiveMax = maxPacketSize
			}
			invalid := (hasMin && (!minOK || minPacketSize <= 0)) ||
				(hasMax && (!maxOK || rawMax <= 0)) ||
				effectiveMax < effectiveMin
			if !invalid {
				if hasMin {
					obfsMap["min_packet_size"] = minPacketSize
				}
				if hasMax {
					obfsMap["max_packet_size"] = maxPacketSize
				}
			}
		}
	}
	if v := p.Get("obfs-password"); sbTruthy(v) {
		obfsMap["password"] = str(v)
	}
	if _, ok := obfsMap["type"]; !ok {
		delete(out, "obfs")
	}
	if v := p.Get("bbr-profile"); sbTruthy(v) {
		out["bbr_profile"] = v
	}
	if v := p.Get("disable-chrome-parrot"); sbTruthy(v) {
		out["disable_chrome_parrot"] = true
	}
	sbNetworkParser(p, out)
	sbTLSParser(p, out)
	sbTFOParser(p, out)
	sbDetourParser(p, out)
	sbSmuxParser(p.GetMap("smux"), out)
	sbIPVersionParser(p, out)
	sbDomainResolverParser(p, out)
	return out, nil
}

func sbTUIC5Parser(p *model.Proxy) (map[string]any, error) {
	out := map[string]any{
		"tag":         p.GetString("name"),
		"type":        "tuic",
		"server":      p.Server(),
		"server_port": sbServerPortAny(p),
		"tls":         sbTlsInit(true, p),
	}
	sbSetIf(out, "uuid", p.Get("uuid"))
	sbSetIf(out, "password", p.Get("password"))
	if err := sbCheckPort(out["server_port"]); err != nil {
		return nil, err
	}
	if sbTruthy(p.Get("fast-open")) {
		out["udp_fragment"] = true
	}
	if cc := p.GetString("congestion-controller"); cc != "" && cc != "cubic" {
		out["congestion_control"] = cc
	}
	if um := p.GetString("udp-relay-mode"); um != "" && um != "native" {
		out["udp_relay_mode"] = um
	}
	if sbTruthy(p.Get("reduce-rtt")) {
		out["zero_rtt_handshake"] = true
	}
	if sbTruthy(p.Get("udp-over-stream")) {
		out["udp_over_stream"] = true
	}
	if v := p.Get("heartbeat-interval"); sbTruthy(v) {
		out["heartbeat"] = str(v) + "ms"
	}
	sbNetworkParser(p, out)
	sbTFOParser(p, out)
	sbDetourParser(p, out)
	sbTLSParser(p, out)
	sbSmuxParser(p.GetMap("smux"), out)
	sbIPVersionParser(p, out)
	sbDomainResolverParser(p, out)
	return out, nil
}

func sbAnytlsParser(p *model.Proxy) (map[string]any, error) {
	out := map[string]any{
		"tag":         p.GetString("name"),
		"type":        "anytls",
		"server":      p.Server(),
		"server_port": sbServerPortAny(p),
		"tls":         sbTlsInit(true, p),
	}
	sbSetIf(out, "password", p.Get("password"))
	if v := p.Get("client-metadata"); sbTruthy(v) {
		out["client_metadata"] = str(v)
	}
	if allDigits(str(p.Get("idle-session-check-interval"))) {
		out["idle_session_check_interval"] = str(p.Get("idle-session-check-interval")) + "s"
	}
	if allDigits(str(p.Get("idle-session-timeout"))) {
		out["idle_session_timeout"] = str(p.Get("idle-session-timeout")) + "s"
	}
	if allDigits(str(p.Get("min-idle-session"))) {
		out["min_idle_session"] = sbIntOrNull(p.Get("min-idle-session"))
	}
	if v := p.Get("disable-reuse"); v != nil {
		out["disable_reuse"] = sbTruthy(v)
	}
	sbDetourParser(p, out)
	sbTLSParser(p, out)
	sbIPVersionParser(p, out)
	sbDomainResolverParser(p, out)
	return out, nil
}

func sbHasControlHTTPClient(p *model.Proxy) bool {
	v := p.Get("control-http-client")
	if v == nil {
		return false
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s) != ""
	}
	if m, ok := v.(map[string]any); ok {
		for _, item := range m {
			if item != nil && str(item) != "" {
				return true
			}
		}
		return false
	}
	return true
}

func sbTailscaleParser(p *model.Proxy) map[string]any {
	useControlHTTPClient := sbHasControlHTTPClient(p)
	out := map[string]any{
		"tag":   p.GetString("name"),
		"type":  "tailscale",
	}
	sbSetIf(out, "control_http_client", p.Get("control-http-client"))
	sbSetIf(out, "udp_timeout", p.Get("udp-timeout"))
	stateDir := p.Get("state-dir")
	if !sbTruthy(stateDir) {
		stateDir = p.Get("state-directory")
	}
	sbSetIf(out, "state_directory", stateDir)
	sbSetIf(out, "auth_key", p.Get("auth-key"))
	sbSetIf(out, "control_url", p.Get("control-url"))
	sbSetIf(out, "ephemeral", p.Get("ephemeral"))
	sbSetIf(out, "hostname", p.Get("hostname"))
	sbSetIf(out, "accept_routes", p.Get("accept-routes"))
	sbSetIf(out, "exit_node", p.Get("exit-node"))
	sbSetIf(out, "exit_node_allow_lan_access", p.Get("exit-node-allow-lan-access"))
	if arr, ok := p.Get("advertise-routes").([]any); ok {
		out["advertise_routes"] = arr
	}
	sbSetIf(out, "advertise_exit_node", p.Get("advertise-exit-node"))
	if arr, ok := p.Get("advertise-tags").([]any); ok {
		out["advertise_tags"] = arr
	}
	if arr, ok := p.Get("relay-server-static-endpoints").([]any); ok {
		out["relay_server_static_endpoints"] = arr
	}
	sbSetIf(out, "system_interface", p.Get("system-interface"))
	sbSetIf(out, "system_interface_name", p.Get("system-interface-name"))
	if allDigits(str(p.Get("system-interface-mtu"))) {
		out["system_interface_mtu"] = sbIntOrNull(p.Get("system-interface-mtu"))
	}
	if allDigits(str(p.Get("relay-server-port"))) {
		out["relay_server_port"] = sbIntOrNull(p.Get("relay-server-port"))
	}
	if !useControlHTTPClient {
		sbDetourParser(p, out)
		sbIPVersionParser(p, out)
		sbDomainResolverParser(p, out)
	}
	if sshServer := p.GetMap("ssh-server"); sshServer != nil {
		enabled := true
		if b, ok := sshServer["enabled"].(bool); ok && !b {
			enabled = false
		}
		sshMap := map[string]any{"enabled": enabled}
		sbSetIf(sshMap, "disable_pty", sshServer["disable-pty"])
		sbSetIf(sshMap, "disable_sftp", sshServer["disable-sftp"])
		sbSetIf(sshMap, "disable_forwarding", sshServer["disable-forwarding"])
		out["ssh_server"] = sshMap
	} else if sbTruthy(p.Get("ssh-server")) {
		out["ssh_server"] = true
	}
	return out
}

func sbWireGuardParser(p *model.Proxy) (map[string]any, error) {
	address := []any{}
	for _, family := range []string{"ipv4", "ipv6"} {
		if a := getWireGuardAddressWithCIDR(p, family); a != "" {
			address = append(address, a)
		}
	}
	out := map[string]any{
		"system":      sbTruthy(p.Get("system")),
		"tag":         p.GetString("name"),
		"type":        "wireguard",
		"server":      p.Server(),
		"server_port": sbServerPortAny(p),
		"address":     address,
	}
	if v := p.Get("mtu"); sbTruthy(v) {
		out["mtu"] = sbIntOrNull(v)
	}
	sbSetIf(out, "udp_timeout", p.Get("udp-timeout"))
	if v := p.Get("workers"); sbTruthy(v) {
		out["workers"] = sbIntOrNull(v)
	}
	sbSetIf(out, "private_key", p.Get("private-key"))
	sbSetIf(out, "peer_public_key", p.Get("public-key"))
	sbSetIf(out, "pre_shared_key", p.Get("pre-shared-key"))
	out["reserved"] = []any{}
	if err := sbCheckPort(out["server_port"]); err != nil {
		return nil, err
	}
	if sbTruthy(p.Get("fast-open")) {
		out["udp_fragment"] = true
	}
	// top-level reserved
	switch rv := p.Get("reserved").(type) {
	case string:
		out["reserved"] = rv
	case []any:
		out["reserved"] = cloneAny(rv)
	default:
		delete(out, "reserved")
	}
	peersRaw, _ := p.Get("peers").([]any)
	if len(peersRaw) == 0 {
		peersRaw = []any{map[string]any{}}
	}
	sbPeers := []any{}
	for _, pr := range peersRaw {
		pm, ok := pr.(map[string]any)
		if !ok {
			pm = map[string]any{}
		}
		var peerAddress string
		var peerPort any
		if sbTruthy(pm["server"]) && sbTruthy(pm["port"]) {
			peerAddress = str(pm["server"])
			peerPort = sbIntOrNull(pm["port"])
		} else {
			peerAddress = out["server"].(string)
			peerPort = out["server_port"]
		}
		peer := map[string]any{"address": peerAddress, "port": peerPort}
		if v := pm["persistent-keepalive-interval"]; sbTruthy(v) {
			peer["persistent_keepalive_interval"] = sbIntOrNull(v)
		}
		var pubKey any
		if sbTruthy(pm["public-key"]) {
			pubKey = pm["public-key"]
		} else if sbTruthy(pm["public_key"]) {
			pubKey = pm["public_key"]
		} else {
			pubKey = out["peer_public_key"]
		}
		sbSetIf(peer, "public_key", pubKey)
		var psk any
		if sbTruthy(pm["pre-shared-key"]) {
			psk = pm["pre-shared-key"]
		} else if sbTruthy(pm["pre_shared_key"]) {
			psk = pm["pre_shared_key"]
		} else {
			psk = out["pre_shared_key"]
		}
		sbSetIf(peer, "pre_shared_key", psk)
		var allowed any
		if v := pm["allowed-ips"]; sbTruthy(v) {
			allowed = v
		} else if v := pm["allowed_ips"]; sbTruthy(v) {
			allowed = v
		} else {
			def := []any{"0.0.0.0/0"}
			if sbTruthy(p.Get("ipv6")) {
				def = append(def, "::/0")
			}
			allowed = def
		}
		peer["allowed_ips"] = allowed
		// peer reserved: string → ["str"], array → copy, else fall back to
		// the top-level reserved (which may itself be a string).
		var peerReserved any
		switch rv := pm["reserved"].(type) {
		case string:
			peerReserved = []any{rv}
		case []any:
			peerReserved = cloneAny(rv)
		}
		if arr, ok := peerReserved.([]any); !ok || len(arr) == 0 {
			peerReserved = out["reserved"]
		}
		sbSetIf(peer, "reserved", peerReserved)
		sbPeers = append(sbPeers, peer)
	}
	out["peers"] = sbPeers
	sbTFOParser(p, out)
	sbDetourParser(p, out)
	sbSmuxParser(p.GetMap("smux"), out)
	sbIPVersionParser(p, out)
	sbDomainResolverParser(p, out)
	delete(out, "server")
	delete(out, "server_port")
	delete(out, "pre_shared_key")
	delete(out, "peer_public_key")
	delete(out, "reserved")
	return out, nil
}

// ProduceV2Ray outputs a base64-encoded URI list — the "通用订阅" format
// used by v2rayN-style subscription clients. This mirrors Sub-Store's
// V2Ray producer, which simply encodes the URI list in base64.
func ProduceV2Ray(proxies []*model.Proxy, opts map[string]any) (string, error) {
	plain, err := ProduceURI(proxies, opts)
	if err != nil {
		return "", err
	}
	return base64StdEncode([]byte(plain)), nil
}
