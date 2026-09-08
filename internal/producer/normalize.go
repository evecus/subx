package producer

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"substore/internal/model"
)

// encodeURIComponent mirrors JS encodeURIComponent: every byte except the
// unreserved set is percent-encoded (space becomes %20, not '+').
func encodeURIComponent(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if strings.IndexByte(unreserved, b) >= 0 {
			sb.WriteByte(b)
		} else {
			fmt.Fprintf(&sb, "%%%02X", b)
		}
	}
	return sb.String()
}

// getNested resolves a lodash-style dot path (e.g. "ws-opts.headers.Host")
// against a proxy's fields.
func getNested(p *model.Proxy, path string) any {
	var cur any = p.Fields()
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[part]
		if !ok {
			return nil
		}
	}
	return cur
}

// isPresent mirrors isPresent in producers/utils.js: present unless the
// resolved value is nil (null/undefined).
func isPresent(p *model.Proxy, attr string) bool {
	return getNested(p, attr) != nil
}

// hasNonBlankValue mirrors hasNonBlankValue in surge.js/surfboard.js.
func hasNonBlankValue(v any) bool {
	if v == nil {
		return false
	}
	return strings.TrimSpace(str(v)) != ""
}

// isShadowsocksOverTls mirrors producers/utils.js isShadowsocksOverTls.
func isShadowsocksOverTls(p *model.Proxy) bool {
	if p.Type() != "ss" || !p.GetBool("tls") {
		return false
	}
	if isPresent(p, "plugin") {
		return false
	}
	if isPresent(p, "network") {
		return strings.ToLower(strings.TrimSpace(p.GetString("network"))) == "tcp"
	}
	return true
}

// normalizePluginMuxValue mirrors producers/utils.js.
func normalizePluginMuxValue(mux any) any {
	switch t := mux.(type) {
	case bool:
		if t {
			return 1
		}
		return 0
	case string:
		normalized := strings.ToLower(strings.TrimSpace(t))
		switch normalized {
		case "true":
			return 1
		case "false":
			return 0
		}
		if allDigits(normalized) {
			if n, err := strconv.Atoi(normalized); err == nil {
				return n
			}
		}
	}
	return mux
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// normalizePluginMuxBooleanValue mirrors producers/utils.js.
func normalizePluginMuxBooleanValue(mux any) bool {
	v := normalizePluginMuxValue(mux)
	if b, ok := v.(bool); ok {
		return b
	}
	if n, ok := v.(int); ok {
		return n != 0
	}
	return false
}

// supportsShadowsocksV2rayPluginMode mirrors producers/utils.js.
func supportsShadowsocksV2rayPluginMode(p *model.Proxy, supportedModes ...string) bool {
	if p.Type() != "ss" || p.GetString("plugin") != "v2ray-plugin" {
		return true
	}
	mode := ""
	if opts := p.GetMap("plugin-opts"); opts != nil {
		if m, ok := opts["mode"].(string); ok {
			mode = strings.ToLower(strings.TrimSpace(m))
		} else if m, ok := opts["mode"]; ok && m != nil {
			mode = strings.ToLower(strings.TrimSpace(str(m)))
		}
	}
	for _, sm := range supportedModes {
		if mode == sm {
			return true
		}
	}
	return false
}

// restoreShadowTLSOpts mirrors producers/utils.js restoreShadowTLSOpts and
// returns whether shadow-tls is enabled.
func restoreShadowTLSOpts(target map[string]any, serverNameKey string) bool {
	plugin, _ := target["plugin"].(string)
	if plugin != "shadow-tls" {
		return false
	}
	opts, ok := target["plugin-opts"].(map[string]any)
	if !ok {
		return false
	}
	password := strAny(opts["password"])
	version := opts["version"]
	enabled := password != "" || (version != nil && strconvNum(version) != 0)
	target["shadow-tls-opts"] = map[string]any{
		"password": opts["password"],
		"version":  opts["version"],
	}
	if opts["host"] != nil {
		target[serverNameKey] = opts["host"]
	}
	if opts["alpn"] != nil {
		target["alpn"] = opts["alpn"]
	}
	delete(target, "plugin")
	delete(target, "plugin-opts")
	return enabled
}

func strconvNum(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	case json.Number:
		n, _ := strconv.Atoi(t.String())
		return n
	default:
		return 0
	}
}

func strAny(v any) string {
	if v == nil {
		return ""
	}
	return str(v)
}

// restoreShadowTLSProxyOpts mirrors producers/utils.js restoreShadowTLSProxyOpts.
func restoreShadowTLSProxyOpts(p *model.Proxy) {
	typ := p.Type()
	switch typ {
	case "vmess", "vless", "trojan", "anytls":
		if restoreShadowTLSOpts(p.Fields(), "sni") && (typ == "vmess" || typ == "vless") {
			p.Set("tls", true)
		}
	}
	if typ == "vless" && p.GetString("network") == "xhttp" {
		ds := getMapNested(p.Fields(), "xhttp-opts", "download-settings")
		if ds != nil && restoreShadowTLSOpts(ds, "servername") {
			ds["tls"] = true
		}
	}
}

func getMapNested(root map[string]any, path ...string) map[string]any {
	var cur any = root
	for _, part := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[part]
		if !ok {
			return nil
		}
	}
	m, _ := cur.(map[string]any)
	return m
}

// parseWireGuardCIDR mirrors producers/utils.js: a pure digit string in
// [0, max], otherwise undefined.
func parseWireGuardCIDR(cidr any, max int) (int, bool) {
	if cidr == nil {
		return 0, false
	}
	normalized := strings.TrimSpace(str(cidr))
	if !allDigits(normalized) {
		return 0, false
	}
	parsed, err := strconv.Atoi(normalized)
	if err != nil || parsed < 0 || parsed > max {
		return 0, false
	}
	return parsed, true
}

// parseWireGuardInterfaceAddress mirrors producers/utils.js: parses
// "host[/cidr]" (strips square brackets) and validates the IP family.
func parseWireGuardInterfaceAddress(value any, isIPv4Family bool) (address string, cidr int, hasCIDR bool, ok bool) {
	if value == nil {
		return "", 0, false, false
	}
	raw := strings.TrimSpace(str(value))
	if raw == "" {
		return "", 0, false, false
	}
	host := raw
	cidrStr := ""
	if idx := strings.IndexByte(raw, '/'); idx != -1 {
		host = raw[:idx]
		cidrStr = raw[idx+1:]
	}
	// Mirror the JS regex /^(.*?)(?:\/(\d+))?$/: when a slash is present the
	// remainder must be non-empty digits, otherwise the whole value is invalid.
	if strings.Contains(raw, "/") && (cidrStr == "" || !allDigits(cidrStr)) {
		return "", 0, false, false
	}
	host = strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(host, "]"), "["))
	if isIPv4Family {
		if net.ParseIP(host) == nil || strings.Contains(host, ":") {
			return "", 0, false, false
		}
	} else if net.ParseIP(host) == nil || !strings.Contains(host, ":") {
		return "", 0, false, false
	}
	max := 128
	if isIPv4Family {
		max = 32
	}
	parsed, parsedOK := parseWireGuardCIDR(cidrStr, max)
	return host, parsed, parsedOK, true
}

func normalizeWireGuardInterfaceAddress(p *model.Proxy, addressKey, cidrKey string, isIPv4Family bool, defaultCIDR int) {
	address, cidr, hasCIDR, ok := parseWireGuardInterfaceAddress(p.Get(addressKey), isIPv4Family)
	if !ok {
		if p.Get(addressKey) == nil || strings.TrimSpace(str(p.Get(addressKey))) == "" {
			p.Delete(cidrKey)
		}
		return
	}
	p.Set(addressKey, address)
	normalized, hasNorm := parseWireGuardCIDR(p.Get(cidrKey), defaultCIDR)
	switch {
	case hasNorm:
		p.Set(cidrKey, normalized)
	case hasCIDR:
		p.Set(cidrKey, cidr)
	default:
		p.Set(cidrKey, defaultCIDR)
	}
}

// normalizeWireGuardInterface mirrors producers/utils.js.
func normalizeWireGuardInterface(p *model.Proxy) {
	normalizeWireGuardInterfaceAddress(p, "ip", "ip-cidr", true, 32)
	normalizeWireGuardInterfaceAddress(p, "ipv6", "ipv6-cidr", false, 128)
}

// getWireGuardAddressWithCIDR mirrors producers/utils.js and returns
// "address/cidr" or "".
func getWireGuardAddressWithCIDR(p *model.Proxy, family string) string {
	addressKey, cidrKey, defaultCIDR := "ip", "ip-cidr", 32
	isV4 := true
	if family == "ipv6" {
		addressKey, cidrKey, defaultCIDR = "ipv6", "ipv6-cidr", 128
		isV4 = false
	}
	address, cidr, hasCIDR, ok := parseWireGuardInterfaceAddress(p.Get(addressKey), isV4)
	if !ok {
		return ""
	}
	normalized, hasNorm := parseWireGuardCIDR(p.Get(cidrKey), defaultCIDR)
	switch {
	case hasNorm:
		return fmt.Sprintf("%s/%d", address, normalized)
	case hasCIDR:
		return fmt.Sprintf("%s/%d", address, cidr)
	default:
		return fmt.Sprintf("%s/%d", address, defaultCIDR)
	}
}

// vmessSecurityCommon mirrors vmess-security.js normalizeVmessSecurity with
// the COMMON value list: auto/none/zero/aes-128-gcm/chacha20-poly1305,
// fallback "auto".
func vmessSecurityCommon(cipher string) string {
	c := strings.ToLower(strings.TrimSpace(cipher))
	switch c {
	case "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305":
		return c
	case "chacha20-ietf-poly1305":
		return "chacha20-poly1305"
	default:
		return "auto"
	}
}

// clashVmessSecurity mirrors vmess-security.js normalizeClashVmessSecurity:
// auto/aes-128-gcm/chacha20-poly1305/none, fallback "auto".
func clashVmessSecurity(cipher string) string {
	c := strings.ToLower(strings.TrimSpace(cipher))
	switch c {
	case "auto", "aes-128-gcm", "chacha20-poly1305", "none":
		return c
	case "chacha20-ietf-poly1305":
		return "chacha20-poly1305"
	default:
		return "auto"
	}
}

// formatLoonVmessSecurity mirrors vmess-security.js formatLoonVmessSecurity:
// Clash values, then chacha20-poly1305 re-mapped to chacha20-ietf-poly1305.
func formatLoonVmessSecurity(cipher string) string {
	c := clashVmessSecurity(cipher)
	if c == "chacha20-poly1305" {
		return "chacha20-ietf-poly1305"
	}
	return c
}

// formatQXVmessMethod mirrors vmess-security.js formatQXVmessMethod: only
// none/chacha20-poly1305, fallback chacha20-poly1305.
func formatQXVmessMethod(cipher string) string {
	c := strings.ToLower(strings.TrimSpace(cipher))
	switch c {
	case "none", "chacha20-poly1305":
		return c
	case "chacha20-ietf-poly1305":
		return "chacha20-poly1305"
	default:
		return "chacha20-poly1305"
	}
}

// parseSafeIntegerValue mirrors transport-path.js: /^\d+$/ then safe-int.
func parseSafeIntegerValue(v any) (int, bool) {
	if v == nil {
		return 0, false
	}
	s := strings.TrimSpace(str(v))
	if !allDigits(s) {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// extractPathQueryParam mirrors transport-path.js: splits "?" and removes
// the name=value parts (decoded compare), returning the path and the first
// non-empty value.
func extractPathQueryParam(path, name string) (string, string) {
	qIdx := strings.IndexByte(path, '?')
	if qIdx == -1 {
		return path, ""
	}
	base := path[:qIdx]
	query := path[qIdx+1:]
	parts := strings.Split(query, "&")
	kept := make([]string, 0, len(parts))
	value := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		key, val, _ := strings.Cut(part, "=")
		decKey, _ := url.PathUnescape(key)
		if decKey != name {
			kept = append(kept, part)
			continue
		}
		// decoded compare, like the JS version
		decVal, _ := url.PathUnescape(val)
		if value == "" && decVal != "" {
			value = decVal
		}
	}
	newPath := base
	if len(kept) > 0 {
		newPath = base + "?" + strings.Join(kept, "&")
	}
	return newPath, value
}

// setPathQueryParam mirrors transport-path.js: empty path becomes "/",
// existing param is stripped, then appended.
func setPathQueryParam(path, name, value string) string {
	if path == "" {
		path = "/"
	}
	clean, _ := extractPathQueryParam(path, name)
	if strings.Contains(clean, "?") {
		return clean + "&" + encodeURIComponent(name) + "=" + encodeURIComponent(value)
	}
	return clean + "?" + encodeURIComponent(name) + "=" + encodeURIComponent(value)
}

// getSafeEarlyDataValue mirrors uri.js: null/'' -> '', non-safe-int -> '',
// otherwise the original string form.
func getSafeEarlyDataValue(v any) string {
	if v == nil {
		return ""
	}
	s := str(v)
	if s == "" {
		return ""
	}
	if _, ok := parseSafeIntegerValue(s); !ok {
		return ""
	}
	return s
}

// setWebSocketEarlyDataPath mirrors uri.js setWebSocketEarlyDataPath.
func setWebSocketEarlyDataPath(path string, transportOpts map[string]any) string {
	earlyDataValue := transportOpts["max-early-data"]
	earlyData := getSafeEarlyDataValue(earlyDataValue)
	if earlyData == "" {
		if earlyDataValue != nil && str(earlyDataValue) != "" {
			clean, _ := extractPathQueryParam(path, "ed")
			return clean
		}
		return path
	}
	headerName, _ := transportOpts["early-data-header-name"].(string)
	if headerName != "" && headerName != "Sec-WebSocket-Protocol" {
		clean, _ := extractPathQueryParam(path, "ed")
		return clean
	}
	return setPathQueryParam(path, "ed", earlyData)
}

// getHttpUpgradeEarlyData mirrors uri.js getHttpUpgradeEarlyData.
func getHttpUpgradeEarlyData(transportOpts map[string]any, path string) string {
	if v := getSafeEarlyDataValue(transportOpts["_v2ray-http-upgrade-ed"]); v != "" {
		return v
	}
	if _, val := extractPathQueryParam(path, "ed"); val != "" {
		return val
	}
	return "2560"
}

// setHttpUpgradeEarlyDataPath mirrors uri.js setHttpUpgradeEarlyDataPath.
func setHttpUpgradeEarlyDataPath(path string, transportOpts map[string]any) string {
	fastOpen, _ := transportOpts["v2ray-http-upgrade-fast-open"].(bool)
	if !fastOpen {
		return path
	}
	return setPathQueryParam(path, "ed", getHttpUpgradeEarlyData(transportOpts, path))
}

// normalizeWebSocketEarlyDataPath mirrors transport-path.js.
func normalizeWebSocketEarlyDataPath(wsOpts map[string]any) {
	path, _ := wsOpts["path"].(string)
	_, ed := extractPathQueryParam(path, "ed")
	hasED := ed != ""
	// transport-path.js:133 uses a truthiness check.
	upgrade := isTruthy(wsOpts["v2ray-http-upgrade"])
	if upgrade {
		if hasED {
			clean, _ := extractPathQueryParam(path, "ed")
			wsOpts["path"] = clean
			wsOpts["v2ray-http-upgrade-fast-open"] = true
			if v, ok := wsOpts["_v2ray-http-upgrade-ed"]; !ok || v == nil || str(v) == "" {
				wsOpts["_v2ray-http-upgrade-ed"] = ed
			}
		}
		delete(wsOpts, "early-data-header-name")
		delete(wsOpts, "max-early-data")
		return
	}
	if !hasED {
		return
	}
	clean, _ := extractPathQueryParam(path, "ed")
	wsOpts["path"] = clean
	if _, ok := wsOpts["early-data-header-name"]; !ok || wsOpts["early-data-header-name"] == nil {
		wsOpts["early-data-header-name"] = "Sec-WebSocket-Protocol"
	}
	if _, ok := wsOpts["max-early-data"]; !ok || wsOpts["max-early-data"] == nil {
		if n, ok := parseSafeIntegerValue(ed); ok {
			wsOpts["max-early-data"] = n
		}
	}
}

// deleteHttpUpgradeEarlyDataMetadata mirrors transport-path.js.
func deleteHttpUpgradeEarlyDataMetadata(wsOpts map[string]any) {
	if wsOpts != nil {
		delete(wsOpts, "_v2ray-http-upgrade-ed")
	}
}

// getTransportHost mirrors uri.js getTransportHost with per-network header
// preference order. `??` coalescing semantics: only null/undefined fall
// through to the next candidate, an empty string wins over a fallback.
func getTransportHost(network string, transportOpts map[string]any) string {
	if transportOpts == nil {
		return ""
	}
	// host may be a string or an array (h2 parses host into an array);
	// mirror Array.isArray ? host[0] : host before coalescing.
	var host string
	hasHost := false
	switch v := transportOpts["host"].(type) {
	case string:
		host, hasHost = v, true
	case []any:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				host, hasHost = s, true
			} else if v[0] != nil {
				host, hasHost = strAny(v[0]), true
			}
		}
	case nil:
		// missing
	default:
		host, hasHost = strAny(v), true
	}
	headers, _ := transportOpts["headers"].(map[string]any)
	var headerHost, headerHostLower string
	hasHeaderHost, hasHeaderHostLower := false, false
	if headers != nil {
		if hh, ok := headers["Host"].(string); ok {
			headerHost, hasHeaderHost = hh, true
		}
		if hh, ok := headers["host"].(string); ok {
			headerHostLower, hasHeaderHostLower = hh, true
		}
	}
	// coalesce mirrors JS `a ?? b ?? c`: only nil candidates fall through.
	coalesce := func(vals ...any) string {
		for _, v := range vals {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}
	present := func(s string, ok bool) any {
		if ok {
			return s
		}
		return nil
	}
	switch network {
	case "h2":
		return coalesce(present(host, hasHost), present(headerHostLower, hasHeaderHostLower), present(headerHost, hasHeaderHost))
	case "xhttp":
		return coalesce(present(host, hasHost), present(headerHost, hasHeaderHost), present(headerHostLower, hasHeaderHostLower))
	default:
		return coalesce(present(headerHost, hasHeaderHost), present(headerHostLower, hasHeaderHostLower), present(host, hasHost))
	}
}

// buildXrayEchConfigListFromMihomo mirrors ech-utils.js buildXrayEchConfigListFromMihomo.
func buildXrayEchConfigListFromMihomo(echOpts map[string]any, fallback string) string {
	if echOpts == nil {
		return fallback
	}
	fields := buildXrayEchFieldsFromMihomo(echOpts, fallback)
	if v, ok := fields["echConfigList"].(string); ok {
		return v
	}
	return ""
}

// isMihomoEchEnabled mirrors ech-utils.js: bool directly, or an integer
// number != 0 (strings are not converted).
func isMihomoEchEnabled(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case int:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t == float64(int64(t)) && t != 0
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i != 0
		}
	}
	return false
}

// buildXrayEchFieldsFromMihomo mirrors ech-utils.js buildXrayEchFieldsFromMihomo.
func buildXrayEchFieldsFromMihomo(echOpts map[string]any, fallback string) map[string]any {
	out := map[string]any{}
	if echOpts != nil {
		if !isMihomoEchEnabled(echOpts["enable"]) {
			return out
		}
		queryServerName := strAny(echOpts["query-server-name"])
		config := strAny(echOpts["config"])
		dns := strAny(echOpts["_dns"])
		configList := ""
		if config != "" {
			configList = config
		} else if dns != "" {
			if queryServerName != "" {
				configList = queryServerName + "+" + dns
			} else {
				configList = dns
			}
		} else if queryServerName != "" {
			configList = queryServerName + "+https://dns.alidns.com/dns-query"
		}
		if configList != "" {
			out["echConfigList"] = configList
		}
		if forceQuery, ok := echOpts["_force-query"].(string); ok && configList != "" {
			switch forceQuery {
			case "none", "half", "full":
				out["echForceQuery"] = forceQuery
			}
		}
		if sockopt, ok := echOpts["_sockopt"].(map[string]any); ok && configList != "" {
			out["echSockopt"] = cloneAny(sockopt)
		}
		return out
	}
	if fallback != "" {
		out["echConfigList"] = fallback
	}
	return out
}

func cloneAny(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, val := range t {
			m[k] = cloneAny(val)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, val := range t {
			a[i] = cloneAny(val)
		}
		return a
	default:
		return t
	}
}

// produceProxyListOutput mirrors producers/utils.js: 'internal' returns the
// list unchanged (callers handle it), otherwise a "proxies:" prefixed line
// per proxy as inline JSON.
func produceProxyListOutput(list []map[string]any, type_ string, opts map[string]any) (string, error) {
	if type_ == "internal" {
		return "", nil
	}
	var sb strings.Builder
	sb.WriteString("proxies:\n")
	for _, p := range list {
		b, err := marshalOrderedMap(p)
		if err != nil {
			return "", err
		}
		sb.WriteString("  - ")
		sb.WriteString(b)
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

// marshalOrderedMap marshals a map with sorted keys (Go maps are unordered;
// sorted output is deterministic).
func marshalOrderedMap(m map[string]any) (string, error) {
	return jsonMarshalSorted(m)
}

// parseNormalizedXhttpRangeBounds mirrors xhttp-utils.js: accepts a single
// unsigned integer or an ascending "a-b" range.
func parseNormalizedXhttpRangeBounds(value any, allowZeroLowerBound, allowZeroUpperBound bool) (lower int, upper int, ok bool) {
	if value == nil {
		return 0, 0, false
	}
	switch value.(type) {
	case string, int, int64, float64, json.Number:
	default:
		return 0, 0, false
	}
	normalized := strings.TrimSpace(str(value))
	parseToken := func(token string) (int, bool) {
		trimmed := strings.TrimSpace(token)
		if !regexpUnsignedPlus(trimmed) {
			return 0, false
		}
		p, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			return 0, false
		}
		return int(p), true
	}
	rangeParts := strings.Split(normalized, "-")
	minLower := 0
	minUpper := 0
	if !allowZeroLowerBound {
		minLower = 1
	}
	if !allowZeroUpperBound {
		minUpper = 1
	}
	if len(rangeParts) == 1 {
		val, ok := parseToken(rangeParts[0])
		if !ok {
			return 0, 0, false
		}
		minimum := minLower
		if minUpper > minimum {
			minimum = minUpper
		}
		if val < minimum {
			return 0, 0, false
		}
		return val, val, true
	}
	if len(rangeParts) != 2 {
		return 0, 0, false
	}
	lo, ok1 := parseToken(rangeParts[0])
	hi, ok2 := parseToken(rangeParts[1])
	if !ok1 || !ok2 {
		return 0, 0, false
	}
	if lo < minLower || hi < minUpper || hi < lo {
		return 0, 0, false
	}
	return lo, hi, true
}

func regexpUnsignedPlus(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '+' {
		i = 1
	}
	if i >= len(s) {
		return false
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// normalizeXhttpPositiveRange mirrors xhttp-utils.js.
func normalizeXhttpPositiveRange(value any) any {
	lo, hi, ok := parseNormalizedXhttpRangeBounds(value, true, false)
	if !ok {
		return nil
	}
	if lo == hi {
		return hi
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

// normalizeXhttpStrictPositiveRangeValue mirrors xhttp-utils.js.
func normalizeXhttpStrictPositiveRangeValue(value any) any {
	lo, hi, ok := parseNormalizedXhttpRangeBounds(value, false, false)
	if !ok {
		return nil
	}
	if lo == hi {
		return hi
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

// normalizeXhttpNonNegativeRange mirrors xhttp-utils.js.
func normalizeXhttpNonNegativeRange(value any) any {
	lo, hi, ok := parseNormalizedXhttpRangeBounds(value, true, true)
	if !ok {
		return nil
	}
	if lo == hi {
		return hi
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

// normalizeXhttpIntegerValue mirrors xhttp-utils.js.
func normalizeXhttpIntegerValue(value any, allowNegative bool) any {
	switch t := value.(type) {
	case int:
		if !allowNegative && t < 0 {
			return nil
		}
		return t
	case int64:
		if !allowNegative && t < 0 {
			return nil
		}
		return int(t)
	case float64:
		if t == float64(int64(t)) {
			v := int64(t)
			if !allowNegative && v < 0 {
				return nil
			}
			return int(v)
		}
		return nil
	case json.Number:
		if i, err := t.Int64(); err == nil {
			if !allowNegative && i < 0 {
				return nil
			}
			return int(i)
		}
		return nil
	case string:
		trimmed := strings.TrimSpace(t)
		patternOK := regexpSigned(trimmed, allowNegative)
		if !patternOK {
			return nil
		}
		p, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			return nil
		}
		if !allowNegative && p < 0 {
			return nil
		}
		return int(p)
	default:
		return nil
	}
}

func regexpSigned(s string, allowNegative bool) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '+' || (allowNegative && s[0] == '-') {
		i = 1
	}
	if i >= len(s) {
		return false
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
