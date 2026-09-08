package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"substore/internal/model"
)

// normalizeProxy applies post-parse normalization, mirroring the original
// Sub-Store lastParse() logic.
func normalizeProxy(p *model.Proxy) {
	normalizeOptKeys(p)
	// udp is always normalized to a boolean, defaulting to true (mirroring
	// Sub-Store lastParse)
	switch v := p.Get("udp").(type) {
	case string:
		lv := strings.ToLower(v)
		p.Set("udp", !(lv == "false" || lv == "off" || lv == "0"))
	case bool:
		p.Set("udp", v)
	case float64:
		p.Set("udp", v != 0)
	case int:
		p.Set("udp", v != 0)
	default:
		p.Set("udp", true)
	}
	if c := p.GetString("cipher"); c != "" {
		p.Set("cipher", strings.ToLower(c))
	}
	// password 数字转字符串（原版 numberToString）
	switch p.Get("password").(type) {
	case int, int64, float64, json.Number:
		p.Set("password", p.GetString("password"))
	}
	// ss cipher none 且无 password 时补空字符串
	// https://github.com/MetaCubeX/mihomo/issues/1677
	if p.Type() == "ss" && p.GetString("cipher") == "none" && !jsTruthy(p.Get("password")) {
		p.Set("password", "")
	}
	if p.Has("interface") {
		p.Set("interface-name", p.Get("interface"))
		p.Delete("interface")
	}
	if port := p.GetInt("port"); port > 0 {
		p.Set("port", port)
	}
	if s := p.GetString("server"); s != "" {
		p.Set("server", strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(s), "]"), "["))
	}

	// shadow-tls-opts -> plugin: shadow-tls（vmess/vless/trojan/anytls）
	switch p.Type() {
	case "vmess", "vless", "trojan", "anytls":
		if opts := p.GetMap("shadow-tls-opts"); opts != nil {
			pluginOpts := map[string]any{}
			if sni := p.Get("sni"); sni != nil && sni != "" {
				pluginOpts["host"] = sni
			}
			if v, ok := opts["password"]; ok && v != nil {
				pluginOpts["password"] = v
			}
			if v, ok := opts["version"]; ok && v != nil {
				pluginOpts["version"] = v
			}
			p.Set("plugin", "shadow-tls")
			p.Set("plugin-opts", pluginOpts)
			p.Delete("shadow-tls-opts")
		}
	}

	// snell obfs-opts.mode === 'shadow-tls' -> plugin: shadow-tls
	if p.Type() == "snell" && !p.Has("plugin") {
		if obfsOpts := p.GetMap("obfs-opts"); obfsOpts != nil && obfsOpts["mode"] == "shadow-tls" {
			pluginOpts := map[string]any{}
			for _, k := range []string{"host", "password", "version", "alpn"} {
				if v, ok := obfsOpts[k]; ok && v != nil {
					pluginOpts[k] = v
				}
			}
			p.Set("plugin", "shadow-tls")
			p.Set("plugin-opts", pluginOpts)
			p.Delete("obfs-opts")
		}
	}

	// plugin === 'shadow-tls' 时 alpn 下沉到 plugin-opts（覆盖所有来源，
	// surge/loon parser 内已有等价逻辑，这里兜底其余来源）
	if p.GetString("plugin") == "shadow-tls" {
		if pluginOpts := p.GetMap("plugin-opts"); pluginOpts != nil {
			if alpn := p.Get("alpn"); jsTruthy(alpn) {
				if _, exists := pluginOpts["alpn"]; !exists {
					pluginOpts["alpn"] = alpn
				}
			}
			p.Delete("alpn")
		}
	}
	// network defaults
	switch p.Type() {
	case "trojan":
		if !p.Has("network") {
			p.Set("network", "tcp")
		}
	case "vmess":
		if !p.Has("network") {
			p.Set("network", "tcp")
		}
		if !p.Has("cipher") {
			p.Set("cipher", "none")
		}
		if p.GetInt("alterId") == 0 && !p.Has("alterId") {
			p.Set("alterId", 0)
		}
	case "vless":
		if !p.Has("network") {
			p.Set("network", "tcp")
		}
	}

	// tls defaults for certain types
	tlsTypes := map[string]bool{
		"trojan": true, "tuic": true, "hysteria": true, "hysteria2": true,
		"juicity": true, "anytls": true, "trusttunnel": true, "h2-connect": true,
		"naive": true, "masque": true, "shadowquic": true,
	}
	if tlsTypes[p.Type()] {
		p.Set("tls", true)
	}

	// ws-opts normalization
	if p.GetString("network") == "ws" {
		if !p.Has("ws-opts") && (p.Has("ws-path") || p.Has("ws-headers")) {
			opts := map[string]any{}
			if p.Has("ws-path") {
				opts["path"] = p.Get("ws-path")
			}
			if p.Has("ws-headers") {
				opts["headers"] = p.Get("ws-headers")
			}
			p.Set("ws-opts", opts)
		}
		p.Delete("ws-path")
		p.Delete("ws-headers")
	}

	// path normalization
	network := p.GetString("network")
	if network != "" {
		opts := p.GetMap(network + "-opts")
		if opts != nil {
			if path, ok := opts["path"]; ok {
				opts["path"] = normalizeTransportPath(path)
			}
		}
	}

	// lowercase transport headers "host" promote to "Host" for non-h2
	// networks (mirroring Sub-Store lastParse)
	if network != "" && network != "h2" {
		if opts := p.GetMap(network + "-opts"); opts != nil {
			if headers, ok := opts["headers"].(map[string]any); ok {
				if _, hasUpper := headers["Host"]; !hasUpper {
					if hostLower, hasLower := headers["host"]; hasLower {
						headers["Host"] = hostLower
						delete(headers, "host")
					}
				}
			}
		}
	}

	// h2-opts normalization: host becomes an array, host headers are lifted
	// out, array paths collapse to their first element (mirroring lastParse)
	if network == "h2" {
		if opts := p.GetMap("h2-opts"); opts != nil {
			var host any
			if v, ok := opts["host"]; ok {
				host = v
			} else if headers, ok := opts["headers"].(map[string]any); ok {
				if v, ok := headers["host"]; ok {
					host = v
				} else if v, ok := headers["Host"]; ok {
					host = v
				}
			}
			if host != nil {
				if s, ok := host.(string); ok && s == "" {
					// JS falsy empty host is ignored
				} else if !isSlice(host) {
					opts["host"] = []any{host}
				}
			}
			if headers, ok := opts["headers"].(map[string]any); ok {
				delete(headers, "host")
				delete(headers, "Host")
				if len(headers) == 0 {
					delete(opts, "headers")
				}
			}
			if arr, ok := opts["path"].([]any); ok && len(arr) > 0 {
				opts["path"] = arr[0]
			}
		}
	}

	// legacy xudp / packet-addr flags become packet-encoding (mirroring
	// Sub-Store lastParse)
	if (p.Type() == "vmess" || p.Type() == "vless") && !p.Has("packet-encoding") {
		if p.GetBool("xudp") {
			p.Set("packet-encoding", "xudp")
		} else if p.GetBool("packet-addr") {
			p.Set("packet-encoding", "packetaddr")
		}
	}

	// sni fallback for tls proxies
	// mirrors proxy-utils/index.js:1033 `proxy.tls && !proxy.sni &&
	// proxy.sni !== ''`: an explicit empty string (e.g. hysteria2 "?sni=")
	// is falsy but must NOT trigger the server fallback
	sniVal := p.Get("sni")
	sniEmptyStr := false
	if s, ok := sniVal.(string); ok && s == "" {
		sniEmptyStr = true
	}
	if p.GetBool("tls") && !jsTruthy(sniVal) && !sniEmptyStr {
		if network != "" {
			opts := p.GetMap(network + "-opts")
			if opts != nil {
				var transportHost any
				if network == "h2" {
					transportHost = opts["host"]
				} else if headers, ok := opts["headers"].(map[string]any); ok {
					transportHost = headers["Host"]
				}
				if arr, ok := transportHost.([]any); ok && len(arr) > 0 {
					transportHost = arr[0]
				}
				if s, ok := transportHost.(string); ok && s != "" {
					p.Set("sni", s)
				}
			}
		}
		if !p.Has("sni") && !isIPString(p.GetString("server")) {
			p.Set("sni", p.GetString("server"))
		}
	}

	// non-tls ws/http nodes with a domain server get a transport Host so
	// the domain is not lost after resolution (mirroring Sub-Store)
	if !p.GetBool("tls") && (network == "ws" || network == "http") && !isIPString(p.GetString("server")) {
		opts := p.GetMap(network + "-opts")
		var headers map[string]any
		if opts != nil {
			headers, _ = opts["headers"].(map[string]any)
		}
		var host string
		if headers != nil {
			host, _ = headers["Host"].(string)
		}
		if host == "" {
			if opts == nil {
				opts = map[string]any{}
				p.Set(network+"-opts", opts)
			}
			if headers == nil {
				headers = map[string]any{}
				opts["headers"] = headers
			}
			if p.Type() == "vmess" || p.Type() == "vless" {
				if network == "http" {
					headers["Host"] = []any{p.GetString("server")}
				} else {
					headers["Host"] = p.GetString("server")
				}
			} else {
				headers["Host"] = p.GetString("server")
			}
		}
	}

	// vmess/vless http transport paths and Host headers are arrays
	// (mirroring Sub-Store lastParse)
	if (p.Type() == "vmess" || p.Type() == "vless") && network == "http" {
		opts := p.GetMap("http-opts")
		if opts != nil {
			if path, ok := opts["path"]; ok && !isSlice(path) {
				opts["path"] = []any{path}
			}
			if headers, ok := opts["headers"].(map[string]any); ok {
				if host, ok := headers["Host"]; ok && !isSlice(host) {
					headers["Host"] = []any{host}
				}
			}
		}
	}

	// vless http transport defaults to a "/" path (mirroring Sub-Store)
	if p.Type() == "vless" && network == "http" {
		opts := p.GetMap("http-opts")
		if opts == nil {
			opts = map[string]any{}
			p.Set("http-opts", opts)
		}
		if _, ok := opts["path"]; !ok {
			opts["path"] = []any{"/"}
		}
	}

	// vless reality/grpc marker cleanup and flow removal (mirroring
	// Sub-Store lastParse)
	if p.Type() == "vless" {
		if opts := p.GetMap("reality-opts"); opts != nil && len(opts) == 0 {
			p.Delete("reality-opts")
		}
		if opts := p.GetMap("grpc-opts"); opts != nil && len(opts) == 0 {
			p.Delete("grpc-opts")
		}
		flow := p.Get("flow")
		flowFalsy := flow == nil
		if s, ok := flow.(string); ok && s == "" {
			flowFalsy = true
		}
		realityFalsy := !p.Has("reality-opts")
		if (realityFalsy && flowFalsy) || flow == "null" || flow == nil {
			p.Delete("flow")
		}
	}

	// anytls disable-reuse maps to reuse=false (mirroring lastParse)
	if p.Type() == "anytls" && p.GetBool("disable-reuse") {
		p.Set("reuse", false)
	}

	// ports 归一化：存在则 String(ports).replace(/\//g, ',')，空则删除
	if ports := p.Get("ports"); jsTruthy(ports) {
		p.Set("ports", strings.ReplaceAll(p.GetString("ports"), "/", ","))
	} else {
		p.Delete("ports")
	}

	// hysteria2 obfs
	if p.Type() == "hysteria2" {
		obfs := p.GetString("obfs")
		if obfs != "" && obfs != "salamander" && !p.Has("obfs-password") {
			p.Set("obfs-password", obfs)
			p.Set("obfs", "salamander")
		}
		// obfs_password -> obfs-password
		if p.GetString("obfs-password") == "" {
			if v := p.Get("obfs_password"); jsTruthy(v) {
				p.Set("obfs-password", v)
				p.Delete("obfs_password")
			}
		}
	}

	// 允许设置 sni 为空串或 'off' 时禁用 SNI（原版 ['', 'off'].includes(proxy.sni)）；
	// hysteria2 侧已在解析时保留显式空串，因此此处能正确触发
	if s, ok := p.Get("sni").(string); ok && (s == "" || s == "off") {
		p.Set("disable-sni", true)
	}

	// ca-str / ca_str 生成 tls-fingerprint（原版 rs.generateFingerprint：
	// 对 PEM 的 DER 做 sha256，冒号分隔的大写十六进制）
	caStr := p.GetString("ca_str")
	if s := p.GetString("ca-str"); s != "" {
		caStr = s
	} else if caStr != "" {
		p.Delete("ca_str")
		p.Set("ca-str", caStr)
	}
	// mirrors proxy-utils/index.js:1160: when no ca string is present, the
	// "_ca" key may point to a certificate file whose content is used for
	// the fingerprint; read failures are ignored (original logs only)
	if caStr == "" {
		if caPath := p.GetString("_ca"); caPath != "" {
			if data, err := os.ReadFile(caPath); err == nil {
				caStr = string(data)
			}
		}
	}
	if p.GetString("tls-fingerprint") == "" && caStr != "" {
		if fp := tlsFingerprintFromPEM(caStr); fp != "" {
			p.Set("tls-fingerprint", fp)
		}
	}

	// tuic defaults
	if p.Type() == "tuic" {
		// alpn 强转数组（原版：非数组包一层，缺省 h3）
		switch alpn := p.Get("alpn").(type) {
		case []any:
		case []string:
			arr := make([]any, len(alpn))
			for i, s := range alpn {
				arr[i] = s
			}
			p.Set("alpn", arr)
		default:
			if jsTruthy(p.Get("alpn")) {
				p.Set("alpn", []any{p.Get("alpn")})
			} else {
				p.Set("alpn", []any{"h3"})
			}
		}
		if !p.Has("congestion-controller") {
			p.Set("congestion-controller", "cubic")
		}
		if !p.Has("udp-relay-mode") {
			p.Set("udp-relay-mode", "native")
		}
	}

	// ws/http/h2 default paths
	if network == "ws" || network == "h2" {
		opts := p.GetMap(network + "-opts")
		if opts == nil {
			opts = map[string]any{}
			p.Set(network+"-opts", opts)
		}
		if _, ok := opts["path"]; !ok {
			opts["path"] = "/"
		}
	}
	if network == "http" {
		opts := p.GetMap("http-opts")
		if opts == nil {
			opts = map[string]any{}
			p.Set("http-opts", opts)
		}
		path, hasPath := opts["path"]
		missing := !hasPath
		if arr, ok := path.([]any); ok {
			missing = len(arr) == 0
			for _, item := range arr {
				if s, ok := item.(string); ok && s != "" {
					missing = false
					break
				}
				if f, ok := item.(float64); ok && f != 0 {
					missing = false
					break
				}
			}
		}
		if missing {
			opts["path"] = []any{"/"}
		}
	}

	// hop-interval range split (mirroring Sub-Store lastParse)
	if p.Has("hop-interval") {
		hopInterval := strings.TrimSpace(p.GetString("hop-interval"))
		hiRangeRe := regexp.MustCompile(`^(\d+)\s*-\s*(\d+)$`)
		if rm := hiRangeRe.FindStringSubmatch(hopInterval); rm != nil {
			hopMin, err1 := strconv.Atoi(rm[1])
			hopMax, err2 := strconv.Atoi(rm[2])
			if err1 == nil && err2 == nil && hopMin > 0 && hopMin <= hopMax {
				p.Set("hop-interval", hopMin)
				p.Set("hop-interval-max", hopMax)
			} else {
				p.Delete("hop-interval")
				p.Delete("hop-interval-max")
			}
		} else if m := digitRunRe.FindString(hopInterval); m == hopInterval && hopInterval != "" {
			parsed, err := strconv.Atoi(hopInterval)
			if err == nil && parsed > 0 {
				p.Set("hop-interval", parsed)
				p.Delete("hop-interval-max")
			} else {
				p.Delete("hop-interval")
				p.Delete("hop-interval-max")
			}
		} else {
			p.Delete("hop-interval")
			p.Delete("hop-interval-max")
		}
	}

	// wireguard interface address normalization (mirroring Sub-Store lastParse)
	if p.Type() == "wireguard" {
		backfillWireGuardPeers(p)
		normalizeWireGuardInterface(p)
	}

	// name decoding
	name := p.GetString("name")
	if name == "" {
		p.Set("name", p.Type()+" "+p.Server()+":"+strconv.Itoa(p.Port()))
	}
}

func normalizeOptKeys(p *model.Proxy) {
	for _, key := range keysOf(p.Fields()) {
		normalizedKey := strings.ToLower(key)
		if !strings.HasSuffix(normalizedKey, "-opts") {
			continue
		}
		if key != normalizedKey {
			// 原版 hasOwn 检查：重名时仅删除旧键
			if !p.Has(normalizedKey) {
				p.Set(normalizedKey, p.Get(key))
			}
			p.Delete(key)
		}
		// 子键小写化作用于改名后的 key（原版 normalizeOpts(proxy[normalizedKey])）
		normalizeOptsMap(p.Get(normalizedKey))
	}
}

// normalizeOptsMap lowercase-renames the subkeys of an -opts map in place
// (mirroring lastParse's normalizeOpts).
func normalizeOptsMap(value any) {
	m, ok := value.(map[string]any)
	if !ok {
		return
	}
	for _, k2 := range keysOf(m) {
		lk := strings.ToLower(k2)
		if k2 != lk {
			if _, exists := m[lk]; !exists {
				m[lk] = m[k2]
			}
			delete(m, k2)
		}
	}
}

// jsTruthy mirrors JS truthiness for the values handled here (nil / "" /
// false / 0 are falsy; everything else truthy).
func jsTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case bool:
		return x
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case json.Number:
		return x.String() != "" && x.String() != "0"
	}
	return true
}

// backfillWireGuardPeers mirrors the original lastParse wireguard block:
// when any peer carries ip/ipv6, the interface ip/ipv6 fall back to
// peers[0]'s values (index.js:1179-1192).
func backfillWireGuardPeers(p *model.Proxy) {
	peers, ok := p.Get("peers").([]any)
	if !ok || len(peers) == 0 {
		return
	}
	valid := false
	for _, peer := range peers {
		pm, ok := peer.(map[string]any)
		if !ok {
			continue
		}
		if jsTruthy(pm["ip"]) && jsTruthy(pm["ipv6"]) {
			valid = true
			break
		}
	}
	if !valid {
		for _, peer := range peers {
			pm, ok := peer.(map[string]any)
			if !ok {
				continue
			}
			if jsTruthy(pm["ip"]) || jsTruthy(pm["ipv6"]) {
				valid = true
				break
			}
		}
	}
	if !valid {
		return
	}
	pm0, _ := peers[0].(map[string]any)
	if pm0 == nil {
		return
	}
	if !jsTruthy(p.Get("ip")) {
		if v, ok := pm0["ip"]; ok && jsTruthy(v) {
			p.Set("ip", v)
		}
	}
	if !jsTruthy(p.Get("ipv6")) {
		if v, ok := pm0["ipv6"]; ok && jsTruthy(v) {
			p.Set("ipv6", v)
		}
	}
}

// tlsFingerprintFromPEM mirrors rs.generateFingerprint: SHA-256 over the
// DER bytes of the first PEM block, rendered as uppercase colon-separated
// hex pairs. Returns "" for non-PEM input (the original would throw).
func tlsFingerprintFromPEM(caStr string) string {
	block, _ := pem.Decode([]byte(caStr))
	if block == nil {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	hexStr := strings.ToUpper(hex.EncodeToString(sum[:]))
	pairs := make([]string, 0, len(hexStr)/2)
	for i := 0; i+2 <= len(hexStr); i += 2 {
		pairs = append(pairs, hexStr[i:i+2])
	}
	return strings.Join(pairs, ":")
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func isSlice(v any) bool {
	switch v.(type) {
	case []any, []string:
		return true
	}
	return false
}

func normalizeTransportPath(path any) any {
	s, ok := path.(string)
	if !ok {
		return path
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "/"
	}
	if !strings.HasPrefix(s, "/") {
		return "/" + s
	}
	return s
}

// parseWireGuardCIDR mirrors producers/utils.js: valid "N" strings in
// 0..max, otherwise absent.
func parseWireGuardCIDR(cidr any, max int) (int, bool) {
	if cidr == nil {
		return 0, false
	}
	normalized := strings.TrimSpace(fmt.Sprint(cidr))
	if !digitRunRe.MatchString(normalized) || normalized != digitRunRe.FindString(normalized) {
		return 0, false
	}
	parsed, err := strconv.Atoi(normalized)
	if err != nil || parsed < 0 || parsed > max {
		return 0, false
	}
	return parsed, true
}

// parseWireGuardInterfaceAddress mirrors producers/utils.js.
func parseWireGuardInterfaceAddress(value any, ipv4 bool) (host string, cidr int, hasCIDR, valid bool) {
	if value == nil {
		return "", 0, false, false
	}
	raw := strings.TrimSpace(fmt.Sprint(value))
	if raw == "" {
		return "", 0, false, false
	}
	hostRaw := raw
	cidrRaw := ""
	if m := wgAddressRe.FindStringSubmatch(raw); m != nil {
		if m[1] != "" {
			hostRaw = m[1]
		}
		cidrRaw = m[2]
	}
	host = strings.Trim(strings.Trim(strings.TrimSpace(hostRaw), "]"), "[")
	max := 32
	valid = isIPv4String(host)
	if !ipv4 {
		max = 128
		valid = isIPv6String(host)
	}
	if !valid {
		return "", 0, false, false
	}
	cidr, hasCIDR = parseWireGuardCIDR(cidrRaw, max)
	return host, cidr, hasCIDR, true
}

// normalizeWireGuardInterface mirrors producers/utils.js
// normalizeWireGuardInterface: default CIDR suffixes are filled for the
// wireguard interface addresses.
func normalizeWireGuardInterface(p *model.Proxy) {
	for _, cfg := range []struct {
		addressKey, cidrKey string
		ipv4                bool
		defaultCIDR         int
	}{
		{"ip", "ip-cidr", true, 32},
		{"ipv6", "ipv6-cidr", false, 128},
	} {
		host, cidr, hasCIDR, valid := parseWireGuardInterfaceAddress(p.Get(cfg.addressKey), cfg.ipv4)
		if !valid {
			if p.Get(cfg.addressKey) == nil || strings.TrimSpace(p.GetString(cfg.addressKey)) == "" {
				p.Delete(cfg.cidrKey)
			}
			continue
		}
		p.Set(cfg.addressKey, host)
		if existing, ok := parseWireGuardCIDR(p.Get(cfg.cidrKey), cfg.defaultCIDR); ok {
			p.Set(cfg.cidrKey, existing)
		} else if hasCIDR {
			p.Set(cfg.cidrKey, cidr)
		} else {
			p.Set(cfg.cidrKey, cfg.defaultCIDR)
		}
	}
}
