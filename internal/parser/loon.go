package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"substore/internal/model"
)

// loonTypeMap maps Loon proxy type names to the canonical model type.
var loonTypeMap = map[string]string{
	"shadowsocks":  "ss",
	"shadowsocksr": "ssr",
	"vmess":        "vmess",
	"vless":        "vless",
	"trojan":       "trojan",
	"https":        "http",
	"http":         "http",
	"socks5":       "socks5",
	"hysteria2":    "hysteria2",
	"anytls":       "anytls",
	"wireguard":    "wireguard",
}

// loonCiphers is the cipher enumeration accepted by the Loon ss grammar.
var loonCiphers = map[string]bool{
	"aes-128-cfb": true, "aes-128-ctr": true, "aes-128-gcm": true,
	"aes-192-cfb": true, "aes-192-ctr": true, "aes-192-gcm": true,
	"aes-256-cfb": true, "aes-256-ctr": true, "aes-256-gcm": true,
	"auto": true, "bf-cfb": true, "camellia-128-cfb": true,
	"camellia-192-cfb": true, "camellia-256-cfb": true,
	"chacha20-ietf-poly1305": true, "chacha20-ietf": true,
	"chacha20-poly1305": true, "chacha20": true, "none": true,
	"rc4-md5": true, "rc4": true, "salsa20": true,
	"xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
}

// loonVmessSecurities are the encrypt-method values accepted for Loon
// vmess lines; anything else falls back to "auto".
var loonVmessSecurities = map[string]bool{
	"none": true, "auto": true, "aes-128-gcm": true, "chacha20-ietf-poly1305": true,
}

// loonSsrObfs are the obfs values accepted by the Loon ssr grammar.
var loonSsrObfs = map[string]bool{
	"plain": true, "http_simple": true, "http_post": true, "random_head": true,
	"tls1.2_ticket_auth": true, "tls1.2_ticket_fastauth": true,
}

// loonSsrProtocols are the protocol values accepted by the Loon ssr grammar.
var loonSsrProtocols = map[string]bool{
	"origin": true, "auth_sha1_v4": true, "auth_aes128_md5": true,
	"auth_aes128_sha1": true, "auth_chain_a": true, "auth_chain_b": true,
}

// loonShadowTLSTypes are the Loon types whose grammar includes the
// shadow-tls-* options (shadowsocks and shadowsocksr only). The keys are
// the Loon type names.
var loonShadowTLSTypes = map[string]bool{
	"shadowsocks":  true,
	"shadowsocksr": true,
}

// loonTransportTypes are the Loon types whose grammar includes the
// transport / host / path options.
var loonTransportTypes = map[string]bool{
	"vmess": true, "vless": true, "trojan": true, "anytls": true,
}

// loonTLSKeywordTypes are the Loon types whose grammar includes the
// tls-name / sni / tls-* / alpn option set.
var loonTLSKeywordTypes = map[string]bool{
	"vmess": true, "vless": true, "trojan": true, "anytls": true,
	"https": true, "socks5": true, "hysteria2": true,
}

// loonLineTest checks whether a line looks like a Loon proxy entry.
// The type name is the first comma field after "="; the Loon grammar uses
// its own type names, so this does not collide with Surge. Loon vmess
// lines are distinguished from Surge vmess lines by the absence of a
// "username" option.
func loonLineTest(line string) bool {
	idx := strings.Index(line, "=")
	if idx == -1 {
		return false
	}
	first := strings.SplitN(line[idx+1:], ",", 2)[0]
	typ := strings.ToLower(strings.TrimSpace(first))
	if _, ok := loonTypeMap[typ]; !ok {
		return false
	}
	if typ == "vmess" {
		return !strings.Contains(line, "username=")
	}
	return true
}

// parseLoonLine parses a Loon proxy entry, mirroring the peggy/loon.js
// grammar. Positional fields (cipher, quoted password/uuid, optional
// username/password pair) are required where the grammar requires them;
// unrecognized key=value options are dropped.
func parseLoonLine(line string) (*model.Proxy, error) {
	eq := strings.Index(line, "=")
	if eq == -1 {
		return nil, fmt.Errorf("invalid loon line")
	}
	name := strings.TrimSpace(line[:eq])
	rest := line[eq+1:]
	first := strings.SplitN(rest, ",", 2)[0]
	loonType := strings.ToLower(strings.TrimSpace(first))
	typ, ok := loonTypeMap[loonType]
	if !ok {
		return nil, fmt.Errorf("unsupported loon type: %s", loonType)
	}

	if loonType == "wireguard" {
		return parseLoonWireGuard(name, rest)
	}

	fields := splitSurgeFields(rest)
	if len(fields) < 3 {
		return nil, fmt.Errorf("invalid loon line")
	}
	server := strings.TrimSpace(fields[1])
	port, err := strconv.Atoi(strings.TrimSpace(fields[2]))
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid loon port: %s", fields[2])
	}

	p := model.NewProxy()
	p.Set("name", name)
	p.Set("type", typ)
	p.Set("server", server)
	p.Set("port", port)

	ctx := &loonParamCtx{}
	pos := 3
	switch loonType {
	case "shadowsocks", "shadowsocksr":
		// positional cipher (strict enumeration) and quoted password
		if len(fields) < 5 || !loonCiphers[strings.TrimSpace(fields[3])] {
			return nil, fmt.Errorf("invalid loon %s cipher", loonType)
		}
		p.Set("cipher", strings.TrimSpace(fields[3]))
		pwd, ok := loonQuoted(fields[4])
		if !ok {
			return nil, fmt.Errorf("invalid loon %s password", loonType)
		}
		p.Set("password", pwd)
		pos = 5
		if loonType == "shadowsocks" {
			// optional positional obfs type/host pair
			if len(fields) > 5 && (fields[5] == "http" || fields[5] == "tls") {
				if len(fields) < 7 {
					return nil, fmt.Errorf("invalid loon ss obfs")
				}
				ctx.obfsType = fields[5]
				ctx.obfsHost = fields[6]
				pos = 7
			}
		}
	case "vmess":
		// the positional cipher slot is greedy in the grammar; any value
		// is normalized or falls back to "auto"
		if len(fields) < 5 {
			return nil, fmt.Errorf("invalid loon vmess line")
		}
		p.Set("cipher", normalizeLoonVmessSecurity(fields[3]))
		uuid, ok := loonQuoted(fields[4])
		if !ok {
			return nil, fmt.Errorf("invalid loon vmess uuid")
		}
		p.Set("uuid", uuid)
		pos = 5
	case "vless":
		if len(fields) < 4 {
			return nil, fmt.Errorf("invalid loon vless line")
		}
		uuid, ok := loonQuoted(fields[3])
		if !ok {
			return nil, fmt.Errorf("invalid loon vless uuid")
		}
		p.Set("uuid", uuid)
		pos = 4
	case "trojan", "anytls", "hysteria2":
		if len(fields) < 4 {
			return nil, fmt.Errorf("invalid loon %s line", loonType)
		}
		pwd, ok := loonQuoted(fields[3])
		if !ok {
			return nil, fmt.Errorf("invalid loon %s password", loonType)
		}
		p.Set("password", pwd)
		pos = 4
	case "https", "http", "socks5":
		// optional positional username / quoted password pair
		if len(fields) > 3 && !strings.Contains(fields[3], "=") {
			if len(fields) < 5 {
				return nil, fmt.Errorf("invalid loon %s username", loonType)
			}
			pwd, ok := loonQuoted(fields[4])
			if !ok {
				return nil, fmt.Errorf("invalid loon %s password", loonType)
			}
			p.Set("username", strings.TrimSpace(fields[3]))
			p.Set("password", pwd)
			pos = 5
		}
	}

	if err := applyLoonParams(p, fields[pos:], loonType, ctx); err != nil {
		return nil, err
	}

	// type-specific defaults from the grammar
	switch loonType {
	case "vmess":
		if !p.Has("cipher") {
			p.Set("cipher", "auto")
		}
		if !p.Has("alterId") {
			p.Set("alterId", 0)
		}
	case "https":
		p.Set("tls", true)
	}

	// ws/http transport assembly
	if loonTransportTypes[loonType] {
		applyLoonTransport(p, ctx)
	}

	// ss obfs plugin assembly
	if loonType == "shadowsocks" && (ctx.obfsType == "http" || ctx.obfsType == "tls") {
		p.Set("plugin", "obfs")
		opts := EnsureOpts(p, "plugin-opts")
		opts["mode"] = ctx.obfsType
		if ctx.obfsHost != "" {
			opts["host"] = ctx.obfsHost
		}
		if ctx.obfsPath != "" {
			opts["path"] = ctx.obfsPath
		}
	}

	// shadow-tls plugin assembly
	if ctx.shadowTLS.password != "" && loonShadowTLSTypes[loonType] {
		if err := ctx.shadowTLS.apply(p); err != nil {
			return nil, err
		}
	}
	return p, nil
}
// loonQuoted extracts the content of a double-quoted field, as required by
// the Loon grammar's password / uuid rules.
func loonQuoted(f string) (string, bool) {
	f = strings.TrimSpace(f)
	if len(f) >= 2 && f[0] == '"' && f[len(f)-1] == '"' {
		return f[1 : len(f)-1], true
	}
	return "", false
}

// loonParamCtx collects state shared by the Loon option rules.
type loonParamCtx struct {
	transport     string
	transportHost string
	transportPath string
	obfsType      string
	obfsHost      string
	obfsPath      string
	shadowTLS     loonShadowTLS
}

// loonShadowTLS accumulates the shadow-tls-* options. Unlike Surge, Loon
// does not default the version to 2.
type loonShadowTLS struct {
	password   string
	host       string
	version    int
	hasVersion bool
}

func (s *loonShadowTLS) apply(p *model.Proxy) error {
	if s.hasVersion && s.version < 2 {
		return fmt.Errorf("shadow-tls version %d is not supported", s.version)
	}
	p.Set("plugin", "shadow-tls")
	opts := EnsureOpts(p, "plugin-opts")
	if s.host != "" {
		opts["host"] = s.host
	}
	opts["password"] = s.password
	if s.hasVersion {
		opts["version"] = s.version
	}
	if p.Has("alpn") {
		opts["alpn"] = p.Get("alpn")
		p.Delete("alpn")
	}
	return nil
}

// applyLoonParams applies the remaining key=value options of a Loon line.
// Options not listed by the corresponding grammar rule are dropped
// (mirroring the action-less "others" rule). typ is the Loon type name.
func applyLoonParams(p *model.Proxy, fields []string, typ string, ctx *loonParamCtx) error {
	for _, f := range fields {
		f = strings.TrimSpace(f)
		idx := strings.Index(f, "=")
		if idx == -1 {
			// a positional field fails every Loon grammar rule
			return fmt.Errorf("loon %s line has a positional field: %s", typ, f)
		}
		key := strings.ToLower(strings.TrimSpace(f[:idx]))
		val := strings.TrimSpace(f[idx+1:])
		if err := applyLoonOption(p, key, val, typ, ctx); err != nil {
			return err
		}
	}
	return nil
}

// applyLoonOption applies a single Loon option key, gated by the option
// lists of the corresponding Loon grammar rule.
func applyLoonOption(p *model.Proxy, key, val, typ string, ctx *loonParamCtx) error {
	switch key {
	case "obfs-name":
		if typ == "shadowsocks" && (val == "http" || val == "tls") {
			ctx.obfsType = val
		}
	case "obfs-host":
		if typ == "shadowsocks" || typ == "shadowsocksr" {
			ctx.obfsHost = stripLoonQuotes(val)
		}
	case "obfs-uri":
		if typ == "shadowsocks" || typ == "shadowsocksr" {
			ctx.obfsPath = val
		}
	case "obfs":
		if typ == "shadowsocksr" && loonSsrObfs[val] {
			p.Set("obfs", val)
		}
	case "obfs-param":
		if typ == "shadowsocksr" {
			// the grammar token $[^=,]+ cannot cross "=" or ","
			if strings.ContainsAny(val, "=,") {
				return fmt.Errorf("loon ssr obfs-param contains = or ,")
			}
			p.Set("obfs-param", val)
		}
	case "protocol":
		if typ == "shadowsocksr" && loonSsrProtocols[val] {
			p.Set("protocol", val)
		}
	case "protocol-param":
		if typ == "shadowsocksr" {
			if strings.ContainsAny(val, "=,") {
				return fmt.Errorf("loon ssr protocol-param contains = or ,")
			}
			p.Set("protocol-param", val)
		}
	case "transport":
		if loonTransportTypes[typ] && (val == "tcp" || val == "ws" || val == "http") {
			ctx.transport = val
		}
	case "host":
		if loonTransportTypes[typ] {
			ctx.transportHost = stripLoonQuotes(val)
		}
	case "path":
		if loonTransportTypes[typ] {
			ctx.transportPath = val
		}
	case "over-tls":
		if typ == "vmess" || typ == "vless" || typ == "trojan" || typ == "anytls" || typ == "socks5" {
			b, err := parseLoonBool(key, val)
			if err != nil {
				return err
			}
			p.Set("tls", b)
		}
	case "tls-name", "sni":
		if loonTLSKeywordTypes[typ] {
			p.Set("sni", stripLoonQuotes(val))
		}
	case "skip-cert-verify":
		if loonTLSKeywordTypes[typ] {
			b, err := parseLoonBool(key, val)
			if err != nil {
				return err
			}
			p.Set("skip-cert-verify", b)
		}
	case "tls-cert-sha256":
		if loonTLSKeywordTypes[typ] {
			p.Set("tls-fingerprint", stripLoonQuotes(val))
		}
	case "tls-pubkey-sha256":
		if loonTLSKeywordTypes[typ] {
			p.Set("tls-pubkey-sha256", stripLoonQuotes(val))
		}
	case "tls-profile":
		if loonTLSKeywordTypes[typ] || typ == "shadowsocks" || typ == "shadowsocksr" {
			profile := stripLoonQuotes(val)
			p.Set("_loon_tls_profile", profile)
			switch profile {
			case "chrome":
				p.Set("client-fingerprint", "chrome")
			case "ios18", "ios26":
				p.Set("client-fingerprint", "ios")
			}
		}
	case "alpn":
		// the grammar requires a double-quoted value
		if loonTLSKeywordTypes[typ] || typ == "shadowsocks" || typ == "shadowsocksr" {
			trimmed := strings.TrimSpace(val)
			if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
				vals := parseAlpnValue(trimmed)
				if len(vals) > 0 {
					p.Set("alpn", vals)
				}
			}
		}
	case "fast-open":
		b, err := parseLoonBool(key, val)
		if err != nil {
			return err
		}
		p.Set("tfo", b)
	case "udp":
		b, err := parseLoonBool(key, val)
		if err != nil {
			return err
		}
		p.Set("udp", b)
	case "ip-mode":
		p.Set("ip-version", val)
	case "alterId":
		if typ == "vmess" {
			n, err := parseLoonInt(key, val)
			if err != nil {
				return err
			}
			p.Set("alterId", n)
		}
	case "udp-port":
		if typ == "shadowsocks" || typ == "shadowsocksr" {
			n, err := parseLoonInt(key, val)
			if err != nil {
				return err
			}
			p.Set("udp-port", n)
		}
	case "shadow-tls-password":
		if loonShadowTLSTypes[typ] {
			v := stripLoonQuotes(val)
			v = strings.TrimSpace(v)
			if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
				v = v[1 : len(v)-1]
			}
			ctx.shadowTLS.password = v
		}
	case "shadow-tls-sni":
		if loonShadowTLSTypes[typ] {
			ctx.shadowTLS.host = val
		}
	case "shadow-tls-version":
		if loonShadowTLSTypes[typ] {
			n, err := parseLoonInt(key, val)
			if err != nil {
				return err
			}
			ctx.shadowTLS.version = n
			ctx.shadowTLS.hasVersion = true
		}
	case "public-key":
		if typ == "vmess" || typ == "vless" || typ == "trojan" || typ == "anytls" {
			opts := EnsureOpts(p, "reality-opts")
			opts["public-key"] = stripLoonQuotes(val)
		}
	case "short-id":
		if typ == "vmess" || typ == "vless" || typ == "trojan" || typ == "anytls" {
			opts := EnsureOpts(p, "reality-opts")
			opts["short-id"] = stripLoonQuotes(val)
		}
	case "flow":
		if typ == "vless" {
			p.Set("flow", stripLoonQuotes(val))
		}
	case "ecn":
		if typ == "hysteria2" {
			b, err := parseLoonBool(key, val)
			if err != nil {
				return err
			}
			p.Set("ecn", b)
		}
	case "download-bandwidth":
		if typ == "hysteria2" {
			p.Set("down", val)
		}
	case "server-ports":
		if typ == "hysteria2" {
			trimmed := strings.TrimSpace(val)
			if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
				ports := trimmed[1 : len(trimmed)-1]
				ports = normalizeLoonPorts(ports)
				p.Set("ports", ports)
			}
		}
	case "hop-interval":
		if typ == "hysteria2" {
			n, err := parseLoonInt(key, val)
			if err != nil {
				return err
			}
			p.Set("hop-interval", n)
		}
	case "salamander-password":
		if typ == "hysteria2" {
			p.Set("obfs-password", val)
			p.Set("obfs", "salamander")
		}
	case "block-quic":
		b, err := parseLoonBool(key, val)
		if err != nil {
			return err
		}
		if b {
			p.Set("block-quic", "on")
		} else {
			p.Set("block-quic", "off")
		}
	case "idle-session-check-interval", "idle-session-timeout", "min-idle-session", "max-stream-count":
		if typ == "anytls" {
			n, err := parseLoonInt(key, val)
			if err != nil {
				return err
			}
			p.Set(key, n)
		}
	case "udp-over-tcp":
		if typ == "shadowsocks" {
			b, err := parseLoonBool(key, val)
			if err != nil {
				return err
			}
			if b {
				p.Set("udp-over-tcp", true)
				p.Set("udp-over-tcp-version", 2)
			}
		}
	}
	return nil
}

// stripLoonQuotes strips a pair of double quotes (the Loon grammar's
// ^"(.*)"$ replacement).
func stripLoonQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// parseLoonBool parses a Loon grammar bool flag ("true"/"false" only).
func parseLoonBool(key, val string) (bool, error) {
	switch val {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("loon %s must be true or false, got %q", key, val)
}

// parseLoonInt parses a Loon grammar $[0-9]+ integer.
func parseLoonInt(key, val string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(val))
	if err != nil {
		return 0, fmt.Errorf("loon %s must be an integer, got %q", key, val)
	}
	return n, nil
}

// normalizeLoonVmessSecurity mirrors the Loon normalizeVmessSecurity
// helper: supported values pass through (chacha20 renamed), anything else
// falls back to "auto".
func normalizeLoonVmessSecurity(security string) string {
	normalized := strings.ToLower(strings.TrimSpace(security))
	if !loonVmessSecurities[normalized] {
		return "auto"
	}
	if normalized == "chacha20-ietf-poly1305" {
		return "chacha20-poly1305"
	}
	return normalized
}

// normalizeLoonPorts normalizes the spacing of a server-ports value
// (spaces around "-" and "," are removed).
var (
	loonPortsSpacesRe = regexp.MustCompile(`\s*-\s*`)
	loonCommasSpacesRe = regexp.MustCompile(`\s*,\s*`)
)

func normalizeLoonPorts(ports string) string {
	return loonPortsSpacesRe.ReplaceAllString(loonCommasSpacesRe.ReplaceAllString(ports, ","), "-")
}

// applyLoonTransport assembles the ws/http transport options, mirroring the
// Loon grammar: ws-opts uses plain strings, http-opts uses single-element
// arrays (path and header values).
func applyLoonTransport(p *model.Proxy, ctx *loonParamCtx) {
	if ctx.transport != "ws" && ctx.transport != "http" {
		return
	}
	p.Set("network", ctx.transport)
	opts := EnsureOpts(p, ctx.transport+"-opts")
	if ctx.transport == "http" {
		if ctx.transportPath != "" {
			opts["path"] = []any{ctx.transportPath}
		}
		if ctx.transportHost != "" {
			opts["headers"] = map[string]any{"Host": []any{ctx.transportHost}}
		}
		return
	}
	if ctx.transportPath != "" {
		opts["path"] = ctx.transportPath
	}
	if ctx.transportHost != "" {
		opts["headers"] = map[string]any{"Host": ctx.transportHost}
	}
}

// --- Loon WireGuard (hand-written parser, mirroring Loon_WireGuard) ---

var (
	loonWgPeersRe = regexp.MustCompile(`(?i),\s*peers\s*=\s*\[\s*\{\s*(.+?)\s*\}\s*\]`)
	loonWgPortRe  = regexp.MustCompile(`(?i)(?:^|,)\s*endpoint\s*=\s*"?(.+?):(\d+)"?\s*(?:,|$)`)
	loonWgResvRe  = regexp.MustCompile(`(?i)(?:^|,)\s*reserved\s*=\s*"?(\[\s*.+?\s*\])"?\s*(?:,|$)`)
	loonWgIpsRe   = regexp.MustCompile(`(?i)(?:^|,)\s*allowed-ips\s*=\s*"(.+?)"\s*(?:,|$)`)
)

// loonWgValue extracts the value of a specific key=value option, mirroring
// the Loon_WireGuard regexes (quotes optional).
func loonWgValue(s, key string) string {
	re := regexp.MustCompile(`(?i)(?:^|,)\s*` + regexp.QuoteMeta(key) + `\s*=\s*"?(.*?)"?\s*(?:,|$)`)
	m := re.FindStringSubmatch(s)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

// loonWgInt extracts an integer option value.
func loonWgInt(s, key string) (int, bool) {
	re := regexp.MustCompile(`(?i)(?:^|,)\s*` + regexp.QuoteMeta(key) + `\s*=\s*"?(\d+)"?\s*(?:,|$)`)
	m := re.FindStringSubmatch(s)
	if len(m) > 1 {
		n, err := strconv.Atoi(m[1])
		if err == nil {
			return n, true
		}
	}
	return 0, false
}

// parseLoonWireGuard parses a Loon wireguard line, mirroring Sub-Store's
// Loon_WireGuard parser: the endpoint / public-key / reserved / allowed-ips
// live inside a peers=[{...}] block, the interface settings on the line
// itself.
func parseLoonWireGuard(name, rest string) (*model.Proxy, error) {
	peers := ""
	if m := loonWgPeersRe.FindStringSubmatch(rest); len(m) > 1 {
		peers = m[1]
	}

	p := model.NewProxy()
	p.Set("type", "wireguard")
	p.Set("name", name)

	if m := loonWgPortRe.FindStringSubmatch(peers); len(m) > 2 {
		if port, err := strconv.Atoi(m[2]); err == nil {
			p.Set("server", m[1])
			p.Set("port", port)
		}
	}
	if n, ok := loonWgInt(rest, "mtu"); ok {
		p.Set("mtu", n)
	}
	if n, ok := loonWgInt(rest, "keepalive"); ok {
		p.Set("keepalive", n)
	}
	if m := loonWgResvRe.FindStringSubmatch(peers); len(m) > 1 {
		p.Set("reserved", parseLoonJSONArrayInts(m[1]))
	}
	var dns []any
	if v := loonWgValue(rest, "dns"); v != "" {
		dns = append(dns, v)
	}
	if v := loonWgValue(rest, "dnsv6"); v != "" {
		dns = append(dns, v)
	}
	if len(dns) > 0 {
		p.Set("dns", dns)
		p.Set("remote-dns-resolve", true)
	}
	if m := loonWgIpsRe.FindStringSubmatch(peers); len(m) > 1 {
		parts := strings.Split(m[1], ",")
		ips := make([]any, 0, len(parts))
		for _, ip := range parts {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				ips = append(ips, ip)
			}
		}
		p.Set("allowed-ips", ips)
	}
	p.Set("private-key", loonWgValue(rest, "private-key"))
	p.Set("ip", loonWgValue(rest, "interface-ip"))
	p.Set("ipv6", loonWgValue(rest, "interface-ipv6"))
	p.Set("public-key", loonWgValue(peers, "public-key"))
	p.Set("preshared-key", loonWgValue(peers, "preshared-key"))

	peer := map[string]any{
		"server":         p.GetString("server"),
		"port":           p.Get("port"),
		"ip":             p.GetString("ip"),
		"ipv6":           p.GetString("ipv6"),
		"public-key":     p.GetString("public-key"),
		"pre-shared-key": p.GetString("preshared-key"),
		"allowed-ips":    p.Get("allowed-ips"),
		"reserved":       p.Get("reserved"),
	}
	p.Set("peers", []any{peer})

	p.Set("udp", true)
	return p, nil
}

// parseLoonJSONArrayInts parses a [1,2,3]-style reserved value.
func parseLoonJSONArrayInts(s string) []any {
	out := []any{}
	for _, m := range regexp.MustCompile(`\d+`).FindAllString(s, -1) {
		if n, err := strconv.Atoi(m); err == nil {
			out = append(out, n)
		}
	}
	return out
}

