package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"substore/internal/model"
)

var surgeTypes = map[string]bool{
	"direct": true, "ss": true, "vmess": true, "trojan": true, "http": true,
	"https": true, "socks5": true, "socks5-tls": true, "snell": true,
	"tuic": true, "tuic-v5": true, "hysteria2": true,
	"wireguard": true, "vless": true, "anytls": true, "h2-connect": true,
	"trust-tunnel": true, "trusttunnel": true, "ssh": true, "external": true,
}

// surgeLoonOnlyOptionsRe matches option keys that only Loon uses; a Surge
// http/https/socks5 line containing any of them is handed over to the Loon
// parser (mirrors Sub-Store's LOON_ONLY_OPTIONS filter).
var surgeLoonOnlyOptionsRe = regexp.MustCompile(`(?i)(^|,)\s*(fast-open|over-tls|tls-name|ip-mode|tls-cert-sha256|tls-pubkey-sha256)\s*=`)

// surgePortHoppingRe extracts the port-hopping option from Surge tuic /
// hysteria2 lines before field splitting (mirrors Sub-Store's
// surge_port_hopping pre-processing).
var surgePortHoppingRe = regexp.MustCompile(`,\s*port-hopping\s*=\s*["']?\s*((\d+(-\d+)?)([,;]\d+(-\d+)?)*)\s*["']?\s*`)

// surgeCiphers is the cipher enumeration accepted by the Surge ss grammar.
var surgeCiphers = map[string]bool{
	"aes-128-cfb": true, "aes-128-ctr": true, "aes-128-gcm": true,
	"aes-192-cfb": true, "aes-192-ctr": true, "aes-192-gcm": true,
	"aes-256-cfb": true, "aes-256-ctr": true, "aes-256-gcm": true,
	"bf-cfb": true, "camellia-128-cfb": true, "camellia-192-cfb": true,
	"camellia-256-cfb": true, "cast5-cfb": true, "chacha20-ietf-poly1305": true,
	"chacha20-ietf": true, "chacha20-poly1305": true, "chacha20": true,
	"des-cfb": true, "idea-cfb": true, "none": true, "rc2-cfb": true,
	"rc4-md5": true, "rc4": true, "salsa20": true, "seed-cfb": true,
	"xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
}

// surgeVmessSecurities are the encrypt-method values accepted for Surge
// vmess lines; anything else falls back to "auto".
var surgeVmessSecurities = map[string]bool{
	"aes-128-gcm": true, "chacha20-ietf-poly1305": true,
}

// surgeShadowTLSTypes are the Surge types whose grammar includes the
// shadow-tls-* options (anytls / trust-tunnel do not).
var surgeShadowTLSTypes = map[string]bool{
	"ss": true, "vmess": true, "trojan": true, "https": true, "http": true,
	"ssh": true, "snell": true, "tuic": true, "tuic-v5": true,
	"wireguard": true, "hysteria2": true, "socks5": true, "socks5-tls": true,
	"h2-connect": true,
}

// surgeHasPositionalAuth lists the Surge types whose grammar accepts
// positional username/password fields after the address.
var surgeHasPositionalAuth = map[string]bool{
	"http": true, "https": true, "h2-connect": true, "ssh": true,
	"socks5": true, "socks5-tls": true,
}

func surgeLineTest(line string) bool {
	idx := strings.Index(line, "=")
	if idx == -1 {
		return false
	}
	first := strings.SplitN(line[idx+1:], ",", 2)[0]
	typ := strings.TrimSpace(first)
	if !surgeTypes[typ] {
		return false
	}
	switch typ {
	case "vmess":
		// Surge vmess lines carry the uuid in a "username" option, which
		// distinguishes them from Loon vmess lines.
		return strings.Contains(line, "username=")
	case "http", "https", "socks5", "socks5-tls":
		// Loon-specific options are not valid Surge syntax; let the Loon
		// parser handle those lines.
		return !surgeLoonOnlyOptionsRe.MatchString(line)
	}
	return true
}

func parseSurgeLine(line string) (*model.Proxy, error) {
	eq := strings.Index(line, "=")
	if eq == -1 {
		return nil, fmt.Errorf("invalid surge line")
	}
	name := strings.TrimSpace(line[:eq])
	rest := line[eq+1:]

	first := strings.SplitN(rest, ",", 2)[0]
	typ := strings.TrimSpace(first)

	p := model.NewProxy()
	p.Set("name", name)

	if typ == "external" {
		return parseSurgeExternal(p, rest)
	}

	// port-hopping is extracted from tuic / hysteria2 lines before field
	// splitting (mirrors Sub-Store's surge_port_hopping pre-processing).
	ports := ""
	if typ == "tuic" || typ == "tuic-v5" || typ == "hysteria2" {
		ports, rest = extractSurgePortHopping(rest)
	}

	fields := splitSurgeFields(rest)
	if len(fields) < 1 {
		return nil, fmt.Errorf("invalid surge line")
	}

	switch typ {
	case "direct":
		p.Set("type", "direct")
		if err := applySurgeParams(p, fields[1:], &surgeParamCtx{typ: typ}); err != nil {
			return nil, err
		}
		return p, nil
	case "wireguard":
		// Surge wireguard sections carry no address; the peer endpoint is
		// configured in a separate section.
		p.Set("type", "wireguard-surge")
		if err := applySurgeParams(p, fields[1:], &surgeParamCtx{typ: typ}); err != nil {
			return nil, err
		}
		return p, nil
	}

	if len(fields) < 3 {
		return nil, fmt.Errorf("invalid surge line")
	}
	portStr := strings.TrimSpace(fields[2])
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid surge port: %s", portStr)
	}
	p.Set("type", typ)
	p.Set("server", strings.TrimSpace(fields[1]))
	p.Set("port", port)

	// positional username/password
	pos := 3
	if surgeHasPositionalAuth[typ] {
		// The Surge grammar accepts (username password)? as a pair: when a
		// positional username is present a positional password must follow,
		// otherwise the line fails the grammar and falls through to Loon.
		if len(fields) > 3 && !strings.Contains(fields[3], "=") {
			if len(fields) < 5 || strings.Contains(fields[4], "=") {
				return nil, fmt.Errorf("surge %s positional username requires positional password", typ)
			}
			p.Set("username", TrimQuotes(fields[3]))
			p.Set("password", TrimQuotes(fields[4]))
			pos = 5
		}
	} else if len(fields) > 3 && !strings.Contains(fields[3], "=") {
		// Address-only types have no positional options; any positional
		// field fails the Surge grammar. This is what hands Loon-style
		// vmess / trojan lines over to the Loon parser.
		return nil, fmt.Errorf("surge %s line has a positional field: %s", typ, fields[3])
	}

	gtyp := typ
	if typ == "trusttunnel" {
		gtyp = "trust-tunnel"
	}
	ctx := &surgeParamCtx{typ: gtyp}
	// vmess cipher defaults to "auto" before the encrypt-method option is
	// applied (mirrors the Surge grammar).
	if typ == "vmess" {
		p.Set("cipher", "auto")
	}
	if err := applySurgeParams(p, fields[pos:], ctx); err != nil {
		return nil, err
	}

	// type mapping and defaults
	switch typ {
	case "https":
		p.Set("type", "http")
		p.Set("tls", true)
	case "socks5-tls":
		p.Set("type", "socks5")
		p.Set("tls", true)
	case "tuic-v5":
		p.Set("type", "tuic")
		p.Set("version", 5)
	case "trust-tunnel", "trusttunnel":
		p.Set("type", "trusttunnel")
		p.Set("tls", true)
	case "anytls", "h2-connect":
		p.Set("tls", true)
	}

	// Surge vmess alterId derives from vmess-aead (0) or defaults to 1.
	if typ == "vmess" {
		if ctx.aead {
			p.Set("alterId", 0)
		} else {
			p.Set("alterId", 1)
		}
	}

	// websocket transport (vmess/trojan per the Surge grammar, plus the
	// vless extension for round-trip with the Surge producer).
	if typ == "vmess" || typ == "trojan" || typ == "vless" {
		applySurgeWebsocket(p, ctx)
	}

	// obfs plugin assembly
	switch typ {
	case "ss":
		if ctx.obfsType == "http" || ctx.obfsType == "tls" {
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
	case "snell":
		if ctx.obfsType == "http" || ctx.obfsType == "tls" {
			opts := EnsureOpts(p, "obfs-opts")
			opts["mode"] = ctx.obfsType
			if ctx.obfsHost != "" {
				opts["host"] = ctx.obfsHost
			}
			if ctx.obfsPath != "" {
				opts["path"] = ctx.obfsPath
			}
		}
	}

	// shadow-tls plugin assembly
	if ctx.shadowTLS.password != "" && surgeShadowTLSTypes[typ] {
		if err := ctx.shadowTLS.apply(p); err != nil {
			return nil, err
		}
	}

	if ports != "" {
		p.Set("ports", ports)
	}
	return p, nil
}

// surgeParamCtx collects state shared by the Surge option rules.
type surgeParamCtx struct {
	typ         string
	obfsType    string
	obfsHost    string
	obfsPath    string
	obfsHeaders map[string]string
	shadowTLS   surgeShadowTLS
	aead        bool
}

// surgeShadowTLS accumulates the shadow-tls-* options.
type surgeShadowTLS struct {
	password    string
	host        string
	version     int
	hasVersion  bool
	defaultV2   bool // surge defaults the version to 2; loon does not
}

func (s *surgeShadowTLS) apply(p *model.Proxy) error {
	// mirrors surge.js:35 `if (shadowTLS.password && !shadowTLS.version)`:
	// an unset version AND an explicit 0 both default to 2 (0 is falsy)
	if s.defaultV2 && (!s.hasVersion || s.version == 0) {
		s.version = 2
		s.hasVersion = true
	}
	if s.hasVersion && s.version < 2 {
		return fmt.Errorf("shadow-tls version %d is not supported", s.version)
	}
	p.Set("plugin", "shadow-tls")
	opts := EnsureOpts(p, "plugin-opts")
	if s.host != "" {
		opts["host"] = s.host
	}
	opts["password"] = s.password
	if s.hasVersion || s.defaultV2 {
		opts["version"] = s.version
	}
	if p.Has("alpn") {
		opts["alpn"] = p.Get("alpn")
		p.Delete("alpn")
	}
	return nil
}

func applySurgeParams(p *model.Proxy, fields []string, ctx *surgeParamCtx) error {
	for _, f := range fields {
		f = strings.TrimSpace(f)
		idx := strings.Index(f, "=")
		if idx == -1 {
			// A positional field fails every Surge grammar rule.
			return fmt.Errorf("surge %s line has a positional field: %s", ctx.typ, f)
		}
		key := strings.ToLower(strings.TrimSpace(f[:idx]))
		val := TrimQuotes(strings.TrimSpace(f[idx+1:]))
		// The peggy grammar has no bracket-aware value scanning, so a
		// value containing a comma fails unless the key uses a dedicated
		// reader (headers / ws-headers / alpn).
		if strings.Contains(val, ",") {
			switch key {
			case "headers", "ws-headers", "alpn":
			default:
				return fmt.Errorf("surge %s value contains a comma: %s", key, val)
			}
		}
		if err := applySurgeOption(p, key, val, ctx); err != nil {
			return err
		}
	}
	return nil
}

// applySurgeOption applies a single Surge option key, gated by the option
// lists of the corresponding Surge grammar rule. Unknown keys are dropped
// (mirroring the action-less "others" rule of the peggy grammar).
func applySurgeOption(p *model.Proxy, key, val string, ctx *surgeParamCtx) error {
	typ := ctx.typ
	switch key {
	case "encrypt-method":
		switch typ {
		case "vmess":
			p.Set("cipher", normalizeSurgeVmessSecurity(val))
		case "ss":
			// the cipher rule is a strict enumeration; anything else is
			// consumed by "others" and dropped
			if surgeCiphers[val] {
				p.Set("cipher", val)
			}
		}
	case "username":
		if typ == "vmess" || typ == "vless" {
			p.Set("uuid", val)
		} else if surgeKeywordTypes["username"][typ] {
			p.Set("username", val)
		}
	case "password":
		if surgeKeywordTypes["password"][typ] {
			p.Set("password", val)
		}
	case "tls":
		if surgeKeywordTypes["tls"][typ] {
			b, err := parseSurgeBool(val, "tls")
			if err != nil {
				return err
			}
			p.Set("tls", b)
		}
	case "sni":
		if surgeKeywordTypes["sni"][typ] {
			if val == "off" {
				p.Set("disable-sni", true)
			} else {
				p.Set("sni", val)
			}
		}
	case "server-cert-verify-name":
		if surgeKeywordTypes["server-cert-verify-name"][typ] {
			p.Set("name-cert-verify", val)
		}
	case "skip-cert-verify":
		if surgeKeywordTypes["server-cert-verify-name"][typ] {
			b, err := parseSurgeBool(val, "skip-cert-verify")
			if err != nil {
				return err
			}
			p.Set("skip-cert-verify", b)
		}
	case "server-cert-fingerprint-sha256":
		if surgeKeywordTypes["server-cert-verify-name"][typ] {
			p.Set("tls-fingerprint", val)
		}
	case "client-cert":
		if surgeKeywordTypes["server-cert-verify-name"][typ] {
			p.Set("keystore-client-cert", val)
		}
	case "ws":
		if surgeKeywordTypes["ws"][typ] {
			b, err := parseSurgeBool(val, "ws")
			if err != nil {
				return err
			}
			if b {
				ctx.obfsType = "ws"
			}
		}
	case "ws-path":
		if surgeKeywordTypes["ws"][typ] {
			ctx.obfsPath = val
		}
	case "ws-headers":
		if surgeKeywordTypes["ws"][typ] {
			ctx.obfsHeaders = parseSurgeHeaders(val, '|')
		}
	case "headers":
		if surgeKeywordTypes["headers"][typ] {
			p.Set("headers", parseSurgeHeaders(val, ';'))
		}
	case "obfs":
		if surgeKeywordTypes["obfs"][typ] && (val == "http" || val == "tls") {
			ctx.obfsType = val
		}
	case "obfs-host":
		if surgeKeywordTypes["obfs"][typ] {
			ctx.obfsHost = val
		}
	case "obfs-uri":
		if surgeKeywordTypes["obfs"][typ] {
			ctx.obfsPath = val
		}
	case "udp-relay":
		if surgeKeywordTypes["udp-relay"][typ] {
			b, err := parseSurgeBool(val, "udp-relay")
			if err != nil {
				return err
			}
			p.Set("udp", b)
		}
	case "fast-open", "tfo":
		if surgeKeywordTypes["tfo"][typ] {
			b, err := parseSurgeBool(val, key)
			if err != nil {
				return err
			}
			p.Set("tfo", b)
		}
	case "reuse":
		if surgeKeywordTypes["reuse"][typ] {
			b, err := parseSurgeBool(val, "reuse")
			if err != nil {
				return err
			}
			p.Set("reuse", b)
		}
	case "ecn":
		if surgeKeywordTypes["ecn"][typ] {
			b, err := parseSurgeBool(val, "ecn")
			if err != nil {
				return err
			}
			p.Set("ecn", b)
		}
	case "alpn":
		if surgeKeywordTypes["alpn"][typ] {
			if vals := parseAlpnValue(val); len(vals) > 0 {
				p.Set("alpn", vals)
			}
		}
	case "ip-version":
		p.Set("ip-version", val)
	case "section-name":
		if typ == "wireguard" {
			p.Set("section-name", val)
		}
	case "no-error-alert", "underlying-proxy", "test-url", "test-udp", "block-quic":
		p.Set(key, val)
	case "test-timeout", "tos":
		n, err := parseSurgeInt(val, key)
		if err != nil {
			return err
		}
		p.Set(key, n)
	case "idle-timeout":
		if typ == "ssh" {
			n, err := parseSurgeInt(val, key)
			if err != nil {
				return err
			}
			p.Set("idle-timeout", n)
		}
	case "max-streams":
		if surgeKeywordTypes["max-streams"][typ] {
			n, err := parseSurgeInt(val, key)
			if err != nil {
				return err
			}
			p.Set("max-streams", n)
		}
	case "udp-port":
		if typ == "ss" {
			n, err := parseSurgeInt(val, key)
			if err != nil {
				return err
			}
			p.Set("udp-port", n)
		}
	case "port-hopping-interval":
		if surgeKeywordTypes["port-hopping-interval"][typ] {
			n, err := parseSurgeInt(val, key)
			if err != nil {
				return err
			}
			p.Set("hop-interval", n)
		}
	case "interface":
		p.Set("interface", val)
	case "allow-other-interface", "hybrid":
		b, err := parseSurgeBool(val, key)
		if err != nil {
			return err
		}
		p.Set(key, b)
	case "private-key":
		if typ == "ssh" {
			p.Set("keystore-private-key", val)
		}
	case "server-fingerprint":
		if typ == "ssh" {
			p.Set("server-fingerprint", val)
		}
	case "download-bandwidth":
		if typ == "hysteria2" {
			p.Set("down", val)
		}
	case "salamander-password":
		if typ == "hysteria2" {
			p.Set("obfs-password", val)
			p.Set("obfs", "salamander")
		}
	case "gecko-password":
		if typ == "hysteria2" {
			p.Set("obfs-password", val)
			p.Set("obfs", "gecko")
		}
	case "token":
		if typ == "tuic" {
			p.Set("token", val)
		}
	case "uuid":
		if typ == "tuic-v5" {
			p.Set("uuid", val)
		}
	case "psk":
		if typ == "snell" {
			p.Set("psk", val)
		}
	case "version":
		if typ == "snell" {
			n, err := parseSurgeInt(val, "version")
			if err != nil {
				return err
			}
			p.Set("version", n)
		}
	case "mode":
		if typ == "snell" {
			switch val {
			case "default", "unshaped", "unsafe-raw":
				p.Set("mode", val)
			}
		}
	case "vmess-aead":
		if typ == "vmess" {
			b, err := parseSurgeBool(val, "vmess-aead")
			if err != nil {
				return err
			}
			ctx.aead = b
			p.Set("aead", b)
		}
	case "reality-public-key", "reality-short-id", "flow":
		// subx extension: the Surge producer emits these for vless lines so
		// vless reality nodes round-trip (Sub-Store's Surge grammar has no
		// vless rule at all, so it has no reference behavior here).
		if typ == "vless" {
			switch key {
			case "reality-public-key":
				opts := EnsureOpts(p, "reality-opts")
				opts["public-key"] = val
			case "reality-short-id":
				opts := EnsureOpts(p, "reality-opts")
				opts["short-id"] = val
			case "flow":
				p.Set("flow", val)
			}
		}
	case "shadow-tls-password":
		if surgeShadowTLSTypes[typ] {
			ctx.shadowTLS.password = val
			ctx.shadowTLS.defaultV2 = true
		}
	case "shadow-tls-sni":
		if surgeShadowTLSTypes[typ] {
			ctx.shadowTLS.host = val
		}
	case "shadow-tls-version":
		if surgeShadowTLSTypes[typ] {
			n, err := parseSurgeInt(val, "shadow-tls-version")
			if err != nil {
				return err
			}
			ctx.shadowTLS.version = n
			ctx.shadowTLS.hasVersion = true
		}
	}
	return nil
}

// parseSurgeBool parses a Surge grammar bool flag ("true"/"false" only).
func parseSurgeBool(val, key string) (bool, error) {
	switch val {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("surge %s must be true or false, got %q", key, val)
}

// parseSurgeInt parses a Surge grammar $[0-9]+ integer.
func parseSurgeInt(val, key string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(val))
	if err != nil {
		return 0, fmt.Errorf("surge %s must be an integer, got %q", key, val)
	}
	return n, nil
}

// surgeKeywordTypes maps Surge option keys to the proxy types whose grammar
// rule lists them; options outside the list are consumed by "others" and
// dropped. Mirrors the peggy/surge.js grammar rule lists.
var surgeKeywordTypes = map[string]map[string]bool{
	"username": surgeTypeSet("http", "https", "h2-connect", "ssh", "socks5", "socks5-tls", "trust-tunnel"),
	"password": surgeTypeSet("ss", "trojan", "https", "h2-connect", "http", "ssh", "snell", "tuic-v5", "hysteria2", "socks5", "socks5-tls", "anytls", "trust-tunnel", "vless"),
	"tls":      surgeTypeSet("vmess", "trojan", "https", "h2-connect", "tuic", "tuic-v5", "socks5-tls", "anytls", "trust-tunnel", "vless"),
	"sni":      surgeTypeSet("vmess", "trojan", "https", "h2-connect", "tuic", "tuic-v5", "socks5-tls", "anytls", "trust-tunnel", "hysteria2", "vless"),
	"server-cert-verify-name": surgeTypeSet("vmess", "trojan", "https", "h2-connect", "tuic", "tuic-v5", "ssh", "socks5-tls", "anytls", "trust-tunnel", "hysteria2", "vless"),
	"ws":      surgeTypeSet("vmess", "trojan", "vless"),
	"headers": surgeTypeSet("https", "h2-connect", "http", "trust-tunnel"),
	"obfs":    surgeTypeSet("ss", "snell"),
	"udp-relay": surgeTypeSet("ss", "vmess", "trojan", "https", "h2-connect", "http", "ssh", "snell", "socks5", "socks5-tls", "direct"),
	"tfo": surgeTypeSet("ss", "vmess", "trojan", "https", "h2-connect", "http", "ssh", "snell", "tuic", "tuic-v5", "socks5", "socks5-tls", "anytls", "trust-tunnel", "direct", "hysteria2", "vless"),
	"reuse":  surgeTypeSet("snell", "anytls", "trust-tunnel"),
	"ecn":    surgeTypeSet("tuic", "tuic-v5", "hysteria2"),
	"alpn":   surgeTypeSet("ss", "snell", "ssh", "vmess", "trojan", "https", "h2-connect", "tuic", "tuic-v5", "socks5-tls", "anytls", "trust-tunnel", "hysteria2", "vless"),
	"max-streams": surgeTypeSet("h2-connect", "trust-tunnel"),
	"port-hopping-interval": surgeTypeSet("tuic", "tuic-v5", "hysteria2"),
}

func surgeTypeSet(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

func normalizeSurgeVmessSecurity(security string) string {
	normalized := strings.ToLower(strings.TrimSpace(security))
	if !surgeVmessSecurities[normalized] {
		return "auto"
	}
	if normalized == "chacha20-ietf-poly1305" {
		return "chacha20-poly1305"
	}
	return normalized
}

func parseAlpnValue(v string) []any {
	parts := strings.Split(TrimQuotes(v), ",")
	out := make([]any, 0, len(parts))
	for _, item := range parts {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func applySurgeWebsocket(p *model.Proxy, ctx *surgeParamCtx) {
	if ctx.obfsType != "ws" {
		return
	}
	p.Set("network", "ws")
	opts := EnsureOpts(p, "ws-opts")
	if ctx.obfsPath != "" {
		opts["path"] = ctx.obfsPath
	}
	if len(ctx.obfsHeaders) > 0 {
		headers := map[string]any{}
		for k, v := range ctx.obfsHeaders {
			headers[k] = v
		}
		opts["headers"] = headers
	}
}

func extractSurgePortHopping(raw string) (ports string, line string) {
	m := surgePortHoppingRe.FindString(raw)
	if m == "" {
		return "", raw
	}
	sub := surgePortHoppingRe.FindStringSubmatch(raw)
	ports = strings.ReplaceAll(sub[1], ";", ",")
	return ports, strings.Replace(raw, m, "", 1)
}

// parseSurgeExternal parses the Surge external definition format
// (mirrors Sub-Store's Surge_External parser).
func parseSurgeExternal(p *model.Proxy, rest string) (*model.Proxy, error) {
	fields := splitSurgeFields(rest)
	p.Set("type", "external")
	var args, addresses []string
	for _, f := range fields[1:] {
		kv := strings.SplitN(f, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := TrimQuotes(strings.TrimSpace(kv[1]))
		switch key {
		case "exec":
			p.Set("exec", val)
		case "local-port":
			p.Set("local-port", val)
		case "args":
			args = append(args, val)
		case "addresses":
			ip := strings.Trim(val, "[]")
			if isIPString(ip) {
				addresses = append(addresses, ip)
			}
		}
	}
	// mirrors Sub-Store Surge_External (index.js:3056-3063): args and
	// addresses are always set, possibly as empty arrays
	p.Set("args", toStringSlice(args))
	p.Set("addresses", toStringSlice(addresses))
	return p, nil
}

func toStringSlice(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// splitSurgeFields splits the right-hand side of a Surge/Loon proxy line into
// comma-separated fields. Commas inside quoted regions (headers values,
// quoted values, bracket groups) are kept intact, mirroring the Sub-Store
// peggy grammars.
func splitSurgeFields(s string) []string {
	out := []string{}
	i := 0
	n := len(s)
	for i < n {
		// skip spaces
		j := i
		for j < n && isSurgeSpace(s[j]) {
			j++
		}
		// read a key up to '=' or ','
		keyStart := j
		for j < n && s[j] != '=' && s[j] != ',' {
			j++
		}
		if j < n && s[j] == '=' {
			key := strings.ToLower(strings.TrimSpace(s[keyStart:j]))
			j++ // skip '='
			for j < n && isSurgeSpace(s[j]) {
				j++
			}
			switch key {
			case "headers":
				j = readSurgeHeadersEnd(s, j, ';')
			case "ws-headers":
				j = readSurgeHeadersEnd(s, j, '|')
			case "alpn":
				if j < n && (s[j] == '"' || s[j] == '\'') {
					q := s[j]
					k := j + 1
					for k < n && s[k] != q {
						k++
					}
					if k < n {
						j = k + 1
					} else {
						j = n
					}
				}
			}
		}
		// plain scan to the next comma, skipping quoted and bracket regions
		for j < n && s[j] != ',' {
			switch s[j] {
			case '"', '\'':
				q := s[j]
				j++
				for j < n && s[j] != q {
					j++
				}
				if j < n {
					j++
				}
			case '[':
				j++
				for j < n && s[j] != ']' {
					if s[j] == '"' || s[j] == '\'' {
						q := s[j]
						j++
						for j < n && s[j] != q {
							j++
						}
					}
					j++
				}
				if j < n {
					j++
				}
			default:
				j++
			}
		}
		out = append(out, strings.TrimSpace(s[i:j]))
		if j < n {
			j++ // skip ','
		}
		i = j
	}
	return out
}

func isSurgeSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r'
}

// isSurgeHeaderKeyChar matches the Surge header key token class
// [!#$%&'*+\-.^_|~0-9A-Za-z].
func isSurgeHeaderKeyChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
		strings.IndexByte("!#$%&'*+-.^_|~", c) != -1
}

// isSurgeOptionKeyChar matches the option key token class [0-9A-Za-z-].
func isSurgeOptionKeyChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '-'
}

// readSurgeQuotedHeaderKey returns the index right after the closing quote of
// a quoted header key starting at text[start], or -1 when malformed.
func readSurgeQuotedHeaderKey(text string, start int) int {
	quote := text[start]
	index := start + 1
	hasKey := false
	for index < len(text) {
		if text[index] == quote {
			if hasKey {
				return index + 1
			}
			return -1
		}
		hasKey = true
		index++
	}
	return -1
}

func startsWithSurgeQuotedHeaderKey(s string) bool {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) == 0 || (trimmed[0] != '"' && trimmed[0] != '\'') {
		return false
	}
	index := readSurgeQuotedHeaderKey(trimmed, 0)
	if index == -1 {
		return false
	}
	for index < len(trimmed) && isSurgeSpace(trimmed[index]) {
		index++
	}
	return index < len(trimmed) && trimmed[index] == ':'
}

func isSurgeHeaderKeyStart(text string, start int) bool {
	index := start
	for index < len(text) && isSurgeSpace(text[index]) {
		index++
	}
	if index < len(text) && (text[index] == '"' || text[index] == '\'') {
		index = readSurgeQuotedHeaderKey(text, index)
		if index == -1 {
			return false
		}
	} else {
		keyStart := index
		for index < len(text) && isSurgeHeaderKeyChar(text[index]) {
			index++
		}
		if index == keyStart {
			return false
		}
	}
	for index < len(text) && isSurgeSpace(text[index]) {
		index++
	}
	return index < len(text) && text[index] == ':'
}

func isSurgeOptionStart(text string, start int) bool {
	index := start
	for index < len(text) && isSurgeSpace(text[index]) {
		index++
	}
	keyStart := index
	for index < len(text) && isSurgeOptionKeyChar(text[index]) {
		index++
	}
	if index == keyStart {
		return false
	}
	for index < len(text) && isSurgeSpace(text[index]) {
		index++
	}
	return index < len(text) && text[index] == '='
}

func isSurgeHeaderValueQuoteEnd(text string, index int, sep byte, allowCommaEnd bool, containerQuote byte) bool {
	cursor := index + 1
	for cursor < len(text) && isSurgeSpace(text[cursor]) {
		cursor++
	}
	if cursor >= len(text) {
		return true
	}
	if allowCommaEnd && text[cursor] == ',' && isSurgeOptionStart(text, cursor+1) {
		return true
	}
	if text[cursor] == sep && isSurgeHeaderKeyStart(text, cursor+1) {
		return true
	}
	if containerQuote != 0 && text[cursor] == containerQuote {
		next := cursor + 1
		for next < len(text) && isSurgeSpace(text[next]) {
			next++
		}
		return next >= len(text) || text[next] == ','
	}
	return false
}

func readSurgeUnquotedHeadersEnd(text string, start int, sep byte) int {
	index := start
	var quote byte
	quoteRole := 0 // 0 none, 1 key, 2 value
	seenSeparator := false
	for index < len(text) {
		ch := text[index]
		if quote != 0 {
			if ch == quote {
				if quoteRole == 1 || isSurgeHeaderValueQuoteEnd(text, index, sep, true, 0) {
					quote = 0
					quoteRole = 0
				}
			}
			index++
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
			if seenSeparator {
				quoteRole = 2
			} else {
				quoteRole = 1
			}
			index++
			continue
		}
		if ch == ':' && !seenSeparator {
			seenSeparator = true
			index++
			continue
		}
		if ch == sep && isSurgeHeaderKeyStart(text, index+1) {
			seenSeparator = false
			index++
			continue
		}
		if ch == ',' {
			break
		}
		index++
	}
	return index
}

func readSurgeQuotedHeadersEnd(text string, start int, sep byte) int {
	quote := text[start]
	index := start + 1
	var innerQuote byte
	quoteRole := 0
	seenSeparator := false
	for index < len(text) {
		ch := text[index]
		if innerQuote != 0 {
			if ch == innerQuote {
				if quoteRole == 1 || isSurgeHeaderValueQuoteEnd(text, index, sep, false, quote) {
					innerQuote = 0
					quoteRole = 0
				}
			}
			index++
			continue
		}
		if ch == quote {
			cursor := index + 1
			for cursor < len(text) && isSurgeSpace(text[cursor]) {
				cursor++
			}
			if cursor >= len(text) || text[cursor] == ',' {
				return index + 1
			}
		}
		if ch == '"' || ch == '\'' {
			innerQuote = ch
			if seenSeparator {
				quoteRole = 2
			} else {
				quoteRole = 1
			}
			index++
			continue
		}
		if ch == ':' && !seenSeparator {
			seenSeparator = true
			index++
			continue
		}
		if ch == sep && isSurgeHeaderKeyStart(text, index+1) {
			seenSeparator = false
			index++
			continue
		}
		index++
	}
	return len(text)
}

func readSurgeHeadersEnd(text string, start int, sep byte) int {
	index := start
	for index < len(text) && isSurgeSpace(text[index]) {
		index++
	}
	if index < len(text) && (text[index] == '"' || text[index] == '\'') && !startsWithSurgeQuotedHeaderKey(text[index:]) {
		return readSurgeQuotedHeadersEnd(text, index, sep)
	}
	return readSurgeUnquotedHeadersEnd(text, index, sep)
}

// splitHeadersValue splits a headers value on pairSeparator, keeping quoted
// pairs intact (port of the Sub-Store splitHeaders helper).
func splitHeadersValue(s string, sep byte) []string {
	result := []string{}
	start := 0
	var quote byte
	quoteRole := 0
	seenSeparator := false
	for index := 0; index < len(s); index++ {
		ch := s[index]
		if quote != 0 {
			if ch == quote {
				if quoteRole == 1 || isSurgeHeaderValueQuoteEnd(s, index, sep, false, 0) {
					quote = 0
					quoteRole = 0
				}
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
			if seenSeparator {
				quoteRole = 2
			} else {
				quoteRole = 1
			}
			continue
		}
		if ch == ':' && !seenSeparator {
			seenSeparator = true
			continue
		}
		if ch == sep && isSurgeHeaderKeyStart(s, index+1) {
			result = append(result, s[start:index])
			start = index + 1
			seenSeparator = false
		}
	}
	result = append(result, s[start:])
	return result
}

// findSurgeHeaderSeparator returns the index of the first ':' outside quotes.
func findSurgeHeaderSeparator(pair string) int {
	var quote byte
	for index := 0; index < len(pair); index++ {
		ch := pair[index]
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
			continue
		}
		if ch == ':' {
			return index
		}
	}
	return -1
}

func stripSurgeOuterHeadersQuotes(s string) string {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) >= 2 && (trimmed[0] == '"' || trimmed[0] == '\'') &&
		trimmed[len(trimmed)-1] == trimmed[0] && !startsWithSurgeQuotedHeaderKey(trimmed) {
		return trimmed[1 : len(trimmed)-1]
	}
	return trimmed
}

// parseSurgeHeaders parses a headers string (pairSeparator ';' for headers,
// '|' for ws-headers) into a map, mirroring the Sub-Store parseHeaders
// helper.
func parseSurgeHeaders(s string, sep byte) map[string]string {
	result := map[string]string{}
	for _, pair := range splitHeadersValue(stripSurgeOuterHeadersQuotes(s), sep) {
		idx := findSurgeHeaderSeparator(pair)
		if idx == -1 {
			continue
		}
		key := TrimQuotes(strings.TrimSpace(pair[:idx]))
		value := TrimQuotes(strings.TrimSpace(pair[idx+1:]))
		if key != "" {
			result[key] = value
		}
	}
	return result
}
