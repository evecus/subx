package parser

import (
	"fmt"
	"strconv"
	"strings"

	"substore/internal/model"
)

func init() {
	MustRegister(
		&Parser{Name: "QX VMess Parser",
			Test: func(line string) bool {
				return strings.HasPrefix(line, "vmess://")
			},
			Parse: func(line string) (*model.Proxy, error) {
				return parseVMess(strings.TrimPrefix(line, "vmess://"))
			},
		},
	)
}

// qxTypes are the line types accepted by the Quantumult X line grammar
// (Sub-Store backend/src/core/proxy-utils/parsers/peggy/qx.js). The
// "hysteria2" entry is a subx extension kept so that lines produced by
// subx's QX producer can be parsed back; Sub-Store itself has no QX
// hysteria2 rule.
var qxTypes = map[string]bool{
	"shadowsocks": true,
	"vmess":       true,
	"vless":       true,
	"trojan":      true,
	"anytls":      true,
	"http":        true,
	"socks5":      true,
	"hysteria2":   true,
}

// qxCiphers is the cipher enumeration of the QX method rule; any other
// method value is dropped by the others rule.
var qxCiphers = map[string]bool{
	"aes-128-cfb": true, "aes-128-ctr": true, "aes-128-gcm": true,
	"aes-192-cfb": true, "aes-192-ctr": true, "aes-192-gcm": true,
	"aes-256-cfb": true, "aes-256-ctr": true, "aes-256-gcm": true,
	"bf-cfb": true, "cast5-cfb": true, "chacha20-ietf-poly1305": true,
	"chacha20-ietf": true, "chacha20-poly1305": true, "chacha20": true,
	"des-cfb": true, "none": true, "rc2-cfb": true, "rc4-md5-6": true,
	"rc4-md5": true, "salsa20": true, "xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
}

// qxSsrProtocols and qxSsrObfs are the strict enumerations of the QX
// ssr-protocol and ssr obfs rules.
var qxSsrProtocols = map[string]bool{
	"origin": true, "auth_sha1_v4": true, "auth_aes128_md5": true,
	"auth_aes128_sha1": true, "auth_chain_a": true, "auth_chain_b": true,
}

var qxSsrObfs = map[string]bool{
	"plain": true, "http_simple": true, "http_post": true,
	"random_head": true, "tls1.2_ticket_auth": true, "tls1.2_ticket_fastauth": true,
}

// qxHttpObfs are the http-obfs spellings accepted for ss/vmess/vless.
// The original token is preserved as "_qx_obfs_http" (including the
// upstream "vemss-http" typo) so the line can round-trip unchanged.
var qxHttpObfs = map[string]bool{
	"http": true, "vmess-http": true, "vemss-http": true, "shadowsocks-http": true,
}

type qxParamCtx struct {
	obfsType  string
	obfsHost  string
	obfsPath  string
	httpToken string
	ssr       bool
}

func parseQXLine(line string) (*model.Proxy, error) {
	eq := strings.Index(line, "=")
	if eq == -1 {
		return nil, fmt.Errorf("invalid qx line")
	}
	typ := strings.TrimSpace(line[:eq])
	fields := splitSurgeFields(line[eq+1:])
	if len(fields) == 0 {
		return nil, fmt.Errorf("invalid qx %s line", typ)
	}
	// mirror peggy/qx.js:191: the password reader swallows commas until the
	// next ",key=" parameter, so split segments without a "=" belong to the
	// preceding password value (only for the types using that rule)
	if qxPasswordCommaTypes[typ] {
		fields = mergeQXPasswordCommaFields(fields)
	}
	server, port, ok := parseQXAddress(strings.TrimSpace(fields[0]))
	if !ok {
		return nil, fmt.Errorf("invalid qx %s address: %s", typ, fields[0])
	}
	p := model.NewProxy()
	p.Set("server", server)
	p.Set("port", port)
	ctx := &qxParamCtx{}
	for _, f := range fields[1:] {
		f = strings.TrimSpace(f)
		idx := strings.Index(f, "=")
		if idx == -1 {
			// not a key=value option; dropped like the QX others rule
			continue
		}
		// mirrors `equals = _ "=" _`: whitespace right after "=" is
		// consumed by the grammar; the value is passed along un-trimmed so
		// the tag rule (tag.join(""), peggy/qx.js:272) keeps it verbatim
		val := strings.TrimLeft(f[idx+1:], " \t\r")
		if err := applyQXOption(p, strings.TrimSpace(f[:idx]), val, typ, ctx); err != nil {
			return nil, err
		}
	}
	switch typ {
	case "shadowsocks":
		if p.Has("protocol") || ctx.ssr {
			p.Set("type", "ssr")
			if !p.Has("protocol") {
				p.Set("protocol", "origin")
			}
			if ctx.obfsHost != "" {
				p.Set("obfs-param", ctx.obfsHost)
			}
			if ctx.obfsType != "" {
				p.Set("obfs", ctx.obfsType)
			}
		} else {
			p.Set("type", "ss")
			applyQXSSObfs(p, ctx)
		}
	case "vmess", "vless":
		p.Set("type", typ)
		if !p.Has("cipher") {
			p.Set("cipher", "none")
		}
		if typ == "vmess" {
			// QX defaults to alterId 0 and only switches to 1 on an
			// explicit aead=false (the inverse of Surge's handling)
			if p.Has("aead") && !p.GetBool("aead") {
				p.Set("alterId", 1)
			} else {
				p.Set("alterId", 0)
			}
		}
		applyQXHandleObfs(p, ctx)
	case "trojan":
		p.Set("type", "trojan")
		applyQXHandleObfs(p, ctx)
	case "anytls":
		p.Set("type", "anytls")
		p.Set("tls", true)
	case "http":
		p.Set("type", "http")
	case "socks5":
		p.Set("type", "socks5")
	case "hysteria2":
		p.Set("type", "hysteria2")
	}
	if ctx.httpToken != "" {
		p.Set("_qx_obfs_http", ctx.httpToken)
	}
	return p, nil
}

// parseQXAddress mirrors the QX address rule: "server:port" where the port
// is the last colon-separated token and must be digits in 0..65535.
func parseQXAddress(field string) (string, int, bool) {
	idx := strings.LastIndex(field, ":")
	if idx <= 0 || idx == len(field)-1 {
		return "", 0, false
	}
	for i := idx + 1; i < len(field); i++ {
		if field[i] < '0' || field[i] > '9' {
			return "", 0, false
		}
	}
	port, err := strconv.Atoi(field[idx+1:])
	if err != nil || port > 65535 {
		return "", 0, false
	}
	return field[:idx], port, true
}

func applyQXOption(p *model.Proxy, key, val, typ string, ctx *qxParamCtx) error {
	// the tag rule is the only one reading its value without trimming
	// (peggy/qx.js:272 `proxy.name = tag.join("")`)
	if key != "tag" {
		val = strings.TrimSpace(val)
	}
	switch key {
	case "method":
		if (typ == "shadowsocks" || typ == "vmess" || typ == "vless") && qxCiphers[val] {
			p.Set("cipher", val)
		}
	case "password":
		if typ == "vmess" || typ == "vless" {
			p.Set("uuid", val)
		} else {
			p.Set("password", val)
		}
	case "username":
		if typ == "http" || typ == "socks5" {
			p.Set("username", val)
		}
	case "over-tls":
		if b, ok := parseQXBool(key, val); ok {
			p.Set("tls", b)
		}
	case "tls-host":
		p.Set("sni", stripQXQuotes(val))
	case "tls-verification":
		v := strings.TrimSpace(val)
		if v == "true" || v == "false" {
			p.Set("skip-cert-verify", v != "true")
		} else {
			p.Set("name-cert-verify", v)
		}
	case "tls-cert-sha256":
		p.Set("tls-fingerprint", strings.TrimSpace(val))
	case "tls-pubkey-sha256":
		p.Set("tls-pubkey-sha256", val)
	case "tls-alpn":
		p.Set("tls-alpn", val)
	case "tls-no-session-ticket":
		if b, ok := parseQXBool(key, val); ok {
			p.Set("tls-no-session-ticket", b)
		}
	case "tls-no-session-reuse":
		if b, ok := parseQXBool(key, val); ok {
			p.Set("tls-no-session-reuse", b)
		}
	case "aead":
		if typ == "vmess" || typ == "vless" {
			if b, ok := parseQXBool(key, val); ok {
				p.Set("aead", b)
			}
		}
	case "udp-relay":
		if b, ok := parseQXBool(key, val); ok {
			p.Set("udp", b)
		}
	case "udp-over-tcp":
		if typ != "shadowsocks" {
			return fmt.Errorf("qx udp-over-tcp is not supported")
		}
		switch val {
		case "sp.v1":
			p.Set("udp-over-tcp", true)
			p.Set("udp-over-tcp-version", 1)
		case "sp.v2":
			p.Set("udp-over-tcp", true)
			p.Set("udp-over-tcp-version", 2)
		case "true":
			p.Set("_ssr_python_uot", true)
		default:
			return fmt.Errorf("qx udp-over-tcp has an invalid value: %s", val)
		}
	case "fast-open":
		if b, ok := parseQXBool(key, val); ok {
			p.Set("tfo", b)
		}
	case "server_check_url":
		p.Set("test-url", val)
	case "reality-base64-pubkey":
		EnsureOpts(p, "reality-opts")["public-key"] = val
	case "reality-hex-shortid":
		EnsureOpts(p, "reality-opts")["short-id"] = val
	case "vless-flow":
		if typ == "vless" {
			p.Set("flow", val)
		}
	case "ssr-protocol":
		if typ == "shadowsocks" && qxSsrProtocols[val] {
			p.Set("protocol", val)
		}
	case "ssr-protocol-param":
		if typ == "shadowsocks" {
			p.Set("protocol-param", val)
		}
	case "obfs":
		applyQXObfs(typ, val, ctx)
	case "obfs-host":
		ctx.obfsHost = stripQXQuotes(val)
	case "obfs-uri":
		ctx.obfsPath = val
	case "tag":
		p.Set("name", val)
	}
	return nil
}

// applyQXObfs mirrors the per-type obfs rules of the QX grammar.
func applyQXObfs(typ, val string, ctx *qxParamCtx) {
	switch typ {
	case "shadowsocks":
		if qxSsrObfs[val] {
			ctx.ssr = true
			ctx.obfsType = val
		} else if val == "tls" || val == "wss" || val == "ws" || val == "over-tls" {
			ctx.obfsType = val
		} else if qxHttpObfs[val] {
			ctx.httpToken = val
			ctx.obfsType = "http"
		}
	case "vmess", "vless":
		if val == "wss" || val == "ws" || val == "over-tls" {
			ctx.obfsType = val
		} else if qxHttpObfs[val] {
			ctx.httpToken = val
			ctx.obfsType = "http"
		}
	case "trojan":
		if val == "wss" || val == "ws" || val == "over-tls" || val == "http" {
			ctx.obfsType = val
		}
	}
}

// applyQXSSObfs mirrors the shadowsocks obfs branch of the QX grammar.
func applyQXSSObfs(p *model.Proxy, ctx *qxParamCtx) {
	obfs := ctx.obfsType
	switch obfs {
	case "http", "tls":
		p.Set("plugin", "obfs")
		EnsureOpts(p, "plugin-opts")["mode"] = obfs
	case "ws", "wss":
		p.Set("plugin", "v2ray-plugin")
		opts := EnsureOpts(p, "plugin-opts")
		opts["mode"] = "websocket"
		if obfs == "wss" {
			opts["tls"] = true
		}
	case "over-tls":
		p.Set("tls", true)
		if ctx.obfsHost != "" {
			p.Set("sni", ctx.obfsHost)
		}
	default:
		return
	}
	if obfs != "over-tls" {
		opts := EnsureOpts(p, "plugin-opts")
		if ctx.obfsHost != "" {
			opts["host"] = ctx.obfsHost
		}
		if ctx.obfsPath != "" {
			opts["path"] = ctx.obfsPath
		}
	}
}

// applyQXHandleObfs mirrors the handleObfs() helper of the QX grammar for
// vmess/vless/trojan nodes. http-opts stay as plain strings here; the
// vmess/vless array conversion happens in normalizeProxy like Sub-Store's
// lastParse().
func applyQXHandleObfs(p *model.Proxy, ctx *qxParamCtx) {
	switch ctx.obfsType {
	case "ws", "wss":
		p.Set("network", "ws")
		if ctx.obfsType == "wss" {
			p.Set("tls", true)
		}
		opts := EnsureOpts(p, "ws-opts")
		if ctx.obfsPath != "" {
			opts["path"] = ctx.obfsPath
		}
		if ctx.obfsHost != "" {
			opts["headers"] = map[string]any{"Host": ctx.obfsHost}
		}
	case "over-tls":
		p.Set("tls", true)
		// obfs-host doubles as the TLS server name but never overrides an
		// explicit tls-host
		if ctx.obfsHost != "" && !p.Has("sni") {
			p.Set("sni", ctx.obfsHost)
		}
	case "http":
		p.Set("network", "http")
		opts := EnsureOpts(p, "http-opts")
		if ctx.obfsPath != "" {
			opts["path"] = ctx.obfsPath
		}
		if ctx.obfsHost != "" {
			opts["headers"] = map[string]any{"Host": ctx.obfsHost}
		}
	}
}

// parseQXBool mirrors the strict true/false bool rule of the QX grammar.
func parseQXBool(key, val string) (bool, bool) {
	switch val {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// stripQXQuotes mirrors the /^"(.*)"$/ replacement of the QX obfs-host and
// tls-host rules: only a fully double-quoted value is unquoted.
func stripQXQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// qxPasswordCommaTypes lists the QX line types whose "password" rule uses
// the peggy `$((!next_parameter .)+)` reader, which swallows commas until
// the next ",key=" parameter boundary (peggy/qx.js:190-193). vmess/vless
// map "password" onto the uuid rule ([^,]+) and must not merge.
var qxPasswordCommaTypes = map[string]bool{
	"trojan": true, "shadowsocks": true, "anytls": true,
	"http": true, "socks5": true,
}

// isQXNextParameter mirrors the peggy next_parameter lookahead
// ("," _ [^=,]+ equals): a comma-separated segment starts a new parameter
// only when a non-empty key precedes its "=".
func isQXNextParameter(field string) bool {
	return strings.Index(field, "=") > 0
}

// mergeQXPasswordCommaFields re-joins the split segments that belong to a
// password value, mirroring the peggy lookahead behavior.
func mergeQXPasswordCommaFields(fields []string) []string {
	out := make([]string, 0, len(fields))
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if i == 0 || !strings.HasPrefix(strings.TrimSpace(f), "password=") {
			out = append(out, f)
			continue
		}
		j := i + 1
		for j < len(fields) && !isQXNextParameter(strings.TrimSpace(fields[j])) {
			f = f + "," + strings.TrimSpace(fields[j])
			j++
		}
		out = append(out, f)
		i = j - 1
	}
	return out
}
