package producer

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"substore/internal/model"
)

// ProduceJSON outputs each proxy as a JSON line.
func ProduceJSON(proxies []*model.Proxy, _ map[string]any) (string, error) {
	lines := make([]string, 0, len(proxies))
	for _, p := range proxies {
		b, err := jsonMarshalNoEscape(p.Data())
		if err != nil {
			return "", err
		}
		lines = append(lines, string(b))
	}
	return strings.Join(lines, "\n"), nil
}

// ProduceURI outputs each proxy in its URI format, one per line.
func ProduceURI(proxies []*model.Proxy, _ map[string]any) (string, error) {
	lines := make([]string, 0, len(proxies))
	for _, p := range proxies {
		if uri := ToURI(p); uri != "" {
			lines = append(lines, uri)
		}
	}
	return strings.Join(lines, "\n"), nil
}

// ProduceURIBase64 outputs the whole URI list base64-encoded as a single
// block — the "通用订阅" format used by v2rayN-style subscription clients
// (whole subscription content encoded in one base64 blob).
func ProduceURIBase64(proxies []*model.Proxy, opts map[string]any) (string, error) {
	plain, err := ProduceURI(proxies, opts)
	if err != nil {
		return "", err
	}
	return base64StdEncode([]byte(plain)), nil
}

// ToURI converts a proxy to its URI representation, mirroring uri.js
// URI_Producer: the proxy is mutated (on a clone) by deleting bookkeeping
// fields, dropping tls for QUIC-based types and bracketing IPv6 servers.
func ToURI(p *model.Proxy) string {
	c := p.Clone()
	c.Delete("subName")
	c.Delete("collectionName")
	c.Delete("id")
	c.Delete("resolved")
	c.Delete("no-resolve")
	for k, v := range c.Fields() {
		if v == nil {
			c.Delete(k)
		}
	}
	switch c.Type() {
	case "tuic", "hysteria", "hysteria2", "juicity", "trusttunnel":
		c.Delete("tls")
	}
	if c.Type() != "vmess" && c.Server() != "" && isIPv6(c.Server()) {
		c.Set("server", "["+c.Server()+"]")
	}
	switch c.Type() {
	case "socks5":
		return socksURI(c)
	case "ss":
		return ssURI(c)
	case "ssr":
		return ssrURI(c)
	case "vmess":
		return vmessURI(c)
	case "vless":
		return vlessURI(c)
	case "trojan":
		return trojanURI(c)
	case "hysteria2":
		return hysteria2URI(c)
	case "hysteria":
		return hysteriaURI(c)
	case "tuic":
		return tuicURI(c)
	case "anytls":
		return anytlsURI(c)
	case "wireguard":
		return wireguardURI(c)
	default:
		return ""
	}
}

func isIPv6(s string) bool {
	if !strings.Contains(s, ":") {
		return false
	}
	return net.ParseIP(strings.Trim(s, "[]")) != nil
}

// hostPort renders "server:port", wrapping IPv6 addresses in brackets, the
// same way Sub-Store does before producing any URI.
func hostPort(p *model.Proxy) string {
	host := p.Server()
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		if net.ParseIP(strings.Trim(host, "[]")) != nil {
			host = "[" + host + "]"
		}
	}
	return host + ":" + fmt.Sprint(p.Port())
}

// str converts a raw map value to its string form.
func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		// JS template strings render numbers via ToString (e.g. 1e6 -> "1000000");
		// fmt.Sprint would emit "1e+06".
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return fmt.Sprint(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

// hostFromOpts extracts the Host header from transport opts that carry
// either a headers.Host map entry or a top-level host field (h2 style).
func hostFromOpts(opts map[string]any) string {
	if opts == nil {
		return ""
	}
	if headers, ok := opts["headers"].(map[string]any); ok {
		for k, v := range headers {
			if strings.EqualFold(k, "Host") {
				return str(v)
			}
		}
	}
	return str(opts["host"])
}

func b64Std(s string) string {
	return base64StdEncode([]byte(s))
}

// gstr resolves a dotted path like "ws-opts.headers.Host" to its string form.
func gstr(p *model.Proxy, path string) string {
	return str(getNested(p, path))
}

// gbool mirrors JS truthiness for a dotted path.
func gbool(p *model.Proxy, path string) bool {
	return isTruthy(getNested(p, path))
}

// joinAlpn mirrors the JS "Array.isArray(alpn) ? alpn.join(',') : alpn"
// idiom used across uri.js.
func joinAlpn(v any) string {
	if arr, ok := v.([]any); ok {
		return joinAny(arr, ",")
	}
	if arr, ok := v.([]string); ok {
		return strings.Join(arr, ",")
	}
	return str(v)
}

// joinFirst mirrors the JS "Array.isArray(v) ? v[0] : v" idiom.
func joinFirst(v any) string {
	if arr, ok := v.([]any); ok {
		if len(arr) > 0 {
			return str(arr[0])
		}
		return ""
	}
	if arr, ok := v.([]string); ok {
		if len(arr) > 0 {
			return arr[0]
		}
		return ""
	}
	return str(v)
}

// socksURI mirrors uri.js: socks5://base64(user:pass)@server:port#name.
func socksURI(p *model.Proxy) string {
	return "socks://" + encodeURIComponent(b64Std(p.GetString("username")+":"+p.GetString("password"))) +
		"@" + p.Server() + ":" + fmt.Sprint(p.Port()) + "#" + p.GetString("name")
}

// ssURI mirrors uri.js: 2022-blake3 ciphers stay plain text, plugin is
// expanded per plugin type, network/transport params follow.
func ssURI(p *model.Proxy) string {
	userinfo := p.GetString("cipher") + ":" + p.GetString("password")
	u := "ss://"
	if strings.HasPrefix(p.GetString("cipher"), "2022-blake3-") {
		u += encodeURIComponent(p.GetString("cipher")) + ":" + encodeURIComponent(p.GetString("password"))
	} else {
		u += b64Std(userinfo)
	}
	u += "@" + p.Server() + ":" + fmt.Sprint(p.Port())
	if p.GetString("plugin") != "" {
		u += "/"
	}
	query := ""
	if plugin := p.GetString("plugin"); plugin != "" {
		query += "&plugin="
		opts := p.GetMap("plugin-opts")
		switch plugin {
		case "obfs":
			query += encodeURIComponent("simple-obfs;obfs=" + str(opts["mode"]) + withOptHost(opts, ";obfs-host="))
		case "v2ray-plugin":
			mux := normalizePluginMuxValue(opts["mux"])
			var sb strings.Builder
			sb.WriteString("v2ray-plugin;obfs=" + str(opts["mode"]) + ";mode=" + str(opts["mode"]))
			if h := str(opts["host"]); h != "" {
				sb.WriteString(";obfs-host=" + h)
			}
			if h := str(opts["host"]); h != "" {
				sb.WriteString(";host=" + h)
			}
			if path := str(opts["path"]); path != "" {
				sb.WriteString(";path=" + path)
			}
			if tls, _ := opts["tls"].(bool); tls {
				sb.WriteString(";tls")
			}
			if sni := str(opts["sni"]); sni != "" {
				sb.WriteString(";sni=" + sni)
			}
			if scv, _ := opts["skip-cert-verify"].(bool); scv {
				sb.WriteString(";skip-cert-verify=" + str(opts["skip-cert-verify"]))
			}
			if mux != nil {
				sb.WriteString(";mux=" + str(mux))
			}
			query += encodeURIComponent(sb.String())
		case "shadow-tls":
			query += encodeURIComponent("shadow-tls;host=" + str(opts["host"]) + ";password=" + str(opts["password"]) + ";version=" + str(opts["version"]))
		default:
			return ""
		}
	}
	if p.GetBool("udp-over-tcp") {
		query += "&uot=1"
	}
	if p.GetBool("tfo") {
		query += "&tfo=1"
	}
	ssTransport := ssTransportParams(p)
	if fp := p.GetString("client-fingerprint"); fp != "" {
		ssTransport += "&fp=" + encodeURIComponent(fp)
	}
	ssAlpn := ""
	if alpn := p.Get("alpn"); alpn != nil {
		ssAlpn = "&alpn=" + encodeURIComponent(joinAlpn(alpn))
	}
	ssSecurity := ""
	ssSid := ""
	ssPbk := ""
	ssSpx := ""
	ssMode := ""
	ssExtra := ""
	if reality := p.GetMap("reality-opts"); reality != nil {
		ssSecurity = "&security=reality"
		if pk := str(reality["public-key"]); pk != "" {
			ssPbk = "&pbk=" + encodeURIComponent(pk)
		}
		if sid := str(reality["short-id"]); sid != "" {
			ssSid = "&sid=" + encodeURIComponent(sid)
		}
		if spx := str(reality["_spider-x"]); spx != "" {
			ssSpx = "&spx=" + encodeURIComponent(spx)
		}
		if extra := p.GetString("_extra"); extra != "" {
			ssExtra = "&extra=" + encodeURIComponent(extra)
		}
		if mode := p.GetString("_mode"); mode != "" {
			ssMode = "&mode=" + encodeURIComponent(mode)
		}
	} else if p.GetBool("tls") {
		ssSecurity = "&security=tls"
	}
	if p.GetBool("tls") {
		sni := p.GetString("sni")
		if sni == "" {
			sni = p.Server()
		}
		query += "&sni=" + encodeURIComponent(sni)
		if p.GetBool("skip-cert-verify") {
			query += "&allowInsecure=1"
		}
	}
	query += ssTransport + ssAlpn + ssSecurity + ssSid + ssPbk + ssSpx + ssMode + ssExtra +
		"#" + encodeURIComponent(p.GetString("name"))
	return u + strings.Replace(query, "&", "?", 1)
}

func withOptHost(opts map[string]any, prefix string) string {
	if h := str(opts["host"]); h != "" {
		return prefix + h
	}
	return ""
}

// pluginOptsString expands a stored plugin-opts map into the same string
// Sub-Store emits for ss:// links (also used by Surge/Surfboard plugin-opts).
func pluginOptsString(p *model.Proxy) string {
	plugin := p.GetString("plugin")
	opts := p.GetMap("plugin-opts")
	if opts == nil {
		return plugin
	}
	switch plugin {
	case "obfs":
		s := "simple-obfs;obfs=" + str(opts["mode"])
		if h := str(opts["host"]); h != "" {
			s += ";obfs-host=" + h
		}
		return s
	case "simple-obfs":
		s := "simple-obfs;obfs=" + str(opts["mode"])
		if h := str(opts["host"]); h != "" {
			s += ";obfs-host=" + h
		}
		return s
	case "v2ray-plugin":
		mode := str(opts["mode"])
		s := "v2ray-plugin;obfs=" + mode + ";mode=" + mode
		if h := str(opts["host"]); h != "" {
			s += ";obfs-host=" + h + ";host=" + h
		}
		if path := str(opts["path"]); path != "" {
			s += ";path=" + path
		}
		if b, _ := opts["tls"].(bool); b {
			s += ";tls"
		}
		if sni := str(opts["sni"]); sni != "" {
			s += ";sni=" + sni
		}
		if b, _ := opts["skip-cert-verify"].(bool); b {
			s += ";skip-cert-verify=" + str(opts["skip-cert-verify"])
		}
		if mux := normalizePluginMuxValue(opts["mux"]); mux != nil {
			s += ";mux=" + str(mux)
		}
		return s
	case "shadow-tls":
		return "shadow-tls;host=" + str(opts["host"]) + ";password=" + str(opts["password"]) +
			";version=" + str(opts["version"])
	default:
		return plugin
	}
}

// ssTransportParams mirrors the ss transport block in uri.js: type param,
// grpc serviceName/authority/mode, path/host with early-data handling.
func ssTransportParams(p *model.Proxy) string {
	network := p.GetString("network")
	if network == "" {
		return ""
	}
	ssType := network
	if network == "ws" {
		if wsOpts := p.GetMap("ws-opts"); wsOpts != nil {
			if v, _ := wsOpts["v2ray-http-upgrade"].(bool); v {
				ssType = "httpupgrade"
			}
		}
	}
	transport := "&type=" + encodeURIComponent(ssType)
	if network == "grpc" {
		if sn := gstr(p, "grpc-opts.grpc-service-name"); sn != "" {
			transport += "&serviceName=" + encodeURIComponent(sn)
		}
		if auth := gstr(p, "grpc-opts._grpc-authority"); auth != "" {
			transport += "&authority=" + encodeURIComponent(auth)
		}
		mode := gstr(p, "grpc-opts._grpc-type")
		if mode == "" {
			mode = "gun"
		}
		transport += "&mode=" + encodeURIComponent(mode)
	}
	opts := p.GetMap(network + "-opts")
	isUpgrade := network == "ws" && gbool(p, "ws-opts.v2ray-http-upgrade")
	path := joinFirst(opts["path"])
	if isUpgrade {
		path = setHttpUpgradeEarlyDataPath(path, opts)
	} else if network == "ws" {
		path = setWebSocketEarlyDataPath(path, opts)
	}
	if path != "" {
		transport += "&path=" + encodeURIComponent(path)
	}
	host := ""
	if opts != nil {
		if headers, ok := opts["headers"].(map[string]any); ok {
			if hh, ok := headers["Host"]; ok {
				host = joinFirst(hh)
			}
		}
	}
	if host != "" {
		transport += "&host=" + encodeURIComponent(host)
	}
	return transport
}

func ssrURI(p *model.Proxy) string {
	payload := fmt.Sprintf("%s:%d:%s:%s:%s:%s/?remarks=%s",
		p.Server(), p.Port(),
		p.GetString("protocol"), p.GetString("cipher"),
		p.GetString("obfs"), b64Std(p.GetString("password")),
		b64Std(p.GetString("name")))
	if op := p.GetString("obfs-param"); op != "" {
		payload += "&obfsparam=" + b64Std(op)
	}
	if pp := p.GetString("protocol-param"); pp != "" {
		payload += "&protoparam=" + b64Std(pp)
	}
	return "ssr://" + b64Std(payload)
}

// vmessURI produces a v2rayN-style vmess:// link, mirroring uri.js: the
// JSON body carries v/ps/add/port/id/aid/scy/net/type/tls/alpn/fp plus
// transport path/host and reality/ECH fields.
func vmessURI(p *model.Proxy) string {
	netw := p.GetString("network")
	if netw == "" {
		netw = "tcp"
	}
	typ := ""
	if p.GetString("network") == "http" {
		netw = "tcp"
		typ = "http"
	} else if p.GetString("network") == "ws" && gbool(p, "ws-opts.v2ray-http-upgrade") {
		netw = "httpupgrade"
	}
	obj := map[string]any{}
	if p.GetString("network") != "" {
		transportOpts := p.GetMap(p.GetString("network") + "-opts")
		isUpgrade := p.GetString("network") == "ws" && gbool(p, "ws-opts.v2ray-http-upgrade")
		switch p.GetString("network") {
		case "grpc":
			// uri.js:1067-1077 assigns these unconditionally; undefined values
			// are dropped by JSON.stringify, so omit empty ones here.
			if v := gstr(p, "grpc-opts.grpc-service-name"); v != "" {
				obj["path"] = v
			}
			mode := gstr(p, "grpc-opts._grpc-type")
			if mode == "" {
				mode = "gun"
			}
			obj["type"] = mode
			if v := gstr(p, "grpc-opts._grpc-authority"); v != "" {
				obj["host"] = v
			}
		case "kcp", "quic":
			obj["type"] = gstr(p, p.GetString("network")+"-opts._"+p.GetString("network")+"-type")
			if obj["type"] == "" {
				obj["type"] = "none"
			}
			if v := gstr(p, p.GetString("network")+"-opts._"+p.GetString("network")+"-host"); v != "" {
				obj["host"] = v
			}
			if v := gstr(p, p.GetString("network")+"-opts._"+p.GetString("network")+"-path"); v != "" {
				obj["path"] = v
			}
		default:
			path := joinFirst(transportOpts["path"])
			if isUpgrade {
				path = setHttpUpgradeEarlyDataPath(path, transportOpts)
			} else if p.GetString("network") == "ws" {
				path = setWebSocketEarlyDataPath(path, transportOpts)
			}
			if path != "" {
				obj["path"] = path
			}
			if h := joinFirst(getTransportHost(p.GetString("network"), transportOpts)); h != "" {
				obj["host"] = h
			}
		}
	}
	obj["v"] = "2"
	obj["ps"] = p.GetString("name")
	obj["add"] = p.Server()
	obj["port"] = fmt.Sprint(p.Port())
	obj["id"] = p.GetString("uuid")
	obj["aid"] = fmt.Sprint(p.GetInt("alterId"))
	obj["scy"] = vmessSecurityCommon(p.GetString("cipher"))
	obj["net"] = netw
	// mirror uri.js: the transport branches above set obj["type"] for
	// grpc/kcp/quic; only fill the fallback (http/tcp) when unset.
	if _, exists := obj["type"]; !exists {
		obj["type"] = typ
	}
	obj["tls"] = ""
	if p.GetBool("tls") {
		obj["tls"] = "tls"
		if sni := p.GetString("sni"); sni != "" {
			obj["sni"] = sni
		}
	}
	if alpn := p.Get("alpn"); alpn != nil {
		obj["alpn"] = joinAlpn(alpn)
	}
	if fp := p.GetString("client-fingerprint"); fp != "" {
		obj["fp"] = fp
	}
	if reality := p.GetMap("reality-opts"); reality != nil {
		if pk := str(reality["public-key"]); pk != "" {
			obj["pbk"] = pk
		}
		if sid := str(reality["short-id"]); sid != "" {
			obj["sid"] = sid
		}
		if spx := str(reality["spider-x"]); spx != "" {
			obj["spx"] = spx
		}
	}
	if ech := p.GetMap("ech-opts"); ech != nil {
		if v := buildXrayEchFieldsFromMihomo(ech, ""); v["echConfigList"] != nil {
			obj["echConfigList"] = v["echConfigList"]
		}
	}
	b, _ := jsonMarshalNoEscape(obj)
	return "vmess://" + b64Std(string(b))
}

func joinAny(arr []any, sep string) string {
	parts := make([]string, 0, len(arr))
	for _, v := range arr {
		parts = append(parts, str(v))
	}
	return strings.Join(parts, sep)
}

// vlessURI mirrors the vless() producer in uri.js, including structured
// xhttp "extra" and early-data handling.
func vlessURI(p *model.Proxy) string {
	security := "none"
	reality := p.GetMap("reality-opts")
	if reality != nil {
		security = "reality"
	} else if p.GetBool("tls") {
		security = "tls"
	}

	var sb strings.Builder
	write := func(s string) {
		if s != "" {
			sb.WriteString(s)
		}
	}
	sb.WriteString("?security=" + encodeURIComponent(security))

	network := p.GetString("network")
	if network == "" {
		network = "tcp"
	}
	vlessType := network
	if network == "ws" {
		if v, _ := p.GetMap("ws-opts")["v2ray-http-upgrade"].(bool); v {
			vlessType = "httpupgrade"
		}
	} else if network == "http" {
		vlessType = "tcp"
	} else if network == "h2" {
		vlessType = "http"
	}
	write("&type=" + encodeURIComponent(vlessType))
	if network == "http" {
		write("&headerType=http")
	}
	if network == "grpc" {
		mode := gstr(p, "grpc-opts._grpc-type")
		if mode == "" {
			mode = "gun"
		}
		write("&mode=" + encodeURIComponent(mode))
		if auth := gstr(p, "grpc-opts._grpc-authority"); auth != "" {
			write("&authority=" + encodeURIComponent(auth))
		}
	}
	transportOpts := p.GetMap(network + "-opts")
	isVlessHttpUpgrade := network == "ws" && gbool(p, "ws-opts.v2ray-http-upgrade")
	serviceName := gstr(p, network+"-opts."+network+"-service-name")
	path := joinFirst(transportOpts["path"])
	host := getTransportHost(network, transportOpts)
	vlessWsEarlyData := getSafeEarlyDataValue(p.GetMap("ws-opts")["max-early-data"])
	if isVlessHttpUpgrade && gbool(p, "ws-opts.v2ray-http-upgrade-fast-open") {
		path = setHttpUpgradeEarlyDataPath(path, transportOpts)
	} else if network == "ws" && p.GetMap("ws-opts")["max-early-data"] != nil && path != "" {
		path, _ = extractPathQueryParam(path, "ed")
	}
	if path != "" {
		write("&path=" + encodeURIComponent(path))
	}
	if host != "" {
		write("&host=" + encodeURIComponent(joinFirst(host)))
	}
	if serviceName != "" {
		write("&serviceName=" + encodeURIComponent(serviceName))
	}
	if network == "http" {
		if m := gstr(p, "http-opts.method"); m != "" {
			write("&method=" + encodeURIComponent(m))
		}
	}
	if network == "kcp" {
		if seed := p.GetString("seed"); seed != "" {
			write("&seed=" + encodeURIComponent(seed))
		}
		if ht := p.GetString("headerType"); ht != "" {
			write("&headerType=" + encodeURIComponent(ht))
		}
	}
	if network == "ws" && !isVlessHttpUpgrade && vlessWsEarlyData != "" {
		write("&ed=" + encodeURIComponent(vlessWsEarlyData))
	}
	earlyDataHeaderName := gstr(p, "ws-opts.early-data-header-name")
	if earlyDataHeaderName != "" &&
		(isVlessHttpUpgrade || p.GetMap("ws-opts")["max-early-data"] == nil || earlyDataHeaderName != "Sec-WebSocket-Protocol") {
		write("&eh=" + encodeURIComponent(earlyDataHeaderName))
	}

	write(packetEncodingParam(p))
	if alpn := p.Get("alpn"); alpn != nil {
		write("&alpn=" + encodeURIComponent(joinAlpn(alpn)))
	}
	if p.GetBool("skip-cert-verify") {
		write("&allowInsecure=1")
	}
	if fp := p.GetString("tls-fingerprint"); fp != "" {
		write("&pcs=" + encodeURIComponent(fp))
	}
	// uri.js:599-605: certNames = Array.isArray(_vcn) ? _vcn.join(',') : name-cert-verify
	certNames := ""
	vcnIsArray := false
	if v := p.Get("_vcn"); v != nil {
		if arr, ok := v.([]any); ok {
			certNames = joinAny(arr, ",")
			vcnIsArray = true
		}
	}
	if !vcnIsArray {
		certNames = p.GetString("name-cert-verify")
	}
	if vcnIsArray || certNames != "" {
		write("&vcn=" + encodeURIComponent(certNames))
	}
	echConfigList := buildXrayEchConfigListFromMihomo(p.GetMap("ech-opts"), p.GetString("_echConfigList"))
	if echConfigList != "" {
		write("&ech=" + encodeURIComponent(echConfigList))
	}
	if p.GetBool("_h2") {
		write("&h2=1")
	}
	if sni := p.GetString("sni"); sni != "" {
		write("&sni=" + encodeURIComponent(sni))
	}
	if fp := p.GetString("client-fingerprint"); fp != "" {
		write("&fp=" + encodeURIComponent(fp))
	}
	if flow := p.GetString("flow"); flow != "" {
		write("&flow=" + encodeURIComponent(flow))
	}
	if reality != nil {
		if sid := str(reality["short-id"]); sid != "" {
			write("&sid=" + encodeURIComponent(sid))
		}
		if spx := str(reality["_spider-x"]); spx != "" {
			write("&spx=" + encodeURIComponent(spx))
		}
		if pk := str(reality["public-key"]); pk != "" {
			write("&pbk=" + encodeURIComponent(pk))
		}
	}
	if network == "xhttp" {
		if m := gstr(p, "xhttp-opts.mode"); m != "" {
			write("&mode=" + encodeURIComponent(m))
		}
	} else if m := p.GetString("_mode"); m != "" {
		write("&mode=" + encodeURIComponent(m))
	}
	extra := buildVlessExtra(p)
	if extra != "" {
		write("&extra=" + encodeURIComponent(extra))
	}
	if pqv := p.GetString("_pqv"); pqv != "" {
		write("&pqv=" + encodeURIComponent(pqv))
	}
	if enc := p.GetString("encryption"); enc != "" {
		write("&encryption=" + encodeURIComponent(enc))
	}

	result := "vless://" + p.GetString("uuid") + "@" + p.Server() + ":" + fmt.Sprint(p.Port()) +
		sb.String() + "#" + encodeURIComponent(p.GetString("name"))
	return result
}

// packetEncodingParam mirrors uri.js: packet-encoding (normalized),
// xudp/packet-addr/udp fallbacks, then the canonical mapping.
func packetEncodingParam(p *model.Proxy) string {
	canonical, hasCanonical := "", false
	if pe := p.Get("packet-encoding"); pe != nil {
		canonical = strings.ToLower(strings.TrimSpace(str(pe)))
		hasCanonical = true
	} else if p.GetBool("xudp") {
		canonical, hasCanonical = "xudp", true
	} else if p.GetBool("packet-addr") {
		canonical, hasCanonical = "packetaddr", true
	} else if udp, ok := p.Get("udp").(bool); ok && udp {
		canonical, hasCanonical = "", true
	}
	if !hasCanonical {
		return ""
	}
	switch canonical {
	case "":
		return "&packetEncoding=none"
	case "packetaddr":
		return "&packetEncoding=packet"
	case "xudp":
		return "&packetEncoding=xudp"
	default:
		return ""
	}
}

// buildVlessExtra mirrors uri.js buildVlessExtra: explicit _extra override,
// structured xhttp extra for xhttp networks, otherwise the raw _extra.
func buildVlessExtra(p *model.Proxy) string {
	if extra := p.Get("_extra"); extra != nil {
		if s, ok := extra.(string); ok {
			return s
		}
		if m, ok := extra.(map[string]any); ok {
			b, _ := jsonMarshalNoEscape(m)
			return string(b)
		}
	}
	if p.GetString("network") != "xhttp" {
		return str(p.Get("_extra"))
	}
	structured := buildStructuredVlessExtraObject(p)
	merged := mergeUnsupportedXhttpExtraObject(structured, getMapAny(p.Get("_extra_unsupported")))
	if len(merged) == 0 {
		return ""
	}
	b, _ := jsonMarshalNoEscape(merged)
	return string(b)
}

func getMapAny(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

// buildStructuredVlessExtraObject mirrors uri.js: xhttp extra fields plus
// download-settings.
func buildStructuredVlessExtraObject(p *model.Proxy) map[string]any {
	xhttpOpts := p.GetMap("xhttp-opts")
	extra := map[string]any{}
	applyStructuredXhttpExtraFields(extra, xhttpOpts, false, "root")
	if ds := buildXhttpDownloadSettings(getMapAny(xhttpOpts["download-settings"]), xhttpOpts, p); ds != nil {
		extra["downloadSettings"] = ds
	}
	return extra
}

func toStringHeaderMap(headers map[string]any, excludeHost bool) map[string]any {
	if headers == nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range headers {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if excludeHost && strings.EqualFold(k, "host") {
			continue
		}
		out[k] = s
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// applyStructuredXhttpExtraFields mirrors uri.js.
func applyStructuredXhttpExtraFields(target, xhttpOpts map[string]any, excludeHostHeader bool, xmuxTarget string) {
	if xhttpOpts == nil {
		return
	}
	if headers := toStringHeaderMap(getMapAny(xhttpOpts["headers"]), excludeHostHeader); headers != nil {
		target["headers"] = headers
	}
	if v, _ := xhttpOpts["no-grpc-header"].(bool); v {
		target["noGRPCHeader"] = true
	}
	for _, f := range []struct{ key, out string }{
		{"x-padding-bytes", "xPaddingBytes"},
		{"x-padding-key", "xPaddingKey"},
		{"x-padding-header", "xPaddingHeader"},
		{"x-padding-placement", "xPaddingPlacement"},
		{"x-padding-method", "xPaddingMethod"},
		{"uplink-http-method", "uplinkHTTPMethod"},
		{"session-placement", "sessionIDPlacement"},
		{"session-key", "sessionIDKey"},
		{"seq-placement", "seqPlacement"},
		{"seq-key", "seqKey"},
		{"uplink-data-placement", "uplinkDataPlacement"},
		{"uplink-data-key", "uplinkDataKey"},
	} {
		if v := xhttpOpts[f.key]; v != nil {
			target[f.out] = v
		}
	}
	if v, _ := xhttpOpts["x-padding-obfs-mode"].(bool); v {
		target["xPaddingObfsMode"] = true
	}
	if s, ok := xhttpOpts["session-table"].(string); ok {
		target["sessionIDTable"] = s
	}
	if v := normalizeXhttpStrictPositiveRangeValue(xhttpOpts["session-length"]); v != nil {
		target["sessionIDLength"] = v
	}
	if v := normalizeXhttpNonNegativeRange(xhttpOpts["uplink-chunk-size"]); v != nil {
		target["uplinkChunkSize"] = v
	}
	if xhttpOpts["sc-max-each-post-bytes"] != nil {
		if v := normalizeXhttpStrictPositiveRangeValue(xhttpOpts["sc-max-each-post-bytes"]); v != nil {
			target["scMaxEachPostBytes"] = v
		}
	}
	if xhttpOpts["sc-min-posts-interval-ms"] != nil {
		if v := normalizeXhttpPositiveRange(xhttpOpts["sc-min-posts-interval-ms"]); v != nil {
			target["scMinPostsIntervalMs"] = v
		}
	}
	xmux := mapReuseSettingsToXmux(getMapAny(xhttpOpts["reuse-settings"]))
	if xmux != nil {
		if xmuxTarget == "extra" {
			extra := getMapAny(target["extra"])
			if extra == nil {
				extra = map[string]any{}
			}
			extra["xmux"] = xmux
			target["extra"] = extra
		} else {
			target["xmux"] = xmux
		}
	}
}

func mapReuseSettingsToXmux(reuseSettings map[string]any) map[string]any {
	if reuseSettings == nil {
		return nil
	}
	xmux := map[string]any{}
	fieldMap := []struct{ src, dst string }{
		{"max-connections", "maxConnections"},
		{"max-concurrency", "maxConcurrency"},
		{"c-max-reuse-times", "cMaxReuseTimes"},
		{"h-max-request-times", "hMaxRequestTimes"},
		{"h-max-reusable-secs", "hMaxReusableSecs"},
	}
	for _, f := range fieldMap {
		if v := normalizeXhttpNonNegativeRange(reuseSettings[f.src]); v != nil {
			if n, ok := v.(int); ok {
				xmux[f.dst] = fmt.Sprint(n)
			} else {
				xmux[f.dst] = v
			}
		}
	}
	if v := normalizeXhttpIntegerValue(reuseSettings["h-keep-alive-period"], true); v != nil {
		xmux["hKeepAlivePeriod"] = v
	}
	if len(xmux) == 0 {
		return nil
	}
	return xmux
}

// buildXhttpDownloadSettings mirrors uri.js buildXhttpDownloadSettings.
func buildXhttpDownloadSettings(downloadSettings, outerXhttpOpts map[string]any, p *model.Proxy) map[string]any {
	if downloadSettings == nil {
		return nil
	}
	explicitNetwork := ""
	if s, ok := downloadSettings["network"].(string); ok {
		explicitNetwork = strings.ToLower(s)
	}
	normalizedNetwork := ""
	if explicitNetwork == "xhttp" || explicitNetwork == "splithttp" {
		normalizedNetwork = "xhttp"
	}
	result := map[string]any{}
	if s := str(downloadSettings["server"]); s != "" {
		result["address"] = s
	}
	if v := normalizeXhttpIntegerValue(downloadSettings["port"], false); v != nil {
		result["port"] = v
	}
	realityOpts := getMapAny(downloadSettings["reality-opts"])
	if realityOpts != nil {
		result["security"] = "reality"
	} else if b, _ := downloadSettings["tls"].(bool); b {
		result["security"] = "tls"
	}
	tlsSettings := map[string]any{}
	if s := str(downloadSettings["servername"]); s != "" {
		tlsSettings["serverName"] = s
	}
	if s := str(downloadSettings["client-fingerprint"]); s != "" {
		tlsSettings["fingerprint"] = s
	}
	if b, _ := downloadSettings["skip-cert-verify"].(bool); b {
		tlsSettings["allowInsecure"] = true
	}
	if alpn := downloadSettings["alpn"]; alpn != nil {
		if arr, ok := alpn.([]any); ok {
			tlsSettings["alpn"] = arr
		} else {
			tlsSettings["alpn"] = []any{alpn}
		}
	}
	echFields := buildXrayEchFieldsFromMihomo(getMapAny(downloadSettings["ech-opts"]), "")
	if v, ok := echFields["echConfigList"]; ok {
		tlsSettings["echConfigList"] = v
	}
	if v, ok := echFields["echForceQuery"]; ok {
		tlsSettings["echForceQuery"] = v
	}
	if v, ok := echFields["echSockopt"]; ok {
		tlsSettings["echSockopt"] = cloneAny(v)
	}
	if len(tlsSettings) > 0 {
		result["tlsSettings"] = tlsSettings
	}
	if realityOpts != nil {
		realitySettings := map[string]any{}
		if s := str(downloadSettings["servername"]); s != "" {
			realitySettings["serverName"] = s
		}
		if s := str(downloadSettings["client-fingerprint"]); s != "" {
			realitySettings["fingerprint"] = s
		}
		if s := str(realityOpts["public-key"]); s != "" {
			realitySettings["publicKey"] = s
		}
		if s := str(realityOpts["short-id"]); s != "" {
			realitySettings["shortId"] = s
		}
		if len(realitySettings) > 0 {
			result["realitySettings"] = realitySettings
		}
	}
	xhttpSettings := map[string]any{}
	dsPath := str(downloadSettings["path"])
	if dsPath == "" {
		dsPath = str(outerXhttpOpts["path"])
	}
	if dsPath != "" {
		xhttpSettings["path"] = dsPath
	}
	downloadHost := getTransportHost("xhttp", downloadSettings)
	if downloadHost == "" {
		downloadHost = getTransportHost("xhttp", outerXhttpOpts)
	}
	if downloadHost != "" {
		xhttpSettings["host"] = downloadHost
	}
	mode := str(downloadSettings["mode"])
	if mode == "" {
		mode = str(outerXhttpOpts["mode"])
	}
	if mode != "" {
		xhttpSettings["mode"] = mode
	}
	applyStructuredXhttpExtraFields(xhttpSettings, downloadSettings, true, "extra")
	if len(xhttpSettings) > 0 {
		result["xhttpSettings"] = xhttpSettings
	}
	if len(result) == 0 && normalizedNetwork == "" {
		return nil
	}
	out := map[string]any{"network": normalizedNetwork}
	if normalizedNetwork == "" {
		out["network"] = "xhttp"
	}
	if v, ok := result["address"]; ok {
		out["address"] = v
	}
	if v, ok := result["port"]; ok {
		out["port"] = v
	}
	if v, ok := result["security"]; ok {
		out["security"] = v
	}
	if v, ok := result["tlsSettings"]; ok {
		out["tlsSettings"] = v
	}
	if v, ok := result["realitySettings"]; ok {
		out["realitySettings"] = v
	}
	if v, ok := result["xhttpSettings"]; ok {
		out["xhttpSettings"] = v
	}
	return out
}

func mergeUnsupportedXhttpExtraObject(baseObject, unsupportedObject map[string]any) map[string]any {
	merged := map[string]any{}
	for k, v := range baseObject {
		merged[k] = cloneAny(v)
	}
	for k, v := range unsupportedObject {
		if _, exists := merged[k]; !exists {
			merged[k] = cloneAny(v)
			continue
		}
		merged[k] = mergeUnsupportedXhttpExtraValue(merged[k], v)
	}
	return merged
}

func mergeUnsupportedXhttpExtraValue(baseValue, unsupportedValue any) any {
	if baseValue == nil {
		return cloneAny(unsupportedValue)
	}
	_, baseArr := baseValue.([]any)
	_, unsupportedArr := unsupportedValue.([]any)
	if baseArr || unsupportedArr {
		return cloneAny(baseValue)
	}
	baseMap, baseOK := baseValue.(map[string]any)
	unsupportedMap, unsupportedOK := unsupportedValue.(map[string]any)
	if baseOK && unsupportedOK {
		return mergeUnsupportedXhttpExtraObject(baseMap, unsupportedMap)
	}
	return cloneAny(baseValue)
}

func trojanURI(p *model.Proxy) string {
	var sb strings.Builder
	sb.WriteString("?sni=" + encodeURIComponent(orServer(p.GetString("sni"), p.Server())))
	if p.GetBool("skip-cert-verify") {
		sb.WriteString("&allowInsecure=1")
	}
	transport := trojanTransportParams(p)
	sb.WriteString(transport)
	if alpn := p.Get("alpn"); alpn != nil {
		sb.WriteString("&alpn=" + encodeURIComponent(joinAlpn(alpn)))
	}
	if fp := p.GetString("client-fingerprint"); fp != "" {
		sb.WriteString("&fp=" + encodeURIComponent(fp))
	}
	if pcs := p.GetString("tls-fingerprint"); pcs != "" {
		sb.WriteString("&pcs=" + encodeURIComponent(pcs))
	}
	// uri.js:1203-1206: certNames = Array.isArray(_vcn) ? _vcn.join(',') : name-cert-verify
	trojanCertNames := ""
	trojanVcnIsArray := false
	if v := p.Get("_vcn"); v != nil {
		if arr, ok := v.([]any); ok {
			trojanCertNames = joinAny(arr, ",")
			trojanVcnIsArray = true
		}
	}
	if !trojanVcnIsArray {
		trojanCertNames = p.GetString("name-cert-verify")
	}
	if trojanVcnIsArray || trojanCertNames != "" {
		sb.WriteString("&vcn=" + encodeURIComponent(trojanCertNames))
	}
	if reality := p.GetMap("reality-opts"); reality != nil {
		sb.WriteString("&security=reality")
		if sid := str(reality["short-id"]); sid != "" {
			sb.WriteString("&sid=" + encodeURIComponent(sid))
		}
		if pbk := str(reality["public-key"]); pbk != "" {
			sb.WriteString("&pbk=" + encodeURIComponent(pbk))
		}
		if spx := str(reality["_spider-x"]); spx != "" {
			sb.WriteString("&spx=" + encodeURIComponent(spx))
		}
		if mode := p.GetString("_mode"); mode != "" {
			sb.WriteString("&mode=" + encodeURIComponent(mode))
		}
		if extra := p.GetString("_extra"); extra != "" {
			sb.WriteString("&extra=" + encodeURIComponent(extra))
		}
	}
	return "trojan://" + p.GetString("password") + "@" + p.Server() + ":" + fmt.Sprint(p.Port()) +
		sb.String() + "#" + encodeURIComponent(p.GetString("name"))
}

func orServer(v, server string) string {
	if v != "" {
		return v
	}
	return server
}

func trojanTransportParams(p *model.Proxy) string {
	network := p.GetString("network")
	if network == "" {
		return ""
	}
	trojanType := network
	if network == "ws" && p.GetBool("ws-opts.v2ray-http-upgrade") {
		trojanType = "httpupgrade"
	}
	transport := "&type=" + encodeURIComponent(trojanType)
	if network == "grpc" {
		if sn := gstr(p, "grpc-opts.grpc-service-name"); sn != "" {
			transport += "&serviceName=" + encodeURIComponent(sn)
		}
		if auth := gstr(p, "grpc-opts._grpc-authority"); auth != "" {
			transport += "&authority=" + encodeURIComponent(auth)
		}
		mode := gstr(p, "grpc-opts._grpc-type")
		if mode == "" {
			mode = "gun"
		}
		transport += "&mode=" + encodeURIComponent(mode)
	}
	opts := p.GetMap(network + "-opts")
	isUpgrade := network == "ws" && gbool(p, "ws-opts.v2ray-http-upgrade")
	path := joinFirst(opts["path"])
	if isUpgrade {
		path = setHttpUpgradeEarlyDataPath(path, opts)
	} else if network == "ws" {
		path = setWebSocketEarlyDataPath(path, opts)
	}
	if path != "" {
		transport += "&path=" + encodeURIComponent(path)
	}
	host := ""
	if opts != nil {
		if headers, ok := opts["headers"].(map[string]any); ok {
			if hh, ok := headers["Host"]; ok {
				host = joinFirst(hh)
			}
		}
	}
	if host != "" {
		transport += "&host=" + encodeURIComponent(host)
	}
	return transport
}

func hysteria2URI(p *model.Proxy) string {
	var params []string
	if v := p.GetString("hop-interval"); v != "" {
		params = append(params, "hop-interval="+v)
	}
	if v := p.GetString("keepalive"); v != "" {
		params = append(params, "keepalive="+v)
	}
	if p.GetBool("skip-cert-verify") {
		params = append(params, "insecure=1")
	}
	if obfs := p.GetString("obfs"); obfs != "" {
		params = append(params, "obfs="+encodeURIComponent(obfs))
		if pw := p.GetString("obfs-password"); pw != "" {
			params = append(params, "obfs-password="+encodeURIComponent(pw))
		}
	}
	if sni := p.GetString("sni"); sni != "" {
		params = append(params, "sni="+encodeURIComponent(sni))
	}
	if ports := p.GetString("ports"); ports != "" {
		params = append(params, "mport="+ports)
	}
	if fp := p.GetString("tls-fingerprint"); fp != "" {
		params = append(params, "pinSHA256="+encodeURIComponent(fp))
	}
	if p.GetBool("tfo") {
		params = append(params, "fastopen=1")
	}
	if ech := buildXrayEchConfigListFromMihomo(p.GetMap("ech-opts"), ""); ech != "" {
		params = append(params, "ech="+encodeURIComponent(ech))
	}
	return "hysteria2://" + encodeURIComponent(p.GetString("password")) + "@" + p.Server() + ":" +
		fmt.Sprint(p.Port()) + "?" + strings.Join(params, "&") + "#" + encodeURIComponent(p.GetString("name"))
}

func hysteriaURI(p *model.Proxy) string {
	var params []string
	keys := make([]string, 0, len(p.Fields()))
	for k := range p.Fields() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch key {
		case "name", "type", "server", "port":
			continue
		}
		i := replaceFirstHyphen(key)
		switch key {
		case "alpn":
			if isTruthy(p.Get(key)) {
				params = append(params, "alpn="+encodeURIComponent(joinFirst(p.Get(key))))
			}
		case "skip-cert-verify":
			if isTruthy(p.Get(key)) {
				params = append(params, "insecure=1")
			}
		case "tfo", "fast-open":
			if isTruthy(p.Get(key)) && !containsParam(params, "fastopen=1") {
				params = append(params, "fastopen=1")
			}
		case "ports":
			if isTruthy(p.Get(key)) {
				params = append(params, "mport="+str(p.Get(key)))
			}
		case "auth-str":
			if isTruthy(p.Get(key)) {
				params = append(params, "auth="+str(p.Get(key)))
			}
		case "up":
			if isTruthy(p.Get(key)) {
				params = append(params, "upmbps="+str(p.Get(key)))
			}
		case "down":
			if isTruthy(p.Get(key)) {
				params = append(params, "downmbps="+str(p.Get(key)))
			}
		case "_obfs":
			if isTruthy(p.Get(key)) {
				params = append(params, "obfs="+str(p.Get(key)))
			}
		case "obfs":
			if isTruthy(p.Get(key)) {
				params = append(params, "obfsParam="+str(p.Get(key)))
			}
		case "sni":
			if isTruthy(p.Get(key)) {
				params = append(params, "peer="+str(p.Get(key)))
			}
		default:
			if isTruthy(p.Get(key)) && !strings.HasPrefix(key, "_") {
				params = append(params, i+"="+encodeURIComponent(str(p.Get(key))))
			}
		}
	}
	return "hysteria://" + p.Server() + ":" + fmt.Sprint(p.Port()) + "?" + strings.Join(params, "&") +
		"#" + encodeURIComponent(p.GetString("name"))
}

func replaceFirstHyphen(s string) string {
	idx := strings.IndexByte(s, '-')
	if idx == -1 {
		return s
	}
	return s[:idx] + "_" + s[idx+1:]
}

func containsParam(params []string, target string) bool {
	for _, p := range params {
		if p == target {
			return true
		}
	}
	return false
}

func isTruthy(v any) bool {
	if v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != ""
	case int:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	case json.Number:
		f, _ := t.Float64()
		return f != 0
	default:
		return true
	}
}

func isFalsey(v any) bool {
	return !isTruthy(v)
}

func tuicURI(p *model.Proxy) string {
	token := p.Get("token")
	if token != nil {
		switch t := token.(type) {
		case string:
			if t != "" {
				return ""
			}
		case []any:
			if len(t) > 0 {
				return ""
			}
		case []string:
			if len(t) > 0 {
				return ""
			}
		default:
			return ""
		}
	}
	var params []string
	keys := make([]string, 0, len(p.Fields()))
	for k := range p.Fields() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch key {
		case "name", "type", "uuid", "password", "server", "port", "tls":
			continue
		}
		switch key {
		case "alpn":
			if v := p.Get(key); v != nil {
				params = append(params, "alpn="+encodeURIComponent(joinFirst(v)))
			}
		case "skip-cert-verify":
			if p.GetBool(key) {
				params = append(params, "allow_insecure=1")
			}
		case "tfo", "fast-open":
			if p.GetBool(key) && !containsParam(params, "fast_open=1") {
				params = append(params, "fast_open=1")
			}
		case "disable-sni", "reduce-rtt":
			if p.GetBool(key) {
				params = append(params, strings.ReplaceAll(key, "-", "_")+"=1")
			}
		case "congestion-controller":
			params = append(params, "congestion_control="+str(p.Get(key)))
		default:
			if isTruthy(p.Get(key)) && !strings.HasPrefix(key, "_") {
				params = append(params, strings.ReplaceAll(key, "-", "_")+"="+encodeURIComponent(str(p.Get(key))))
			}
		}
	}
	return "tuic://" + encodeURIComponent(p.GetString("uuid")) + ":" + encodeURIComponent(p.GetString("password")) +
		"@" + p.Server() + ":" + fmt.Sprint(p.Port()) + "?" + strings.Join(params, "&") +
		"#" + encodeURIComponent(p.GetString("name"))
}

func anytlsURI(p *model.Proxy) string {
	clone := p.Clone()
	clone.Set("uuid", clone.GetString("password"))
	if clone.GetString("network") == "" {
		clone.Set("network", "tcp")
	}
	result := strings.Replace(vlessURI(clone), "vless", "anytls", 1)

	existing := map[string]string{}
	if parts := strings.SplitN(result, "?", 2); len(parts) > 1 {
		query := parts[1]
		if idx := strings.IndexByte(query, '#'); idx != -1 {
			query = query[:idx]
		}
		for _, pair := range strings.Split(query, "&") {
			key, val, _ := strings.Cut(pair, "=")
			if key != "" {
				existing[key] = val
			}
		}
	}
	keys := make([]string, 0, len(p.Fields()))
	for k := range p.Fields() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch key {
		case "name", "type", "password", "server", "port", "tls":
			continue
		}
		switch key {
		case "alpn":
			if v := p.Get(key); v != nil {
				existing["alpn"] = encodeURIComponent(joinFirst(v))
			}
		case "skip-cert-verify":
			if p.GetBool(key) {
				existing["insecure"] = "1"
			}
		case "udp":
			if p.GetBool(key) {
				existing["udp"] = "1"
			}
		default:
			val := p.Get(key)
			if isTruthy(val) && !strings.HasPrefix(key, "_") && !strings.Contains(key, "client-fingerprint") {
				switch val.(type) {
				case string, int, int64, float64, bool, json.Number:
					existing[strings.ReplaceAll(key, "-", "_")] = encodeURIComponent(str(val))
				}
			}
		}
	}
	paramKeys := make([]string, 0, len(existing))
	for k := range existing {
		paramKeys = append(paramKeys, k)
	}
	sort.Strings(paramKeys)
	query := make([]string, 0, len(paramKeys))
	for _, k := range paramKeys {
		query = append(query, k+"="+existing[k])
	}
	fragment := ""
	if idx := strings.IndexByte(result, '#'); idx != -1 {
		fragment = result[idx:]
	}
	base := result
	if idx := strings.IndexByte(result, '?'); idx != -1 {
		base = result[:idx]
	}
	return base + "?" + strings.Join(query, "&") + fragment
}

func wireguardURI(p *model.Proxy) string {
	var params []string
	keys := make([]string, 0, len(p.Fields()))
	for k := range p.Fields() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch key {
		case "name", "type", "server", "port", "ip", "ipv6", "ip-cidr", "ipv6-cidr", "private-key":
			continue
		}
		switch key {
		case "public-key":
			params = append(params, "publickey="+encodeURIComponent(str(p.Get(key))))
		case "udp":
			if p.GetBool(key) {
				params = append(params, "udp=1")
			}
		default:
			if isTruthy(p.Get(key)) && !strings.HasPrefix(key, "_") {
				params = append(params, key+"="+encodeURIComponent(str(p.Get(key))))
			}
		}
	}
	v4 := getWireGuardAddressWithCIDR(p, "ipv4")
	v6 := getWireGuardAddressWithCIDR(p, "ipv6")
	switch {
	case v4 != "" && v6 != "":
		params = append(params, "address="+encodeURIComponent(v4+","+v6))
	case v4 != "":
		params = append(params, "address="+encodeURIComponent(v4))
	case v6 != "":
		params = append(params, "address="+encodeURIComponent(v6))
	}
	return "wireguard://" + encodeURIComponent(p.GetString("private-key")) + "@" + p.Server() + ":" +
		fmt.Sprint(p.Port()) + "/?" + strings.Join(params, "&") + "#" + encodeURIComponent(p.GetString("name"))
}
