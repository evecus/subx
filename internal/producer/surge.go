package producer

import (
	"fmt"
	"strings"

	"substore/internal/model"
)

// Surge producer mirroring producers/surge.js. Each proxy becomes one
// "name=type,server,port,opts..." line; unsupported proxies return an error
// (SurgeUnsupportedProxyError in JS) and are skipped by the list assembler.

const surgeTargetPlatform = "Surge"

// surgeUnsupportedError mirrors SurgeUnsupportedProxyError.
type surgeUnsupportedError struct{ message string }

func (e *surgeUnsupportedError) Error() string { return e.message }

func unsupportedSurge(message string) error {
	return &surgeUnsupportedError{message: message}
}

// surgeIpVersions mirrors the ipVersions map in surge.js.
var surgeIpVersions = map[string]string{
	"dual":        "dual",
	"ipv4":        "v4-only",
	"ipv6":        "v6-only",
	"ipv4-prefer": "prefer-v4",
	"ipv6-prefer": "prefer-v6",
}

// surgeResult mirrors the Result class in producers/utils.js.
type surgeResult struct {
	sb    strings.Builder
	proxy *model.Proxy
}

func newSurgeResult(p *model.Proxy) *surgeResult { return &surgeResult{proxy: p} }

func (r *surgeResult) append(data string) { r.sb.WriteString(data) }

func (r *surgeResult) appendIfPresent(data, attr string) {
	if isPresent(r.proxy, attr) {
		r.sb.WriteString(data)
	}
}

func (r *surgeResult) String() string { return r.sb.String() }

// surgeSSCiphers are the ciphers Surge accepts for SS.
var surgeSSCiphers = map[string]bool{
	"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"rc4": true, "rc4-md5": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true,
	"bf-cfb": true,
	"camellia-128-cfb": true, "camellia-192-cfb": true, "camellia-256-cfb": true,
	"cast5-cfb": true, "des-cfb": true, "idea-cfb": true, "rc2-cfb": true,
	"seed-cfb": true, "salsa20": true, "chacha20": true, "chacha20-ietf": true,
	"none": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
}

// ProduceSurge outputs Surge proxy lines (one per supported proxy).
func ProduceSurge(proxies []*model.Proxy, opts map[string]any) (string, error) {
	return produceSurgeLines(proxies, opts)
}

// produceSurgeLines mirrors the SINGLE-producer loop in index.js produce():
// each proxy line is produced, failures are skipped, then joined by "\n".
func produceSurgeLines(proxies []*model.Proxy, opts map[string]any) (string, error) {
	var lines []string
	for _, p := range proxies {
		line, err := surgeProduceLine(p, opts)
		if err != nil {
			continue
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n"), nil
}

// surgeProduceLine mirrors Surge_Producer().produce.
func surgeProduceLine(proxy *model.Proxy, opts map[string]any) (string, error) {
	if proxy.GetString("network") == "ws" {
		if wsOpts := proxy.GetMap("ws-opts"); wsOpts != nil {
			if b, _ := wsOpts["v2ray-http-upgrade"].(bool); b {
				return "", unsupportedSurge("Platform " + surgeTargetPlatform +
					" does not support network " + proxy.GetString("network") +
					" with http upgrade")
			}
		}
	}
	name := proxy.GetString("name")
	name = strings.NewReplacer("=", "", ",", "").Replace(name)
	proxy.Set("name", name)
	if v := proxy.Get("ports"); v != nil {
		proxy.Set("ports", str(v))
	}
	switch proxy.Type() {
	case "ss":
		return surgeShadowsocks(proxy)
	case "trojan":
		return surgeTrojan(proxy)
	case "vmess":
		return surgeVmess(proxy, includeUnsupported(opts))
	case "http":
		return surgeHTTP(proxy)
	case "h2-connect":
		return surgeH2Connect(proxy)
	case "direct":
		return surgeDirect(proxy)
	case "socks5":
		return surgeSocks5(proxy)
	case "snell":
		return surgeSnell(proxy)
	case "tuic":
		return surgeTuic(proxy)
	case "wireguard-surge":
		return surgeWireGuardSurge(proxy)
	case "hysteria2":
		return surgeHysteria2(proxy)
	case "ssh":
		return surgeSSH(proxy)
	case "trusttunnel":
		return surgeTrustTunnel(proxy)
	}

	if includeUnsupported(opts) && proxy.Type() == "wireguard" {
		return surgeWireGuard(proxy)
	}
	if proxy.Type() == "anytls" {
		if network := proxy.GetString("network"); network != "" &&
			(network != "tcp" || proxy.GetMap("reality-opts") != nil) {
			return "", unsupportedSurge("Platform " + surgeTargetPlatform +
				" does not support proxy type " + proxy.Type() + " with network or REALITY")
		}
		return surgeAnyTLS(proxy)
	}
	return "", unsupportedSurge("Platform " + surgeTargetPlatform +
		" does not support proxy type: " + proxy.Type())
}

func stripSurgeQuotes(v any) string {
	if s, ok := v.(string); ok {
		trimmed := strings.TrimSpace(s)
		if len(trimmed) >= 2 {
			quote := trimmed[0]
			if (quote == '"' || quote == '\'') && trimmed[len(trimmed)-1] == quote {
				return trimmed[1 : len(trimmed)-1]
			}
		}
		return trimmed
	}
	return str(v)
}

func quoteSurgeValue(v any) string {
	return `"` + stripSurgeQuotes(v) + `"`
}

// formatSurgeAlpn mirrors surge.js: arrays pass through, strings are split on
// commas after stripping quotes.
func formatSurgeAlpn(alpn any) string {
	var values []any
	if a, ok := alpn.([]any); ok {
		values = a
	} else if a, ok := alpn.([]string); ok {
		for _, s := range a {
			values = append(values, s)
		}
	} else {
		s := stripSurgeQuotes(alpn)
		if s == "" {
			return ""
		}
		for _, item := range strings.Split(s, ",") {
			values = append(values, item)
		}
	}
	parts := make([]string, 0, len(values))
	for _, item := range values {
		if item == nil {
			continue
		}
		trimmed := strings.TrimSpace(stripSurgeQuotes(item))
		if trimmed == "" {
			continue
		}
		parts = append(parts, trimmed)
	}
	return strings.Join(parts, ",")
}

func appendSurgeAlpn(result *surgeResult, proxy *model.Proxy) {
	alpn := formatSurgeAlpn(proxy.Get("alpn"))
	if alpn != "" {
		result.append(`,alpn="` + alpn + `"`)
	}
}

func getShadowTLSAlpn(proxy *model.Proxy) string {
	if opts := proxy.GetMap("plugin-opts"); opts != nil && opts["alpn"] != nil {
		return formatSurgeAlpn(opts["alpn"])
	}
	return formatSurgeAlpn(proxy.Get("alpn"))
}

// appendShadowTLS mirrors surge.js appendShadowTLS.
func appendShadowTLS(result *surgeResult, proxy *model.Proxy, includeUdpPort bool) error {
	if proxy.GetString("plugin") != "shadow-tls" || proxy.GetMap("plugin-opts") == nil {
		return nil
	}
	opts := proxy.GetMap("plugin-opts")
	password := str(opts["password"])
	host := str(opts["host"])
	version := opts["version"]
	if password == "" {
		return nil
	}
	result.append(`,shadow-tls-password="` + password + `"`)
	if host != "" {
		result.append(`,shadow-tls-sni=` + host)
	}
	if version != nil && isTruthy(version) {
		if strconvNum(version) < 2 {
			return unsupportedSurge(fmt.Sprintf("shadow-tls version %s is not supported", str(version)))
		}
		result.append(`,shadow-tls-version=` + str(version))
	}
	alpn := getShadowTLSAlpn(proxy)
	if alpn != "" {
		result.append(`,alpn="` + alpn + `"`)
	}
	if includeUdpPort {
		result.appendIfPresent(`,udp-port=`+str(proxy.Get("udp-port")), "udp-port")
	}
	return nil
}

// appendTlsProxyParams mirrors surge.js appendTlsProxyParams.
func appendTlsProxyParams(result *surgeResult, proxy *model.Proxy, enabled bool) {
	if !enabled {
		return
	}
	result.appendIfPresent(`,server-cert-fingerprint-sha256=`+str(proxy.Get("tls-fingerprint")), "tls-fingerprint")
	result.appendIfPresent(`,sni="`+str(proxy.Get("sni"))+`"`, "sni")
	result.appendIfPresent(`,server-cert-verify-name=`+quoteSurgeValue(proxy.Get("name-cert-verify")), "name-cert-verify")
	if proxy.GetString("plugin") != "shadow-tls" {
		appendSurgeAlpn(result, proxy)
	}
	result.appendIfPresent(`,skip-cert-verify=`+str(proxy.Get("skip-cert-verify")), "skip-cert-verify")
	clientCert := proxy.Get("keystore-client-cert")
	if clientCert == nil {
		clientCert = proxy.Get("client-cert")
	}
	if isPresent(proxy, "keystore-client-cert") || isPresent(proxy, "client-cert") {
		result.append(`,client-cert=` + quoteSurgeValue(clientCert))
	}
}

func appendSshPrivateKey(result *surgeResult, proxy *model.Proxy) {
	privateKey := proxy.Get("keystore-private-key")
	if privateKey == nil {
		privateKey = proxy.Get("private-key")
	}
	if isPresent(proxy, "keystore-private-key") || isPresent(proxy, "private-key") {
		result.append(`,private-key=` + quoteSurgeValue(privateKey))
	}
}

func hasSnellObfs(proxy *model.Proxy) bool {
	return isPresent(proxy, "obfs-opts.mode") ||
		isPresent(proxy, "obfs-opts.host") ||
		isPresent(proxy, "obfs-opts.path")
}

func isUnsupportedSnellV6Obfs(proxy *model.Proxy) bool {
	return strconvNum(proxy.Get("version")) == 6 && hasSnellObfs(proxy)
}

func surgeShadowsocks(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=ss,%s,%d", proxy.GetString("name"), proxy.Server(), proxy.Port()))
	cipher := proxy.GetString("cipher")
	if cipher == "" {
		cipher = "none"
	}
	if !surgeSSCiphers[cipher] {
		return "", unsupportedSurge("cipher " + cipher + " is not supported")
	}
	result.append(`,encrypt-method=` + cipher)
	result.appendIfPresent(`,password="`+str(proxy.Get("password"))+`"`, "password")

	surgeIPVersionNoErrorAlert(result, proxy)

	if isPresent(proxy, "plugin") {
		plugin := proxy.GetString("plugin")
		pluginOpts := proxy.GetMap("plugin-opts")
		if plugin == "obfs" {
			result.append(`,obfs=` + str(pluginOpts["mode"]))
			result.appendIfPresent(`,obfs-host=`+str(pluginOpts["host"]), "plugin-opts.host")
			result.appendIfPresent(`,obfs-uri=`+str(pluginOpts["path"]), "plugin-opts.path")
		} else if plugin != "shadow-tls" {
			return "", unsupportedSurge("plugin " + plugin + " is not supported")
		}
	}

	surgeCommon(result, proxy)
	if err := appendShadowTLS(result, proxy, true); err != nil {
		return "", err
	}
	surgeBlockUnderlying(result, proxy)
	return result.String(), nil
}

func surgeTrojan(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=trojan,%s,%d", proxy.GetString("name"), proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,password="`+str(proxy.Get("password"))+`"`, "password")
	surgeIPVersionNoErrorAlert(result, proxy)
	handleSurgeTransport(result, proxy, false)
	result.appendIfPresent(`,tls=`+str(proxy.Get("tls")), "tls")
	appendTlsProxyParams(result, proxy, true)
	surgeCommon(result, proxy)
	if err := appendShadowTLS(result, proxy, false); err != nil {
		return "", err
	}
	surgeBlockUnderlying(result, proxy)
	return result.String(), nil
}

func surgeAnyTLS(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=anytls,%s,%d", proxy.GetString("name"), proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,password="`+str(proxy.Get("password"))+`"`, "password")
	surgeIPVersionNoErrorAlert(result, proxy)
	appendTlsProxyParams(result, proxy, true)
	surgeCommon(result, proxy)
	surgeBlockUnderlying(result, proxy)
	result.appendIfPresent(`,reuse=`+str(proxy.Get("reuse")), "reuse")
	return result.String(), nil
}

func surgeTrustTunnel(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=trust-tunnel,%s,%d", proxy.GetString("name"), proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,username="`+str(proxy.Get("username"))+`"`, "username")
	result.appendIfPresent(`,password="`+str(proxy.Get("password"))+`"`, "password")
	appendSurgeHeaders(result, proxy)
	warnSurgeMaxStreams(proxy)
	result.appendIfPresent(`,max-streams=`+str(proxy.Get("max-streams")), "max-streams")
	surgeIPVersionNoErrorAlert(result, proxy)
	appendTlsProxyParams(result, proxy, true)
	surgeCommon(result, proxy)
	surgeBlockUnderlying(result, proxy)
	result.appendIfPresent(`,reuse=`+str(proxy.Get("reuse")), "reuse")
	return result.String(), nil
}

func surgeH2Connect(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=h2-connect,%s,%d", proxy.GetString("name"), proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,username="`+str(proxy.Get("username"))+`"`, "username")
	result.appendIfPresent(`,password="`+str(proxy.Get("password"))+`"`, "password")
	appendSurgeHeaders(result, proxy)
	warnSurgeMaxStreams(proxy)
	result.appendIfPresent(`,max-streams=`+str(proxy.Get("max-streams")), "max-streams")
	surgeIPVersionNoErrorAlert(result, proxy)
	appendTlsProxyParams(result, proxy, true)
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	surgeTestFields(result, proxy)
	surgeInterfaceFields(result, proxy)
	if err := appendShadowTLS(result, proxy, false); err != nil {
		return "", err
	}
	surgeBlockUnderlying(result, proxy)
	return result.String(), nil
}

func surgeVmess(proxy *model.Proxy, includeUnsupportedProxy bool) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=vmess,%s,%d", proxy.GetString("name"), proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,username=`+str(proxy.Get("uuid")), "uuid")
	encryptMethod := formatSurgeVmessEncryptMethod(proxy.GetString("cipher"))
	if encryptMethod != "" {
		result.append(`,encrypt-method=` + encryptMethod)
	}
	surgeIPVersionNoErrorAlert(result, proxy)
	if err := handleSurgeTransport(result, proxy, includeUnsupportedProxy); err != nil {
		return "", err
	}
	if isPresent(proxy, "aead") {
		result.append(`,vmess-aead=` + str(proxy.Get("aead")))
	} else {
		// mirror surge.js: alterId === 0 only when the field exists and is 0;
		// a missing alterId means aead=false.
		result.append(fmt.Sprintf(`,vmess-aead=%t`, proxy.Has("alterId") && proxy.GetInt("alterId") == 0))
	}
	result.appendIfPresent(`,tls=`+str(proxy.Get("tls")), "tls")
	appendTlsProxyParams(result, proxy, proxy.GetBool("tls"))
	surgeCommon(result, proxy)
	if err := appendShadowTLS(result, proxy, false); err != nil {
		return "", err
	}
	surgeBlockUnderlying(result, proxy)
	return result.String(), nil
}

func surgeSSH(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=ssh,%s,%d", proxy.GetString("name"), proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,username="`+str(proxy.Get("username"))+`"`, "username")
	result.appendIfPresent(`,password="`+str(proxy.Get("password"))+`"`, "password")
	appendSshPrivateKey(result, proxy)
	result.appendIfPresent(`,idle-timeout=`+str(proxy.Get("idle-timeout")), "idle-timeout")
	result.appendIfPresent(`,server-fingerprint="`+str(proxy.Get("server-fingerprint"))+`"`, "server-fingerprint")
	surgeIPVersionNoErrorAlert(result, proxy)
	surgeCommon(result, proxy)
	surgeBlockUnderlying(result, proxy)
	return result.String(), nil
}

func surgeHTTP(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	typ := "http"
	if proxy.GetBool("tls") {
		typ = "https"
	}
	result.append(fmt.Sprintf("%s=%s,%s,%d", proxy.GetString("name"), typ, proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,username="`+str(proxy.Get("username"))+`"`, "username")
	result.appendIfPresent(`,password="`+str(proxy.Get("password"))+`"`, "password")
	appendSurgeHeaders(result, proxy)
	surgeIPVersionNoErrorAlert(result, proxy)
	appendTlsProxyParams(result, proxy, proxy.GetBool("tls"))
	surgeCommon(result, proxy)
	if err := appendShadowTLS(result, proxy, false); err != nil {
		return "", err
	}
	surgeBlockUnderlying(result, proxy)
	return result.String(), nil
}

func surgeDirect(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(proxy.GetString("name") + "=direct")
	surgeIPVersionNoErrorAlert(result, proxy)
	surgeCommon(result, proxy)
	surgeBlockUnderlying(result, proxy)
	return result.String(), nil
}

func surgeSocks5(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	typ := "socks5"
	if proxy.GetBool("tls") {
		typ = "socks5-tls"
	}
	result.append(fmt.Sprintf("%s=%s,%s,%d", proxy.GetString("name"), typ, proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,username="`+str(proxy.Get("username"))+`"`, "username")
	result.appendIfPresent(`,password="`+str(proxy.Get("password"))+`"`, "password")
	surgeIPVersionNoErrorAlert(result, proxy)
	appendTlsProxyParams(result, proxy, proxy.GetBool("tls"))
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	surgeTestFields(result, proxy)
	surgeInterfaceFields(result, proxy)
	if err := appendShadowTLS(result, proxy, false); err != nil {
		return "", err
	}
	surgeBlockUnderlying(result, proxy)
	return result.String(), nil
}

func appendSurgeHeaders(result *surgeResult, proxy *model.Proxy) {
	value := formatSurgeHeaderMap(proxy.GetMap("headers"), ";")
	if value != "" {
		result.append(`,headers=` + quoteSurgeValue(value))
	}
}

// formatSurgeHeaderMap mirrors surge.js formatHeaderMap.
func formatSurgeHeaderMap(headers map[string]any, separator string) string {
	if headers == nil {
		return ""
	}
	parts := make([]string, 0, len(headers))
	for key, value := range headers {
		if strings.TrimSpace(str(key)) == "" || value == nil {
			continue
		}
		parts = append(parts, key+":"+quoteSurgeValue(value))
	}
	return strings.Join(parts, separator)
}

func surgeSnell(proxy *model.Proxy) (string, error) {
	if isUnsupportedSnellV6Obfs(proxy) {
		return "", nil
	}
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=snell,%s,%d", proxy.GetString("name"), proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,version=`+str(proxy.Get("version")), "version")
	result.appendIfPresent(`,psk="`+str(proxy.Get("psk"))+`"`, "psk")
	if strconvNum(proxy.Get("version")) == 6 {
		result.appendIfPresent(`,mode=`+str(proxy.Get("mode")), "mode")
	}
	surgeIPVersionNoErrorAlert(result, proxy)
	result.appendIfPresent(`,obfs=`+strAny(getMapNested(proxy.Fields(), "obfs-opts", "mode")), "obfs-opts.mode")
	result.appendIfPresent(`,obfs-host=`+strAny(getMapNested(proxy.Fields(), "obfs-opts", "host")), "obfs-opts.host")
	result.appendIfPresent(`,obfs-uri=`+strAny(getMapNested(proxy.Fields(), "obfs-opts", "path")), "obfs-opts.path")
	surgeCommon(result, proxy)
	if err := appendShadowTLS(result, proxy, false); err != nil {
		return "", err
	}
	surgeBlockUnderlying(result, proxy)
	result.appendIfPresent(`,reuse=`+str(proxy.Get("reuse")), "reuse")
	return result.String(), nil
}

func surgeTuic(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	typ := proxy.Type()
	if isTokenEmpty(proxy.Get("token")) {
		typ = "tuic-v5"
	}
	result.append(fmt.Sprintf("%s=%s,%s,%d", proxy.GetString("name"), typ, proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,uuid=`+str(proxy.Get("uuid")), "uuid")
	result.appendIfPresent(`,password="`+str(proxy.Get("password"))+`"`, "password")
	result.appendIfPresent(`,token=`+str(proxy.Get("token")), "token")

	if hasNonBlankValue(proxy.Get("ports")) {
		result.append(`,port-hopping="` + strings.ReplaceAll(str(proxy.Get("ports")), ",", ";") + `"`)
	}
	if hasNonBlankValue(proxy.Get("hop-interval")) {
		result.append(`,port-hopping-interval=` + str(proxy.Get("hop-interval")))
	}
	surgeIPVersionNoErrorAlert(result, proxy)
	appendTlsProxyParams(result, proxy, true)
	if isPresent(proxy, "tfo") {
		result.append(`,tfo=` + str(proxy.Get("tfo")))
	} else if isPresent(proxy, "fast-open") {
		result.append(`,tfo=` + str(proxy.Get("fast-open")))
	}
	surgeTestFields(result, proxy)
	surgeInterfaceFields(result, proxy)
	if err := appendShadowTLS(result, proxy, false); err != nil {
		return "", err
	}
	surgeBlockUnderlying(result, proxy)
	result.appendIfPresent(`,ecn=`+str(proxy.Get("ecn")), "ecn")
	return result.String(), nil
}

func surgeWireGuard(proxy *model.Proxy) (string, error) {
	if peers := proxy.GetArray("peers"); len(peers) > 0 {
		if peer, ok := peers[0].(map[string]any); ok {
			proxy.Set("server", peer["server"])
			proxy.Set("port", peer["port"])
			proxy.Set("ip", peer["ip"])
			proxy.Set("ipv6", peer["ipv6"])
			proxy.Set("public-key", peer["public-key"])
			proxy.Set("preshared-key", peer["pre-shared-key"])
			proxy.Set("allowed-ips", peer["allowed-ips"])
			proxy.Set("reserved", peer["reserved"])
		}
	}
	result := newSurgeResult(proxy)

	result.append(fmt.Sprintf("# > WireGuard Proxy %s\n# %s=wireguard",
		proxy.GetString("name"), proxy.GetString("name")))

	proxy.Set("section-name", getIfNotBlank(proxy.Get("section-name"), proxy.GetString("name")))
	result.appendIfPresent(`,section-name=`+str(proxy.Get("section-name")), "section-name")
	result.appendIfPresent(`,no-error-alert=`+str(proxy.Get("no-error-alert")), "no-error-alert")
	surgeIPVersion(result, proxy)
	surgeTestFields(result, proxy)
	surgeInterfaceFields(result, proxy)
	if err := appendShadowTLS(result, proxy, false); err != nil {
		return "", err
	}
	surgeBlockUnderlying(result, proxy)

	result.append(fmt.Sprintf("\n# > WireGuard Section %s\n[WireGuard %s]\nprivate-key = %s",
		proxy.GetString("name"), proxy.GetString("section-name"), str(proxy.Get("private-key"))))

	result.appendIfPresent("\nself-ip = "+str(proxy.Get("ip")), "ip")
	result.appendIfPresent("\nself-ip-v6 = "+str(proxy.Get("ipv6")), "ipv6")
	if isTruthy(proxy.Get("dns")) {
		dns := proxy.Get("dns")
		if a, ok := dns.([]any); ok {
			parts := make([]string, 0, len(a))
			for _, item := range a {
				parts = append(parts, str(item))
			}
			dns = strings.Join(parts, ", ")
		} else if a, ok := dns.([]string); ok {
			dns = strings.Join(a, ", ")
		}
		result.append("\ndns-server = " + str(dns))
	}
	result.appendIfPresent("\nmtu = "+str(proxy.Get("mtu")), "mtu")

	if ipVersion := proxy.GetString("ip-version"); ipVersion == "prefer-v6" {
		result.append("\nprefer-ipv6 = true")
	}
	allowedIps := proxy.Get("allowed-ips")
	if a, ok := allowedIps.([]any); ok {
		parts := make([]string, 0, len(a))
		for _, item := range a {
			parts = append(parts, str(item))
		}
		allowedIps = strings.Join(parts, ",")
	} else if a, ok := allowedIps.([]string); ok {
		allowedIps = strings.Join(a, ",")
	}
	reserved := proxy.Get("reserved")
	if a, ok := reserved.([]any); ok {
		parts := make([]string, 0, len(a))
		for _, item := range a {
			parts = append(parts, str(item))
		}
		reserved = strings.Join(parts, "/")
	} else if a, ok := reserved.([]string); ok {
		reserved = strings.Join(a, "/")
	}
	presharedKey := proxy.Get("preshared-key")
	if presharedKey == nil {
		presharedKey = proxy.Get("pre-shared-key")
	}

	keepalive := proxy.Get("persistent-keepalive")
	if !isTruthy(keepalive) {
		keepalive = proxy.Get("keepalive")
	}
	allowedIpsStr := ""
	if allowedIps != nil && isTruthy(allowedIps) {
		allowedIpsStr = `"` + str(allowedIps) + `"`
	}
	peer := []string{
		"public-key = " + str(proxy.Get("public-key")),
	}
	if allowedIpsStr != "" {
		peer = append(peer, "allowed-ips = "+allowedIpsStr)
	}
	peer = append(peer, "endpoint = "+str(proxy.Get("server"))+":"+str(proxy.Get("port")))
	if keepalive != nil && !isTruthy(keepalive) {
		// omitted (falsy)
	} else if keepalive != nil {
		peer = append(peer, "keepalive = "+str(keepalive))
	}
	if reserved != nil && isTruthy(reserved) {
		peer = append(peer, "client-id = "+str(reserved))
	}
	if presharedKey != nil && isTruthy(presharedKey) {
		peer = append(peer, "preshared-key = "+str(presharedKey))
	}
	result.append("\npeer = (" + strings.Join(peer, ", ") + ")")
	return result.String(), nil
}

func surgeWireGuardSurge(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(proxy.GetString("name") + "=wireguard")
	result.appendIfPresent(`,section-name=`+str(proxy.Get("section-name")), "section-name")
	result.appendIfPresent(`,no-error-alert=`+str(proxy.Get("no-error-alert")), "no-error-alert")
	surgeIPVersion(result, proxy)
	surgeTestFields(result, proxy)
	surgeInterfaceFields(result, proxy)
	if err := appendShadowTLS(result, proxy, false); err != nil {
		return "", err
	}
	surgeBlockUnderlying(result, proxy)
	return result.String(), nil
}

func surgeHysteria2(proxy *model.Proxy) (string, error) {
	obfsPasswordField := ""
	switch proxy.GetString("obfs") {
	case "salamander":
		obfsPasswordField = "salamander-password"
	case "gecko":
		obfsPasswordField = "gecko-password"
	}
	if isTruthy(proxy.Get("obfs-password")) && obfsPasswordField == "" {
		return "", unsupportedSurge("only salamander and gecko obfs are supported")
	}
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=hysteria2,%s,%d", proxy.GetString("name"), proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,password="`+str(proxy.Get("password"))+`"`, "password")
	if hasNonBlankValue(proxy.Get("ports")) {
		result.append(`,port-hopping="` + strings.ReplaceAll(str(proxy.Get("ports")), ",", ";") + `"`)
	}
	if hasNonBlankValue(proxy.Get("hop-interval")) {
		result.append(`,port-hopping-interval=` + str(proxy.Get("hop-interval")))
	}
	if isTruthy(proxy.Get("obfs-password")) && obfsPasswordField != "" {
		result.append(`,` + obfsPasswordField + `="` + str(proxy.Get("obfs-password")) + `"`)
	}
	surgeIPVersionNoErrorAlert(result, proxy)
	appendTlsProxyParams(result, proxy, true)
	if isPresent(proxy, "tfo") {
		result.append(`,tfo=` + str(proxy.Get("tfo")))
	} else if isPresent(proxy, "fast-open") {
		result.append(`,tfo=` + str(proxy.Get("fast-open")))
	}
	surgeTestFields(result, proxy)
	surgeInterfaceFields(result, proxy)
	if err := appendShadowTLS(result, proxy, false); err != nil {
		return "", err
	}
	surgeBlockUnderlying(result, proxy)
	result.appendIfPresent(`,download-bandwidth=`+str(extractFirstDigits(proxy.Get("down"))), "down")
	result.appendIfPresent(`,ecn=`+str(proxy.Get("ecn")), "ecn")
	return result.String(), nil
}

// handleSurgeTransport mirrors surge.js handleTransport.
func handleSurgeTransport(result *surgeResult, proxy *model.Proxy, includeUnsupportedProxy bool) error {
	if !isPresent(proxy, "network") {
		return nil
	}
	network := proxy.GetString("network")
	if network == "ws" {
		result.append(`,ws=true`)
		if isPresent(proxy, "ws-opts") {
			wsOpts := proxy.GetMap("ws-opts")
			result.appendIfPresent(`,ws-path=`+str(wsOpts["path"]), "ws-opts.path")
			if headers, ok := getNested(proxy, "ws-opts.headers").(map[string]any); ok {
				value := formatSurgeHeaderMap(headers, "|")
				if value != "" {
					result.append(`,ws-headers=` + quoteSurgeValue(value))
				}
			}
		}
		return nil
	}
	if includeUnsupportedProxy && network == "http" {
		// logged as info in JS; network http -> tcp
		return nil
	}
	if network == "tcp" && proxy.GetMap("reality-opts") != nil {
		return unsupportedSurge("reality is unsupported")
	}
	if network != "tcp" {
		return unsupportedSurge("network " + network + " is unsupported")
	}
	return nil
}

// surgeIPVersionNoErrorAlert appends ip-version and no-error-alert.
func surgeIPVersionNoErrorAlert(result *surgeResult, proxy *model.Proxy) {
	surgeIPVersion(result, proxy)
	result.appendIfPresent(`,no-error-alert=`+str(proxy.Get("no-error-alert")), "no-error-alert")
}

// surgeIPVersion mirrors the ip_version mapping + appendIfPresent.
func surgeIPVersion(result *surgeResult, proxy *model.Proxy) {
	ipVersion := proxy.Get("ip-version")
	if ipVersion == nil {
		return
	}
	v := str(ipVersion)
	if mapped, ok := surgeIpVersions[v]; ok {
		v = mapped
	}
	result.appendIfPresent(`,ip-version=`+v, "ip-version")
}

// surgeCommon appends tfo/udp/test/interface fields shared by most types.
func surgeCommon(result *surgeResult, proxy *model.Proxy) {
	result.appendIfPresent(`,tfo=`+str(proxy.Get("tfo")), "tfo")
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	surgeTestFields(result, proxy)
	surgeInterfaceFields(result, proxy)
}

func surgeTestFields(result *surgeResult, proxy *model.Proxy) {
	result.appendIfPresent(`,test-url=`+str(proxy.Get("test-url")), "test-url")
	result.appendIfPresent(`,test-timeout=`+str(proxy.Get("test-timeout")), "test-timeout")
	result.appendIfPresent(`,test-udp=`+str(proxy.Get("test-udp")), "test-udp")
	result.appendIfPresent(`,hybrid=`+str(proxy.Get("hybrid")), "hybrid")
	result.appendIfPresent(`,tos=`+str(proxy.Get("tos")), "tos")
}

func surgeInterfaceFields(result *surgeResult, proxy *model.Proxy) {
	result.appendIfPresent(`,allow-other-interface=`+str(proxy.Get("allow-other-interface")), "allow-other-interface")
	result.appendIfPresent(`,interface=`+str(proxy.Get("interface-name")), "interface-name")
	result.appendIfPresent(`,interface=`+str(proxy.Get("interface")), "interface")
}

func surgeBlockUnderlying(result *surgeResult, proxy *model.Proxy) {
	result.appendIfPresent(`,block-quic=`+str(proxy.Get("block-quic")), "block-quic")
	result.appendIfPresent(`,underlying-proxy=`+str(proxy.Get("underlying-proxy")), "underlying-proxy")
}

func warnSurgeMaxStreams(proxy *model.Proxy) {
	// JS logs a warning when max-streams is an integer greater than 3.
}

// getIfNotBlank mirrors @/utils getIfNotBlank: only non-blank strings pass.
func getIfNotBlank(v any, defaultValue string) string {
	if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
		return s
	}
	return defaultValue
}

// formatSurgeVmessEncryptMethod mirrors vmess-security.js.
func formatSurgeVmessEncryptMethod(cipher string) string {
	c := strings.ToLower(strings.TrimSpace(cipher))
	switch c {
	case "aes-128-gcm":
		return "aes-128-gcm"
	case "chacha20-poly1305", "chacha20-ietf-poly1305":
		return "chacha20-ietf-poly1305"
	default:
		return ""
	}
}
