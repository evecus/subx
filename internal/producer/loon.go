package producer

import (
	"encoding/json"
	"fmt"
	"strings"

	"substore/internal/model"
)

// Loon producer mirroring producers/loon.js. Each proxy becomes one
// "name=type,server,port,..." line; unsupported proxies are skipped.

const loonTargetPlatform = "Loon"

// loonSSCiphers are the ciphers Loon accepts for SS.
var loonSSCiphers = map[string]bool{
	"rc4": true, "rc4-md5": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true,
	"bf-cfb": true,
	"camellia-128-cfb": true, "camellia-192-cfb": true, "camellia-256-cfb": true,
	"salsa20": true, "chacha20": true, "chacha20-ietf": true,
	"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
}

// ProduceLoon outputs Loon proxy lines (one per supported proxy).
func ProduceLoon(proxies []*model.Proxy, options map[string]any) (string, error) {
	var lines []string
	for _, p := range proxies {
		line, err := loonProduceLine(p)
		if err != nil {
			continue
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n"), nil
}

// loonProduceLine mirrors Loon_Producer().produce.
func loonProduceLine(proxy *model.Proxy) (string, error) {
	if proxy.GetString("network") == "ws" {
		if wsOpts := proxy.GetMap("ws-opts"); wsOpts != nil {
			if b, _ := wsOpts["v2ray-http-upgrade"].(bool); b {
				return "", fmt.Errorf("Platform %s does not support network %s with http upgrade",
					loonTargetPlatform, proxy.GetString("network"))
			}
		}
	}
	switch proxy.Type() {
	case "ss":
		return loonShadowsocks(proxy)
	case "ssr":
		return loonShadowsocksR(proxy)
	case "trojan":
		return loonTrojan(proxy)
	case "vmess":
		return loonVmess(proxy)
	case "vless":
		return loonVless(proxy)
	case "http":
		return loonHTTP(proxy)
	case "socks5":
		return loonSocks5(proxy)
	case "wireguard":
		return loonWireGuard(proxy)
	case "hysteria2":
		return loonHysteria2(proxy)
	}
	if proxy.Type() == "anytls" {
		if network := proxy.GetString("network"); network != "" && network != "tcp" {
			return "", fmt.Errorf("Platform %s does not support proxy type %s with network %s",
				loonTargetPlatform, proxy.Type(), network)
		}
		return loonAnyTLS(proxy)
	}
	return "", fmt.Errorf("Platform %s does not support proxy type: %s",
		loonTargetPlatform, proxy.Type())
}

// loonAppendTlsProfile mirrors appendTlsProfile in loon.js.
func loonAppendTlsProfile(result *surgeResult, proxy *model.Proxy) {
	tlsProfile := getLoonTlsProfile(proxy)
	if tlsProfile != "" {
		result.append(`,tls-profile=` + tlsProfile)
	}
}

// loonAppendAlpn mirrors appendAlpn in loon.js.
func loonAppendAlpn(result *surgeResult, proxy *model.Proxy) {
	alpn := getLoonAlpn(proxy)
	if alpn != "" {
		result.append(`,alpn="` + alpn + `"`)
	}
}

// getLoonAlpn mirrors getLoonAlpn in loon.js: arrays are joined, strings are
// comma split, then trimmed and filtered.
func getLoonAlpn(proxy *model.Proxy) string {
	var values []any
	if a, ok := proxy.Get("alpn").([]any); ok {
		values = a
	} else {
		for _, item := range strings.Split(str(proxy.Get("alpn")), ",") {
			values = append(values, item)
		}
	}
	parts := make([]string, 0, len(values))
	for _, item := range values {
		if trimmed := strings.TrimSpace(str(item)); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return strings.Join(parts, ",")
}

// getLoonTlsProfile mirrors getLoonTlsProfile in loon.js.
func getLoonTlsProfile(proxy *model.Proxy) string {
	tlsProfile := strings.TrimSpace(proxy.GetString("_loon_tls_profile"))
	if tlsProfile == "default" || tlsProfile == "chrome" ||
		tlsProfile == "ios18" || tlsProfile == "ios26" {
		return tlsProfile
	}
	switch strings.TrimSpace(proxy.GetString("client-fingerprint")) {
	case "chrome":
		return "chrome"
	case "ios":
		return "ios26"
	}
	return ""
}

// loonAppendShadowTLS mirrors appendShadowTLS in loon.js.
func loonAppendShadowTLS(result *surgeResult, proxy *model.Proxy) error {
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
	result.append(`,shadow-tls-password=` + password)
	if host != "" {
		result.append(`,shadow-tls-sni=` + host)
	}
	if version != nil {
		if n, ok := parseStrictIntString(strings.TrimSpace(str(version))); ok && n < 2 {
			return fmt.Errorf("shadow-tls version %s is not supported", str(version))
		}
		result.append(`,shadow-tls-version=` + str(version))
	}
	loonAppendTlsProfile(result, proxy)
	values := getNested(proxy, "plugin-opts.alpn")
	if values == nil {
		values = proxy.Get("alpn")
	}
	alpn := getLoonAlpnFromValues(values)
	if alpn != "" {
		result.append(`,alpn="` + alpn + `"`)
	}
	result.appendIfPresent(`,udp-port=`+str(proxy.Get("udp-port")), "udp-port")
	return nil
}

// getLoonAlpnFromValues shares the normalization of getLoonAlpn.
func getLoonAlpnFromValues(v any) string {
	var values []any
	if a, ok := v.([]any); ok {
		values = a
	} else {
		for _, item := range strings.Split(str(v), ",") {
			values = append(values, item)
		}
	}
	parts := make([]string, 0, len(values))
	for _, item := range values {
		if trimmed := strings.TrimSpace(str(item)); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return strings.Join(parts, ",")
}

// loonAppendReality mirrors appendReality in loon.js.
func loonAppendReality(result *surgeResult, proxy *model.Proxy) {
	result.appendIfPresent(`,sni=`+str(proxy.Get("sni")), "sni")
	reality := proxy.GetMap("reality-opts")
	if reality != nil {
		if pk, ok := reality["public-key"]; ok && pk != nil {
			result.append(`,public-key="` + str(pk) + `"`)
		}
		if sid, ok := reality["short-id"]; ok && sid != nil {
			result.append(`,short-id=` + str(sid))
		}
	}
}

// loonAppendBlockQuic mirrors the block-quic on/off checks in loon.js.
func loonAppendBlockQuic(result *surgeResult, proxy *model.Proxy) {
	switch proxy.GetString("block-quic") {
	case "on":
		result.append(",block-quic=true")
	case "off":
		result.append(",block-quic=false")
	}
}

// loonAppendIPMode mirrors the ip-mode appends in loon.js.
func loonAppendIPMode(result *surgeResult, proxy *model.Proxy) {
	ipVersion := str(proxy.Get("ip-version"))
	if mapped, ok := surgeIpVersions[ipVersion]; ok {
		ipVersion = mapped
	}
	result.appendIfPresent(`,ip-mode=`+ipVersion, "ip-version")
}

// loonAppendTransport handles the transport block shared by trojan/vmess/vless.
func loonAppendTransport(result *surgeResult, proxy *model.Proxy, fallbackTCP bool) error {
	if proxy.GetString("network") == "tcp" {
		proxy.Delete("network")
	}
	if !isPresent(proxy, "network") {
		if fallbackTCP {
			result.append(`,transport=tcp`)
		}
		return nil
	}
	network := proxy.GetString("network")
	if network == "ws" {
		result.append(`,transport=ws`)
		result.appendIfPresent(`,path=`+str(getNested(proxy, "ws-opts.path")), "ws-opts.path")
		result.appendIfPresent(`,host=`+str(getNested(proxy, "ws-opts.headers.Host")), "ws-opts.headers.Host")
		return nil
	}
	if network == "http" {
		result.append(`,transport=http`)
		httpPath := getNested(proxy, "http-opts.path")
		if a, ok := httpPath.([]any); ok && len(a) > 0 {
			httpPath = a[0]
		}
		result.appendIfPresent(`,path=`+str(httpPath), "http-opts.path")
		httpHost := getNested(proxy, "http-opts.headers.Host")
		if a, ok := httpHost.([]any); ok && len(a) > 0 {
			httpHost = a[0]
		}
		result.appendIfPresent(`,host=`+str(httpHost), "http-opts.headers.Host")
		return nil
	}
	return fmt.Errorf("network %s is unsupported", network)
}

func loonShadowsocks(proxy *model.Proxy) (string, error) {
	cipher := strings.ToLower(strings.TrimSpace(proxy.GetString("cipher")))
	if !loonSSCiphers[cipher] {
		return "", fmt.Errorf("cipher %s is not supported", str(proxy.Get("cipher")))
	}
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=shadowsocks,%s,%d,%s,\"%s\"",
		proxy.GetString("name"), proxy.Server(), proxy.Port(), cipher, str(proxy.Get("password"))))

	if isPresent(proxy, "plugin") {
		switch proxy.GetString("plugin") {
		case "obfs":
			result.append(`,obfs-name=` + str(getNested(proxy, "plugin-opts.mode")))
			result.appendIfPresent(`,obfs-host=`+str(getNested(proxy, "plugin-opts.host")), "plugin-opts.host")
			result.appendIfPresent(`,obfs-uri=`+str(getNested(proxy, "plugin-opts.path")), "plugin-opts.path")
		case "shadow-tls":
		default:
			return "", fmt.Errorf("plugin %s is not supported", str(proxy.Get("plugin")))
		}
	}
	if err := loonAppendShadowTLS(result, proxy); err != nil {
		return "", err
	}
	if proxy.GetBool("udp-over-tcp") {
		if proxy.GetInt("udp-over-tcp-version") == 2 {
			if proxy.GetString("plugin") == "obfs" {
				// JS logs an error and skips the flag
			} else {
				result.append(`,udp-over-tcp=true`)
			}
		}
	}
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	loonAppendBlockQuic(result, proxy)
	if proxy.GetBool("udp") {
		result.append(`,udp=true`)
	}
	loonAppendIPMode(result, proxy)
	return result.String(), nil
}

func loonShadowsocksR(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=shadowsocksr,%s,%d,%s,\"%s\"",
		proxy.GetString("name"), proxy.Server(), proxy.Port(), str(proxy.Get("cipher")), str(proxy.Get("password"))))
	result.append(`,protocol=` + jsValueOrUndefined(proxy.Get("protocol")))
	result.appendIfPresent(`,protocol-param=`+str(proxy.Get("protocol-param")), "protocol-param")
	result.appendIfPresent(`,obfs=`+str(proxy.Get("obfs")), "obfs")
	result.appendIfPresent(`,obfs-param=`+str(proxy.Get("obfs-param")), "obfs-param")
	if err := loonAppendShadowTLS(result, proxy); err != nil {
		return "", err
	}
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	loonAppendBlockQuic(result, proxy)
	if proxy.GetBool("udp") {
		result.append(`,udp=true`)
	}
	loonAppendIPMode(result, proxy)
	return result.String(), nil
}

// jsValueOrUndefined mirrors template interpolation of a missing field.
func jsValueOrUndefined(v any) string {
	if v == nil {
		return "undefined"
	}
	return str(v)
}

func loonTrojan(proxy *model.Proxy) (string, error) {
	isReality := proxy.GetMap("reality-opts") != nil
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=trojan,%s,%d,\"%s\"",
		proxy.GetString("name"), proxy.Server(), proxy.Port(), str(proxy.Get("password"))))
	if err := loonAppendTransport(result, proxy, false); err != nil {
		return "", err
	}
	result.appendIfPresent(`,skip-cert-verify=`+str(proxy.Get("skip-cert-verify")), "skip-cert-verify")
	loonAppendTlsProfile(result, proxy)
	loonAppendAlpn(result, proxy)
	if isReality {
		loonAppendReality(result, proxy)
	} else {
		result.appendIfPresent(`,tls-name=`+str(proxy.Get("sni")), "sni")
		result.appendIfPresent(`,tls-cert-sha256=`+str(proxy.Get("tls-fingerprint")), "tls-fingerprint")
		result.appendIfPresent(`,tls-pubkey-sha256=`+str(proxy.Get("tls-pubkey-sha256")), "tls-pubkey-sha256")
	}
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	loonAppendBlockQuic(result, proxy)
	if proxy.GetBool("udp") {
		result.append(`,udp=true`)
	}
	loonAppendIPMode(result, proxy)
	return result.String(), nil
}

func loonAnyTLS(proxy *model.Proxy) (string, error) {
	isReality := proxy.GetMap("reality-opts") != nil
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=anytls,%s,%d,\"%s\"",
		proxy.GetString("name"), proxy.Server(), proxy.Port(), str(proxy.Get("password"))))
	for _, key := range []string{"idle-session-timeout", "max-stream-count"} {
		if isPresent(proxy, key) && isRawInteger(proxy.Get(key)) {
			result.append(`,` + key + `=` + str(proxy.Get(key)))
		}
	}
	result.appendIfPresent(`,skip-cert-verify=`+str(proxy.Get("skip-cert-verify")), "skip-cert-verify")
	loonAppendTlsProfile(result, proxy)
	loonAppendAlpn(result, proxy)
	if isReality {
		loonAppendReality(result, proxy)
	} else {
		result.appendIfPresent(`,tls-name=`+str(proxy.Get("sni")), "sni")
		result.appendIfPresent(`,tls-cert-sha256=`+str(proxy.Get("tls-fingerprint")), "tls-fingerprint")
		result.appendIfPresent(`,tls-pubkey-sha256=`+str(proxy.Get("tls-pubkey-sha256")), "tls-pubkey-sha256")
	}
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	loonAppendBlockQuic(result, proxy)
	if proxy.GetBool("udp") {
		result.append(`,udp=true`)
	}
	loonAppendIPMode(result, proxy)
	return result.String(), nil
}

// isRawInteger mirrors Number.isInteger on raw values (int types only).
func isRawInteger(v any) bool {
	switch v.(type) {
	case int, int64, json.Number:
		return true
	}
	return false
}

func loonVmess(proxy *model.Proxy) (string, error) {
	isReality := proxy.GetMap("reality-opts") != nil
	security := formatLoonVmessSecurity(proxy.GetString("cipher"))
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=vmess,%s,%d,%s,\"%s\"",
		proxy.GetString("name"), proxy.Server(), proxy.Port(), security, str(proxy.Get("uuid"))))
	if err := loonAppendTransport(result, proxy, true); err != nil {
		return "", err
	}
	result.appendIfPresent(`,over-tls=`+str(proxy.Get("tls")), "tls")
	result.appendIfPresent(`,skip-cert-verify=`+str(proxy.Get("skip-cert-verify")), "skip-cert-verify")
	if proxy.GetBool("tls") || isReality {
		loonAppendTlsProfile(result, proxy)
		loonAppendAlpn(result, proxy)
	}
	if isReality {
		loonAppendReality(result, proxy)
	} else {
		result.appendIfPresent(`,tls-name=`+str(proxy.Get("sni")), "sni")
		result.appendIfPresent(`,tls-cert-sha256=`+str(proxy.Get("tls-fingerprint")), "tls-fingerprint")
		result.appendIfPresent(`,tls-pubkey-sha256=`+str(proxy.Get("tls-pubkey-sha256")), "tls-pubkey-sha256")
	}
	if isPresent(proxy, "aead") {
		if proxy.GetBool("aead") {
			result.append(`,alterId=0`)
		} else {
			result.append(`,alterId=1`)
		}
	} else {
		result.append(`,alterId=` + str(proxy.Get("alterId")))
	}
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	loonAppendBlockQuic(result, proxy)
	if proxy.GetBool("udp") {
		result.append(`,udp=true`)
	}
	loonAppendIPMode(result, proxy)
	return result.String(), nil
}

func loonVless(proxy *model.Proxy) (string, error) {
	if encryption := proxy.GetString("encryption"); encryption != "" && encryption != "none" {
		return "", fmt.Errorf("VLESS encryption is not supported")
	}
	isXtls := false
	isReality := proxy.GetMap("reality-opts") != nil
	if isPresent(proxy, "flow") {
		if proxy.GetString("flow") == "xtls-rprx-vision" {
			isXtls = true
		} else {
			return "", fmt.Errorf("VLESS flow(%s) is not supported", str(proxy.Get("flow")))
		}
	}
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=vless,%s,%d,\"%s\"",
		proxy.GetString("name"), proxy.Server(), proxy.Port(), str(proxy.Get("uuid"))))
	if err := loonAppendTransport(result, proxy, true); err != nil {
		return "", err
	}
	result.appendIfPresent(`,over-tls=`+str(proxy.Get("tls")), "tls")
	result.appendIfPresent(`,skip-cert-verify=`+str(proxy.Get("skip-cert-verify")), "skip-cert-verify")
	if proxy.GetBool("tls") || isReality || isXtls {
		loonAppendTlsProfile(result, proxy)
		loonAppendAlpn(result, proxy)
	}
	if isXtls {
		result.appendIfPresent(`,flow=`+str(proxy.Get("flow")), "flow")
	}
	if isReality {
		loonAppendReality(result, proxy)
	} else {
		result.appendIfPresent(`,tls-name=`+str(proxy.Get("sni")), "sni")
		result.appendIfPresent(`,tls-cert-sha256=`+str(proxy.Get("tls-fingerprint")), "tls-fingerprint")
		result.appendIfPresent(`,tls-pubkey-sha256=`+str(proxy.Get("tls-pubkey-sha256")), "tls-pubkey-sha256")
	}
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	loonAppendBlockQuic(result, proxy)
	if proxy.GetBool("udp") {
		result.append(`,udp=true`)
	}
	loonAppendIPMode(result, proxy)
	return result.String(), nil
}

func loonHTTP(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	typ := "http"
	if proxy.GetBool("tls") {
		typ = "https"
	}
	result.append(fmt.Sprintf("%s=%s,%s,%d", proxy.GetString("name"), typ, proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,`+str(proxy.Get("username")), "username")
	result.appendIfPresent(`,"`+str(proxy.Get("password"))+`"`, "password")
	result.appendIfPresent(`,sni=`+str(proxy.Get("sni")), "sni")
	result.appendIfPresent(`,skip-cert-verify=`+str(proxy.Get("skip-cert-verify")), "skip-cert-verify")
	if proxy.GetBool("tls") {
		loonAppendTlsProfile(result, proxy)
		loonAppendAlpn(result, proxy)
	}
	result.appendIfPresent(`,tfo=`+str(proxy.Get("tfo")), "tfo")
	loonAppendBlockQuic(result, proxy)
	loonAppendIPMode(result, proxy)
	return result.String(), nil
}

func loonSocks5(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=socks5,%s,%d", proxy.GetString("name"), proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,`+str(proxy.Get("username")), "username")
	result.appendIfPresent(`,"`+str(proxy.Get("password"))+`"`, "password")
	result.appendIfPresent(`,over-tls=`+str(proxy.Get("tls")), "tls")
	result.appendIfPresent(`,sni=`+str(proxy.Get("sni")), "sni")
	result.appendIfPresent(`,skip-cert-verify=`+str(proxy.Get("skip-cert-verify")), "skip-cert-verify")
	if proxy.GetBool("tls") {
		loonAppendTlsProfile(result, proxy)
		loonAppendAlpn(result, proxy)
	}
	result.appendIfPresent(`,tfo=`+str(proxy.Get("tfo")), "tfo")
	loonAppendBlockQuic(result, proxy)
	if proxy.GetBool("udp") {
		result.append(`,udp=true`)
	}
	loonAppendIPMode(result, proxy)
	return result.String(), nil
}

func loonWireGuard(proxy *model.Proxy) (string, error) {
	if peers := proxy.GetArray("peers"); len(peers) > 0 {
		if first, ok := peers[0].(map[string]any); ok {
			if v, ok := first["server"]; ok {
				proxy.Set("server", v)
			}
			if v, ok := first["port"]; ok {
				proxy.Set("port", v)
			}
			if v, ok := first["ip"]; ok {
				proxy.Set("ip", v)
			}
			if v, ok := first["ipv6"]; ok {
				proxy.Set("ipv6", v)
			}
			if v, ok := first["public-key"]; ok {
				proxy.Set("public-key", v)
			}
			if v, ok := first["pre-shared-key"]; ok {
				proxy.Set("preshared-key", v)
			}
			if v, ok := first["allowed-ips"]; ok {
				proxy.Set("allowed-ips", v)
			}
			if v, ok := first["reserved"]; ok {
				proxy.Set("reserved", v)
			}
		}
	}
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=wireguard", proxy.GetString("name")))
	result.appendIfPresent(`,interface-ip=`+str(proxy.Get("ip")), "ip")
	result.appendIfPresent(`,interface-ipv6=`+str(proxy.Get("ipv6")), "ipv6")
	result.appendIfPresent(`,private-key="`+str(proxy.Get("private-key"))+`"`, "private-key")
	result.appendIfPresent(`,mtu=`+str(proxy.Get("mtu")), "mtu")
	var dnsv6, dnsValue any
	if dns := proxy.Get("dns"); dns != nil {
		if a, ok := dns.([]any); ok {
			for _, item := range a {
				s := str(item)
				if isIP(s) {
					host := strings.Trim(s, "[]")
					if strings.Contains(host, ":") {
						dnsv6 = item
					} else if dnsValue == nil {
						dnsValue = item
					}
				} else if dnsValue == nil {
					dnsValue = item
				}
			}
			if dnsValue != nil {
				proxy.Set("dns", dnsValue)
			}
			if dnsv6 != nil {
				proxy.Set("dnsv6", dnsv6)
			}
		}
	}
	result.appendIfPresent(`,dns=`+str(proxy.Get("dns")), "dns")
	result.appendIfPresent(`,dnsv6=`+str(proxy.Get("dnsv6")), "dnsv6")
	result.appendIfPresent(`,keepalive=`+str(proxy.Get("persistent-keepalive")), "persistent-keepalive")
	result.appendIfPresent(`,keepalive=`+str(proxy.Get("keepalive")), "keepalive")
	var allowedIps string
	if a, ok := proxy.Get("allowed-ips").([]any); ok {
		parts := make([]string, 0, len(a))
		for _, item := range a {
			parts = append(parts, str(item))
		}
		allowedIps = strings.Join(parts, ",")
	} else {
		allowedIps = str(proxy.Get("allowed-ips"))
	}
	var reserved string
	if a, ok := proxy.Get("reserved").([]any); ok {
		parts := make([]string, 0, len(a))
		for _, item := range a {
			parts = append(parts, str(item))
		}
		reserved = strings.Join(parts, ",")
	} else {
		reserved = str(proxy.Get("reserved"))
	}
	if reserved != "" {
		reserved = `,reserved=[` + reserved + `]`
	}
	presharedKey := str(proxy.Get("preshared-key"))
	if presharedKey == "" {
		presharedKey = str(proxy.Get("pre-shared-key"))
	}
	if presharedKey != "" {
		presharedKey = `,preshared-key="` + presharedKey + `"`
	}
	if allowedIps == "" {
		allowedIps = "0.0.0.0/0,::/0"
	}
	result.append(fmt.Sprintf(`,peers=[{public-key="%s",allowed-ips="%s",endpoint=%s:%d%s%s}]`,
		str(proxy.Get("public-key")), allowedIps, proxy.Server(), proxy.Port(), reserved, presharedKey))
	loonAppendIPMode(result, proxy)
	loonAppendBlockQuic(result, proxy)
	return result.String(), nil
}

func loonHysteria2(proxy *model.Proxy) (string, error) {
	if proxy.GetString("obfs-password") != "" && proxy.GetString("obfs") != "salamander" {
		return "", fmt.Errorf("only salamander obfs is supported")
	}
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=Hysteria2,%s,%d", proxy.GetString("name"), proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,"`+str(proxy.Get("password"))+`"`, "password")
	if isPresent(proxy, "ports") && strings.TrimSpace(str(proxy.Get("ports"))) != "" {
		result.append(`,server-ports="` + str(proxy.Get("ports")) + `"`)
	}
	if isPresent(proxy, "hop-interval") && strings.TrimSpace(str(proxy.Get("hop-interval"))) != "" {
		result.append(`,hop-interval=` + str(proxy.Get("hop-interval")))
	}
	result.appendIfPresent(`,tls-name=`+str(proxy.Get("sni")), "sni")
	result.appendIfPresent(`,tls-cert-sha256=`+str(proxy.Get("tls-fingerprint")), "tls-fingerprint")
	result.appendIfPresent(`,tls-pubkey-sha256=`+str(proxy.Get("tls-pubkey-sha256")), "tls-pubkey-sha256")
	result.appendIfPresent(`,skip-cert-verify=`+str(proxy.Get("skip-cert-verify")), "skip-cert-verify")
	loonAppendTlsProfile(result, proxy)
	loonAppendAlpn(result, proxy)
	if proxy.GetString("obfs-password") != "" && proxy.GetString("obfs") == "salamander" {
		result.append(`,salamander-password=` + str(proxy.Get("obfs-password")))
	}
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	loonAppendBlockQuic(result, proxy)
	if proxy.GetBool("udp") {
		result.append(`,udp=true`)
	}
	if isPresent(proxy, "down") {
		result.append(`,download-bandwidth=` + firstDigits(str(proxy.Get("down")), "0"))
	}
	result.appendIfPresent(`,ecn=`+str(proxy.Get("ecn")), "ecn")
	loonAppendIPMode(result, proxy)
	return result.String(), nil
}
