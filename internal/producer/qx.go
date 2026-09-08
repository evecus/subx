package producer

import (
	"encoding/hex"
	"fmt"
	"strings"

	"substore/internal/model"
)

// QX (Quantumult X) producer mirroring producers/qx.js. Each proxy becomes
// one "type=server:port,...tag=name" line; unsupported proxies are skipped.

const qxTargetPlatform = "QX"

// qxSSCiphers are the ciphers Quantumult X accepts for SS.
var qxSSCiphers = map[string]bool{
	"none": true, "rc4-md5": true, "rc4-md5-6": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true,
	"bf-cfb": true, "cast5-cfb": true, "des-cfb": true, "rc2-cfb": true,
	"salsa20": true, "chacha20": true, "chacha20-ietf": true,
	"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
}

// ProduceQX outputs Quantumult X proxy lines (one per supported proxy).
func ProduceQX(proxies []*model.Proxy, options map[string]any) (string, error) {
	var lines []string
	for _, p := range proxies {
		line, err := qxProduceLine(p)
		if err != nil {
			continue
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n"), nil
}

// qxProduceLine mirrors the wrapped produce() in qx.js.
func qxProduceLine(proxy *model.Proxy) (string, error) {
	if proxy.GetString("network") == "ws" {
		if wsOpts := proxy.GetMap("ws-opts"); wsOpts != nil {
			if b, _ := wsOpts["v2ray-http-upgrade"].(bool); b {
				return "", fmt.Errorf("Platform %s does not support network %s with http upgrade",
					qxTargetPlatform, proxy.GetString("network"))
			}
		}
	}
	var result string
	var err error
	switch proxy.Type() {
	case "ss":
		result, err = qxShadowsocks(proxy)
	case "ssr":
		result, err = qxShadowsocksR(proxy)
	case "trojan":
		result, err = qxTrojan(proxy)
	case "vmess":
		result, err = qxVmess(proxy)
	case "http":
		result, err = qxHTTP(proxy)
	case "socks5":
		result, err = qxSocks5(proxy)
	case "vless":
		result, err = qxVless(proxy)
	case "anytls":
		result, err = qxAnyTLS(proxy)
	default:
		return "", fmt.Errorf("Platform %s does not support proxy type: %s",
			qxTargetPlatform, proxy.Type())
	}
	if err != nil {
		return "", err
	}
	if flow := proxy.GetString("flow"); flow != "" && flow != "xtls-rprx-vision" {
		return "", fmt.Errorf("Platform %s does not support flow %s", qxTargetPlatform, flow)
	}
	if reality := proxy.GetMap("reality-opts"); reality != nil {
		if pk, ok := reality["public-key"]; ok && isTruthy(pk) {
			result += ",reality-base64-pubkey=" + str(pk)
		}
		if sid, ok := reality["short-id"]; ok && isTruthy(sid) {
			result += ",reality-hex-shortid=" + str(sid)
		}
	}
	return result, nil
}

// getQxHttpObfs mirrors getQxHttpObfs in qx.js.
func getQxHttpObfs(proxy *model.Proxy) string {
	token := proxy.GetString("_qx_obfs_http")
	switch token {
	case "http", "vmess-http", "vemss-http", "shadowsocks-http":
		return token
	}
	return "http"
}

// qxAppendTlsVerification mirrors appendTlsVerification in qx.js.
func qxAppendTlsVerification(result *surgeResult, proxy *model.Proxy) {
	attr := "skip-cert-verify"
	if isPresent(proxy, "name-cert-verify") {
		attr = "name-cert-verify"
	}
	value := proxy.Get("name-cert-verify")
	if value == nil {
		value = !proxy.GetBool("skip-cert-verify")
	}
	result.appendIfPresent(`,tls-verification=`+str(value), attr)
}

// qxEncodeAlpn mirrors encodeQxAlpn in qx.js: each protocol is trimmed,
// empty items dropped, then hex-encoded with a two-digit lowercase hex
// length prefix (`length.toString(16).padStart(2, '0')` + UTF-8 hex).
func qxEncodeAlpn(alpn any) (string, error) {
	var items []string
	switch t := alpn.(type) {
	case []any:
		for _, v := range t {
			items = append(items, str(v))
		}
	case []string:
		items = append(items, t...)
	default:
		items = strings.Split(str(alpn), ",")
	}
	var sb strings.Builder
	for _, item := range items {
		protocol := strings.TrimSpace(item)
		if protocol == "" {
			continue
		}
		b := []byte(protocol)
		if len(b) > 255 {
			return "", fmt.Errorf("QX ALPN protocol exceeds 255 bytes")
		}
		sb.WriteString(fmt.Sprintf("%02x", len(b)))
		sb.WriteString(hex.EncodeToString(b))
	}
	return sb.String(), nil
}

// qxAppendTlsAlpn mirrors appendTlsAlpn in qx.js: a raw tls-alpn wins;
// otherwise the alpn field is hex-encoded as a fallback.
func qxAppendTlsAlpn(result *surgeResult, proxy *model.Proxy) error {
	if isPresent(proxy, "tls-alpn") {
		result.append(`,tls-alpn=` + str(proxy.Get("tls-alpn")))
		return nil
	}
	if isPresent(proxy, "alpn") {
		encoded, err := qxEncodeAlpn(proxy.Get("alpn"))
		if err != nil {
			return err
		}
		if encoded != "" {
			result.append(`,tls-alpn=` + encoded)
		}
	}
	return nil
}

// qxAppendTlsBlock mirrors the shared tls field block in qx.js.
func qxAppendTlsBlock(result *surgeResult, proxy *model.Proxy) error {
	result.appendIfPresent(`,tls-pubkey-sha256=`+str(proxy.Get("tls-pubkey-sha256")), "tls-pubkey-sha256")
	if err := qxAppendTlsAlpn(result, proxy); err != nil {
		return err
	}
	result.appendIfPresent(`,tls-no-session-ticket=`+str(proxy.Get("tls-no-session-ticket")), "tls-no-session-ticket")
	result.appendIfPresent(`,tls-no-session-reuse=`+str(proxy.Get("tls-no-session-reuse")), "tls-no-session-reuse")
	result.appendIfPresent(`,tls-cert-sha256=`+str(proxy.Get("tls-fingerprint")), "tls-fingerprint")
	qxAppendTlsVerification(result, proxy)
	return nil
}

// qxAppendCommon mirrors the tfo / udp-relay / server_check_url / tag tail.
func qxAppendCommon(result *surgeResult, proxy *model.Proxy) {
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	result.appendIfPresent(`,server_check_url=`+str(proxy.Get("test-url")), "test-url")
	result.append(`,tag=` + proxy.GetString("name"))
}

// qxNeedTls mirrors needTls in qx.js.
func qxNeedTls(proxy *model.Proxy) bool { return proxy.GetBool("tls") }

func qxShadowsocks(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	cipher := strings.ToLower(strings.TrimSpace(proxy.GetString("cipher")))
	if cipher == "" {
		cipher = "none"
	}
	if !qxSSCiphers[cipher] {
		return "", fmt.Errorf("cipher %s is not supported", str(proxy.Get("cipher")))
	}
	isSSOverTls := isShadowsocksOverTls(proxy)
	result.append(fmt.Sprintf("shadowsocks=%s:%d", proxy.Server(), proxy.Port()))
	result.append(`,method=` + cipher)
	result.append(`,password=` + str(proxy.Get("password")))

	if qxNeedTls(proxy) {
		proxy.Set("tls", true)
	}
	if isSSOverTls {
		result.append(`,obfs=over-tls`)
		if isPresent(proxy, "sni") {
			result.append(`,obfs-host=` + str(proxy.Get("sni")))
		} else {
			result.appendIfPresent(`,obfs-host=`+str(proxy.Get("servername")), "servername")
		}
	} else if isPresent(proxy, "plugin") {
		plugin := proxy.GetString("plugin")
		opts := proxy.GetMap("plugin-opts")
		switch plugin {
		case "obfs":
			mode := ""
			if opts != nil {
				mode = str(opts["mode"])
			}
			if mode == "http" {
				result.append(`,obfs=` + getQxHttpObfs(proxy))
			} else {
				result.append(`,obfs=` + mode)
			}
		case "v2ray-plugin":
			mode := ""
			if opts != nil {
				mode = str(opts["mode"])
			}
			if mode == "websocket" {
				if opts != nil && isTruthy(opts["tls"]) {
					result.append(`,obfs=wss`)
				} else {
					result.append(`,obfs=ws`)
				}
			} else {
				return "", fmt.Errorf("plugin is not supported")
			}
		default:
			return "", fmt.Errorf("plugin is not supported")
		}
		result.appendIfPresent(`,obfs-host=`+str(getNested(proxy, "plugin-opts.host")), "plugin-opts.host")
		result.appendIfPresent(`,obfs-uri=`+str(getNested(proxy, "plugin-opts.path")), "plugin-opts.path")
	}

	if qxNeedTls(proxy) {
		if err := qxAppendTlsBlock(result, proxy); err != nil {
			return "", err
		}
		if !isSSOverTls {
			result.appendIfPresent(`,tls-host=`+str(proxy.Get("sni")), "sni")
		}
	}
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	if proxy.GetBool("_ssr_python_uot") {
		result.append(`,udp-over-tcp=true`)
	} else if proxy.GetBool("udp-over-tcp") {
		switch proxy.GetInt("udp-over-tcp-version") {
		case 0:
			result.append(`,udp-over-tcp=sp.v1`)
		case 1:
			result.append(`,udp-over-tcp=sp.v1`)
		case 2:
			result.append(`,udp-over-tcp=sp.v2`)
		}
	}
	result.appendIfPresent(`,server_check_url=`+str(proxy.Get("test-url")), "test-url")
	result.append(`,tag=` + proxy.GetString("name"))
	return result.String(), nil
}

func qxShadowsocksR(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("shadowsocks=%s:%d", proxy.Server(), proxy.Port()))
	result.append(`,method=` + str(proxy.Get("cipher")))
	result.append(`,password=` + str(proxy.Get("password")))
	result.append(`,ssr-protocol=` + jsValueOrUndefined(proxy.Get("protocol")))
	result.appendIfPresent(`,ssr-protocol-param=`+str(proxy.Get("protocol-param")), "protocol-param")
	result.appendIfPresent(`,obfs=`+str(proxy.Get("obfs")), "obfs")
	result.appendIfPresent(`,obfs-host=`+str(proxy.Get("obfs-param")), "obfs-param")
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	result.appendIfPresent(`,server_check_url=`+str(proxy.Get("test-url")), "test-url")
	result.append(`,tag=` + proxy.GetString("name"))
	return result.String(), nil
}

func qxTrojan(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("trojan=%s:%d", proxy.Server(), proxy.Port()))
	result.append(`,password=` + str(proxy.Get("password")))
	if isPresent(proxy, "network") {
		network := proxy.GetString("network")
		if network == "ws" {
			if qxNeedTls(proxy) {
				result.append(`,obfs=wss`)
			} else {
				result.append(`,obfs=ws`)
			}
			result.appendIfPresent(`,obfs-uri=`+str(getNested(proxy, "ws-opts.path")), "ws-opts.path")
			result.appendIfPresent(`,obfs-host=`+str(getNested(proxy, "ws-opts.headers.Host")), "ws-opts.headers.Host")
		} else if network != "tcp" {
			return "", fmt.Errorf("network %s is unsupported", network)
		}
	}
	if proxy.GetString("network") != "ws" && qxNeedTls(proxy) {
		result.append(`,over-tls=true`)
	}
	if qxNeedTls(proxy) {
		if err := qxAppendTlsBlock(result, proxy); err != nil {
			return "", err
		}
		result.appendIfPresent(`,tls-host=`+str(proxy.Get("sni")), "sni")
	}
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	result.appendIfPresent(`,server_check_url=`+str(proxy.Get("test-url")), "test-url")
	result.append(`,tag=` + proxy.GetString("name"))
	return result.String(), nil
}

// qxAppendTransport mirrors the shared network handling in vmess/vless.
func qxAppendTransport(result *surgeResult, proxy *model.Proxy) error {
	if !isPresent(proxy, "network") {
		if qxNeedTls(proxy) {
			result.append(`,obfs=over-tls`)
		}
		return nil
	}
	network := proxy.GetString("network")
	switch network {
	case "ws":
		if qxNeedTls(proxy) {
			result.append(`,obfs=wss`)
		} else {
			result.append(`,obfs=ws`)
		}
	case "http":
		result.append(`,obfs=` + getQxHttpObfs(proxy))
	case "tcp":
		if qxNeedTls(proxy) {
			result.append(`,obfs=over-tls`)
		}
	default:
		return fmt.Errorf("network %s is unsupported", network)
	}
	path := getNested(proxy, network+"-opts.path")
	if a, ok := path.([]any); ok && len(a) > 0 {
		path = a[0]
	}
	result.appendIfPresent(`,obfs-uri=`+str(path), network+"-opts.path")
	host := getNested(proxy, network+"-opts.headers.Host")
	if a, ok := host.([]any); ok && len(a) > 0 {
		host = a[0]
	}
	result.appendIfPresent(`,obfs-host=`+str(host), network+"-opts.headers.Host")
	return nil
}

func qxVmess(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("vmess=%s:%d", proxy.Server(), proxy.Port()))
	result.append(`,method=` + formatQXVmessMethod(proxy.GetString("cipher")))
	result.append(`,password=` + str(proxy.Get("uuid")))
	if qxNeedTls(proxy) {
		proxy.Set("tls", true)
	}
	if err := qxAppendTransport(result, proxy); err != nil {
		return "", err
	}
	if qxNeedTls(proxy) {
		if err := qxAppendTlsBlock(result, proxy); err != nil {
			return "", err
		}
		result.appendIfPresent(`,tls-host=`+str(proxy.Get("sni")), "sni")
	}
	if isPresent(proxy, "aead") {
		result.append(`,aead=` + str(proxy.Get("aead")))
	} else {
		// mirror qx.js: alterId === 0 only when the field exists and is 0;
		// a missing alterId means aead=false.
		result.append(fmt.Sprintf(`,aead=%t`, proxy.Has("alterId") && proxy.GetInt("alterId") == 0))
	}
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	result.appendIfPresent(`,server_check_url=`+str(proxy.Get("test-url")), "test-url")
	result.append(`,tag=` + proxy.GetString("name"))
	return result.String(), nil
}

func qxVless(proxy *model.Proxy) (string, error) {
	if encryption := proxy.GetString("encryption"); encryption != "" && encryption != "none" {
		return "", fmt.Errorf("VLESS encryption is not supported")
	}
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("vless=%s:%d", proxy.Server(), proxy.Port()))
	result.append(`,method=none`)
	result.append(`,password=` + str(proxy.Get("uuid")))
	if qxNeedTls(proxy) {
		proxy.Set("tls", true)
	}
	if err := qxAppendTransport(result, proxy); err != nil {
		return "", err
	}
	if qxNeedTls(proxy) {
		if err := qxAppendTlsBlock(result, proxy); err != nil {
			return "", err
		}
		result.appendIfPresent(`,tls-host=`+str(proxy.Get("sni")), "sni")
	}
	result.appendIfPresent(`,vless-flow=`+str(proxy.Get("flow")), "flow")
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	result.appendIfPresent(`,server_check_url=`+str(proxy.Get("test-url")), "test-url")
	result.append(`,tag=` + proxy.GetString("name"))
	return result.String(), nil
}

func qxAnyTLS(proxy *model.Proxy) (string, error) {
	network := strings.ToLower(strings.TrimSpace(proxy.GetString("network")))
	if network != "" && network != "tcp" {
		return "", fmt.Errorf("Platform %s does not support AnyTLS with transport %s",
			qxTargetPlatform, proxy.GetString("network"))
	}
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("anytls=%s:%d", proxy.Server(), proxy.Port()))
	result.append(`,password=` + str(proxy.Get("password")))
	proxy.Set("tls", true)
	result.append(`,over-tls=true`)
	qxAppendTlsBlock(result, proxy)
	result.appendIfPresent(`,tls-host=`+str(proxy.Get("sni")), "sni")
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	result.appendIfPresent(`,server_check_url=`+str(proxy.Get("test-url")), "test-url")
	result.append(`,tag=` + proxy.GetString("name"))
	return result.String(), nil
}

func qxHTTP(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("http=%s:%d", proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,username=`+str(proxy.Get("username")), "username")
	result.appendIfPresent(`,password=`+str(proxy.Get("password")), "password")
	if qxNeedTls(proxy) {
		proxy.Set("tls", true)
	}
	result.appendIfPresent(`,over-tls=`+str(proxy.Get("tls")), "tls")
	if qxNeedTls(proxy) {
		if err := qxAppendTlsBlock(result, proxy); err != nil {
			return "", err
		}
		result.appendIfPresent(`,tls-host=`+str(proxy.Get("sni")), "sni")
	}
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	result.appendIfPresent(`,server_check_url=`+str(proxy.Get("test-url")), "test-url")
	result.append(`,tag=` + proxy.GetString("name"))
	return result.String(), nil
}

func qxSocks5(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("socks5=%s:%d", proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,username=`+str(proxy.Get("username")), "username")
	result.appendIfPresent(`,password=`+str(proxy.Get("password")), "password")
	if qxNeedTls(proxy) {
		proxy.Set("tls", true)
	}
	result.appendIfPresent(`,over-tls=`+str(proxy.Get("tls")), "tls")
	if qxNeedTls(proxy) {
		if err := qxAppendTlsBlock(result, proxy); err != nil {
			return "", err
		}
		result.appendIfPresent(`,tls-host=`+str(proxy.Get("sni")), "sni")
	}
	result.appendIfPresent(`,fast-open=`+str(proxy.Get("tfo")), "tfo")
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	result.appendIfPresent(`,server_check_url=`+str(proxy.Get("test-url")), "test-url")
	result.append(`,tag=` + proxy.GetString("name"))
	return result.String(), nil
}
