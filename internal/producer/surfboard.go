package producer

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"substore/internal/model"
)

// Surfboard producer mirroring producers/surfboard.js. Each proxy becomes
// one "name=type,server,port,opts..." line; unsupported proxies are skipped.

const surfboardTargetPlatform = "Surfboard"

// surfboardSSCiphers are the ciphers Surfboard accepts for SS.
var surfboardSSCiphers = map[string]bool{
	"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"rc4": true, "rc4-md5": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true,
	"bf-cfb": true,
	"camellia-128-cfb": true, "camellia-192-cfb": true, "camellia-256-cfb": true,
	"salsa20": true, "chacha20": true, "chacha20-ietf": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
}

// ProduceSurfboard outputs Surfboard proxy lines (one per supported proxy).
func ProduceSurfboard(proxies []*model.Proxy, options map[string]any) (string, error) {
	var lines []string
	for _, p := range proxies {
		line, err := surfboardProduceLine(p)
		if err != nil {
			continue
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n"), nil
}

// surfboardProduceLine mirrors Surfboard_Producer().produce.
func surfboardProduceLine(proxy *model.Proxy) (string, error) {
	if proxy.GetString("network") == "ws" {
		if wsOpts := proxy.GetMap("ws-opts"); wsOpts != nil {
			if b, _ := wsOpts["v2ray-http-upgrade"].(bool); b {
				return "", fmt.Errorf("Platform %s does not support network %s with http upgrade",
					surfboardTargetPlatform, proxy.GetString("network"))
			}
		}
	}
	name := proxy.GetString("name")
	name = strings.NewReplacer("=", "", ",", "").Replace(name)
	proxy.Set("name", name)
	switch proxy.Type() {
	case "ss":
		return surfboardShadowsocks(proxy)
	case "trojan":
		return surfboardTrojan(proxy)
	case "vmess":
		return surfboardVmess(proxy)
	case "http":
		return surfboardHTTP(proxy)
	case "snell":
		return surfboardSnell(proxy)
	case "tuic":
		return surfboardTuic(proxy)
	case "socks5":
		return surfboardSocks5(proxy)
	case "hysteria2":
		return surfboardHysteria2(proxy)
	case "wireguard-surge":
		return surfboardWireGuard(proxy)
	}
	if proxy.Type() == "anytls" {
		if network := proxy.GetString("network"); network != "" &&
			(network != "tcp" || proxy.GetMap("reality-opts") != nil) {
			return "", fmt.Errorf("Platform %s does not support proxy type %s with network or REALITY",
				surfboardTargetPlatform, proxy.Type())
		}
		return surfboardAnyTLS(proxy)
	}
	return "", fmt.Errorf("Platform %s does not support proxy type: %s",
		surfboardTargetPlatform, proxy.Type())
}

// surfboardAppendTLS mirrors appendTlsProxyParams in surfboard.js (a subset
// of the Surge variant: no alpn / cert-verify-name / client-cert).
func surfboardAppendTLS(result *surgeResult, proxy *model.Proxy, enabled bool) {
	if !enabled {
		return
	}
	result.appendIfPresent(","+surfboardFingerprintKey+"="+str(proxy.Get("tls-fingerprint")), "tls-fingerprint")
	result.appendIfPresent(`,sni="`+str(proxy.Get("sni"))+`"`, "sni")
	result.appendIfPresent(","+surfboardSkipVerifyKey+"="+str(proxy.Get("skip-cert-verify")), "skip-cert-verify")
}

const (
	surfboardFingerprintKey = "server-cert-fingerprint-sha256"
	surfboardSkipVerifyKey  = "skip-cert-verify"
)

// surfboardHandleTransport mirrors handleTransport in surfboard.js.
func surfboardHandleTransport(result *surgeResult, proxy *model.Proxy) error {
	if !isPresent(proxy, "network") {
		return nil
	}
	network := proxy.GetString("network")
	if network == "ws" {
		result.append(`,ws=true`)
		if isPresent(proxy, "ws-opts") {
			result.appendIfPresent(`,ws-path=`+str(getNested(proxy, "ws-opts.path")), "ws-opts.path")
			if headers, ok := getNested(proxy, "ws-opts.headers").(map[string]any); ok && len(headers) > 0 {
				keys := make([]string, 0, len(headers))
				for k := range headers {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				parts := make([]string, 0, len(keys))
				for _, k := range keys {
					v := str(headers[k])
					if k == "Host" {
						v = `"` + v + `"`
					}
					parts = append(parts, k+":"+v)
				}
				if value := strings.Join(parts, "|"); strings.TrimSpace(value) != "" {
					result.append(`,ws-headers=` + value)
				}
			}
		}
		return nil
	}
	if network == "tcp" {
		if proxy.GetMap("reality-opts") != nil {
			return fmt.Errorf("reality is unsupported")
		}
		return nil
	}
	return fmt.Errorf("network %s is unsupported", network)
}

// surfboardTuicTokenPresent mirrors `proxy.token?.length` in surfboard.js:
// strings count by characters and arrays by elements; other types (and a
// missing field) are falsy.
func surfboardTuicTokenPresent(v any) bool {
	switch t := v.(type) {
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case []string:
		return len(t) > 0
	}
	return false
}

func surfboardTuic(proxy *model.Proxy) (string, error) {
	if surfboardTuicTokenPresent(proxy.Get("token")) {
		return "", fmt.Errorf("Platform %s does not support proxy type %s v4",
			surfboardTargetPlatform, proxy.Type())
	}
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=tuic-v5,%s,%d", proxy.GetString("name"), proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,uuid=`+str(proxy.Get("uuid")), "uuid")
	result.appendIfPresent(`,password="`+str(proxy.Get("password"))+`"`, "password")
	if alpn := formatSurgeAlpn(proxy.Get("alpn")); alpn != "" {
		result.append(`,alpn="` + alpn + `"`)
	}
	if hasNonBlankValue(proxy.Get("ports")) {
		result.append(`,port-hopping="` + strings.ReplaceAll(str(proxy.Get("ports")), ",", ";") + `"`)
	}
	if hasNonBlankValue(proxy.Get("hop-interval")) {
		result.append(`,port-hopping-interval=` + str(proxy.Get("hop-interval")))
	}
	surfboardAppendTLS(result, proxy, true)
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	return result.String(), nil
}

func surfboardHysteria2(proxy *model.Proxy) (string, error) {
	obfs := proxy.GetString("obfs")
	if (obfs != "" && obfs != "salamander") ||
		(isPresent(proxy, "obfs-password") && obfs != "salamander") {
		return "", fmt.Errorf("Surfboard Hysteria2 only supports salamander obfs")
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
	// surfboard.js:129 `if (proxy['obfs-password'])` is a truthiness check;
	// an empty string must not be emitted.
	if isTruthy(proxy.Get("obfs-password")) {
		result.append(`,salamander-password="` + str(proxy.Get("obfs-password")) + `"`)
	}
	surfboardAppendTLS(result, proxy, true)
	if isPresent(proxy, "down") {
		result.append(`,download-bandwidth=` + firstDigits(str(proxy.Get("down")), "0"))
	}
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	result.appendIfPresent(`,block-quic=`+str(proxy.Get("block-quic")), "block-quic")
	return result.String(), nil
}

func surfboardAnyTLS(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=%s,%s,%d", proxy.GetString("name"), proxy.Type(), proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,password="`+str(proxy.Get("password"))+`"`, "password")
	surfboardAppendTLS(result, proxy, true)
	result.appendIfPresent(`,tfo=`+str(proxy.Get("tfo")), "tfo")
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	result.appendIfPresent(`,reuse=`+str(proxy.Get("reuse")), "reuse")
	result.appendIfPresent(`,block-quic=`+str(proxy.Get("block-quic")), "block-quic")
	return result.String(), nil
}

func surfboardSnell(proxy *model.Proxy) (string, error) {
	if isPresent(proxy, "version") {
		v, err := strconv.Atoi(strings.TrimSpace(str(proxy.Get("version"))))
		if err != nil || v < 1 || v > 5 {
			return "", fmt.Errorf("Platform %s does not support snell version %s",
				surfboardTargetPlatform, str(proxy.Get("version")))
		}
	}
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=%s,%s,%d", proxy.GetString("name"), proxy.Type(), proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,version=`+str(proxy.Get("version")), "version")
	result.appendIfPresent(`,psk="`+str(proxy.Get("psk"))+`"`, "psk")
	result.appendIfPresent(`,obfs=`+str(getNested(proxy, "obfs-opts.mode")), "obfs-opts.mode")
	result.appendIfPresent(`,obfs-host=`+str(getNested(proxy, "obfs-opts.host")), "obfs-opts.host")
	result.appendIfPresent(`,obfs-uri=`+str(getNested(proxy, "obfs-opts.path")), "obfs-opts.path")
	result.appendIfPresent(`,tfo=`+str(proxy.Get("tfo")), "tfo")
	if proxy.GetInt("version") >= 3 {
		result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	}
	result.appendIfPresent(`,block-quic=`+str(proxy.Get("block-quic")), "block-quic")
	return result.String(), nil
}

func surfboardShadowsocks(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=%s,%s,%d", proxy.GetString("name"), proxy.Type(), proxy.Server(), proxy.Port()))
	cipher := strings.ToLower(strings.TrimSpace(proxy.GetString("cipher")))
	if !surfboardSSCiphers[cipher] {
		return "", fmt.Errorf("cipher %s is not supported", str(proxy.Get("cipher")))
	}
	result.append(`,encrypt-method=` + cipher)
	result.appendIfPresent(`,password="`+str(proxy.Get("password"))+`"`, "password")
	if isPresent(proxy, "plugin") {
		if proxy.GetString("plugin") == "obfs" {
			result.append(`,obfs=` + str(getNested(proxy, "plugin-opts.mode")))
			result.appendIfPresent(`,obfs-host=`+str(getNested(proxy, "plugin-opts.host")), "plugin-opts.host")
			result.appendIfPresent(`,obfs-uri=`+str(getNested(proxy, "plugin-opts.path")), "plugin-opts.path")
		} else {
			return "", fmt.Errorf("plugin %s is not supported", str(proxy.Get("plugin")))
		}
	}
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	result.appendIfPresent(`,block-quic=`+str(proxy.Get("block-quic")), "block-quic")
	return result.String(), nil
}

func surfboardTrojan(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=%s,%s,%d", proxy.GetString("name"), proxy.Type(), proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,password=`+str(proxy.Get("password")), "password")
	if err := surfboardHandleTransport(result, proxy); err != nil {
		return "", err
	}
	result.appendIfPresent(`,tls=`+str(proxy.Get("tls")), "tls")
	surfboardAppendTLS(result, proxy, true)
	result.appendIfPresent(`,tfo=`+str(proxy.Get("tfo")), "tfo")
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	result.appendIfPresent(`,block-quic=`+str(proxy.Get("block-quic")), "block-quic")
	return result.String(), nil
}

func surfboardVmess(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=%s,%s,%d", proxy.GetString("name"), proxy.Type(), proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,username=`+str(proxy.Get("uuid")), "uuid")
	if err := surfboardHandleTransport(result, proxy); err != nil {
		return "", err
	}
	if isPresent(proxy, "aead") {
		result.append(`,vmess-aead=` + str(proxy.Get("aead")))
	} else {
		// mirror surfboard.js: alterId === 0 only when the field exists and
		// is 0; a missing alterId means aead=false.
		result.append(fmt.Sprintf(`,vmess-aead=%t`, proxy.Has("alterId") && proxy.GetInt("alterId") == 0))
	}
	result.appendIfPresent(`,tls=`+str(proxy.Get("tls")), "tls")
	surfboardAppendTLS(result, proxy, proxy.GetBool("tls"))
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	result.appendIfPresent(`,block-quic=`+str(proxy.Get("block-quic")), "block-quic")
	return result.String(), nil
}

func surfboardHTTP(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	typ := "http"
	if proxy.GetBool("tls") {
		typ = "https"
	}
	result.append(fmt.Sprintf("%s=%s,%s,%d", proxy.GetString("name"), typ, proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,`+str(proxy.Get("username")), "username")
	result.appendIfPresent(`,`+str(proxy.Get("password")), "password")
	surfboardAppendTLS(result, proxy, proxy.GetBool("tls"))
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	result.appendIfPresent(`,block-quic=`+str(proxy.Get("block-quic")), "block-quic")
	return result.String(), nil
}

func surfboardSocks5(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	typ := "socks5"
	if proxy.GetBool("tls") {
		typ = "socks5-tls"
	}
	result.append(fmt.Sprintf("%s=%s,%s,%d", proxy.GetString("name"), typ, proxy.Server(), proxy.Port()))
	result.appendIfPresent(`,`+str(proxy.Get("username")), "username")
	result.appendIfPresent(`,`+str(proxy.Get("password")), "password")
	surfboardAppendTLS(result, proxy, proxy.GetBool("tls"))
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	result.appendIfPresent(`,block-quic=`+str(proxy.Get("block-quic")), "block-quic")
	return result.String(), nil
}

func surfboardWireGuard(proxy *model.Proxy) (string, error) {
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=wireguard", proxy.GetString("name")))
	result.appendIfPresent(`,section-name=`+str(proxy.Get("section-name")), "section-name")
	result.appendIfPresent(`,block-quic=`+str(proxy.Get("block-quic")), "block-quic")
	return result.String(), nil
}

// firstDigits mirrors `String(v).match(/\d+/)?.[0] || 0` used for Surfboard
// download-bandwidth.
func firstDigits(v, fallback string) string {
	for i := 0; i < len(v); i++ {
		if v[i] >= '0' && v[i] <= '9' {
			j := i
			for j < len(v) && v[j] >= '0' && v[j] <= '9' {
				j++
			}
			return v[i:j]
		}
	}
	return fallback
}
