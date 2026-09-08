package producer

import (
	"encoding/json"
	"strconv"
	"strings"

	"substore/internal/model"
)

// Clash-family producers (Clash, Clash.Meta/Mihomo, Stash, Shadowrocket)
// mirror Sub-Store's producers/{clash,clashmeta,stash,shadowrocket}.js.
//
// Each producer first filters out proxies/features the platform cannot use,
// then normalizes the remaining fields. Output is a "proxies:" block with
// one JSON line per proxy (produceProxyListOutput).

// clashPlatform identifies which Clash-family producer is running.
type clashPlatform string

const (
	clashPlatformClash        clashPlatform = "clash"
	clashPlatformMeta         clashPlatform = "mihomo"
	clashPlatformStash        clashPlatform = "stash"
	clashPlatformShadowrocket clashPlatform = "shadowrocket"
)

// ProduceClashYAML outputs a Clash config. Clash only supports a limited set
// of protocols: ss, ssr, vmess, vless, socks5, http, snell, trojan, wireguard.
func ProduceClashYAML(proxies []*model.Proxy, options map[string]any) (string, error) {
	return clashProduce(proxies, options, clashPlatformClash, "external")
}

// ProduceClashMetaYAML outputs a Mihomo (Clash.Meta) config. Mihomo supports
// all protocols including hysteria, hysteria2, tuic, anytls, snell, ssh, etc.
func ProduceClashMetaYAML(proxies []*model.Proxy, options map[string]any) (string, error) {
	return clashProduce(proxies, options, clashPlatformMeta, "external")
}

func clashProduce(proxies []*model.Proxy, options map[string]any, platform clashPlatform, type_ string) (string, error) {
	list := clashMapProxies(proxies, options, platform, type_)
	return produceProxyListOutput(list, type_, options)
}

func clashMapProxies(proxies []*model.Proxy, options map[string]any, platform clashPlatform, type_ string) []map[string]any {
	list := make([]map[string]any, 0, len(proxies))
	for _, proxy := range proxies {
		if !clashFilter(proxy, options, platform) {
			continue
		}
		clashMap(proxy, options, platform, type_)
		list = append(list, proxy.Fields())
	}
	return list
}

func includeUnsupported(opts map[string]any) bool {
	if opts == nil {
		return false
	}
	b, _ := opts["include-unsupported-proxy"].(bool)
	return b
}

// clashFilter mirrors the filter step in each JS producer.
func clashFilter(proxy *model.Proxy, opts map[string]any, platform clashPlatform) bool {
	if includeUnsupported(opts) {
		return true
	}
	switch platform {
	case clashPlatformClash:
		return clashFilterOriginal(proxy)
	case clashPlatformMeta:
		return clashFilterMeta(proxy)
	case clashPlatformStash:
		return clashFilterStash(proxy)
	case clashPlatformShadowrocket:
		return clashFilterShadowrocket(proxy)
	}
	return true
}

// clashFilterOriginal mirrors clash.js.
func clashFilterOriginal(proxy *model.Proxy) bool {
	typ := proxy.Type()
	if !clashOriginalTypes[typ] {
		return false
	}
	if typ == "ss" && !clashOriginalSSCiphers[strings.ToLower(strings.TrimSpace(proxy.GetString("cipher")))] {
		return false
	}
	if typ == "snell" && proxy.GetInt("version") >= 4 {
		return false
	}
	if typ == "vless" && (isPresent(proxy, "flow") || proxy.GetMap("reality-opts") != nil) {
		return false
	}
	if proxy.GetString("network") == "ws" {
		if wsOpts := proxy.GetMap("ws-opts"); wsOpts != nil {
			// clash.js:59-62 uses a truthiness check.
			if isTruthy(wsOpts["v2ray-http-upgrade"]) {
				return false
			}
		}
	}
	if proxy.Has("underlying-proxy") || proxy.Has("dialer-proxy") {
		return false
	}
	return true
}

// clashFilterMeta mirrors clashmeta.js.
func clashFilterMeta(proxy *model.Proxy) bool {
	typ := proxy.Type()
	if typ == "h2-connect" {
		return false
	}
	if hasRootHeaders(proxy) && typ == "trusttunnel" {
		return false
	}
	if !supportsShadowsocksV2rayPluginMode(proxy, "websocket") {
		return false
	}
	if typ == "snell" && !isSupportedMihomoVersion(proxy.Get("version"), 1, 2, 3, 4, 5) {
		return false
	}
	if shadowTLSOpts := getMihomoShadowTlsOpts(proxy); shadowTLSOpts != nil {
		supported := []string{"ss", "snell", "vmess", "vless", "trojan", "anytls"}
		if !containsString(supported, typ) {
			return false
		}
		versions := []int{0, 1, 2, 3}
		if typ == "ss" || typ == "snell" {
			versions = []int{1, 2, 3}
		}
		if !isSupportedMihomoVersion(shadowTLSOpts["version"], versions...) {
			return false
		}
	}
	if typ == "vless" && proxy.GetString("network") == "xhttp" {
		if ds := getMapNested(proxy.Fields(), "xhttp-opts", "download-settings"); ds != nil {
			if dsShadowTLS := getMihomoShadowTlsOpts(proxyFromMap(ds)); dsShadowTLS != nil &&
				!isSupportedMihomoVersion(dsShadowTLS["version"], 0, 1, 2, 3) {
				return false
			}
		}
	}
	if hasMihomoSnellShadowTlsObfsConflict(proxy) {
		return false
	}
	if typ == "juicity" || typ == "naive" {
		return false
	}
	if typ == "ss" && !clashMetaSSCiphers[strings.ToLower(strings.TrimSpace(proxy.GetString("cipher")))] {
		return false
	}
	if typ == "anytls" {
		if network := proxy.GetString("network"); network != "" &&
			(network != "tcp" || proxy.GetMap("reality-opts") != nil) {
			return false
		}
	}
	if typ != "vless" && proxy.GetString("network") == "xhttp" {
		return false
	}
	return true
}

// clashFilterStash mirrors stash.js.
func clashFilterStash(proxy *model.Proxy) bool {
	typ := proxy.Type()
	if !clashStashTypes[typ] {
		return false
	}
	if typ == "ss" && !clashStashSSCiphers[strings.ToLower(strings.TrimSpace(proxy.GetString("cipher")))] {
		return false
	}
	if typ == "snell" && proxy.GetInt("version") >= 6 {
		return false
	}
	if !supportsShadowsocksV2rayPluginMode(proxy, "websocket") {
		return false
	}
	if typ == "vless" && proxy.GetMap("reality-opts") != nil &&
		proxy.GetString("network") != "" && proxy.GetString("network") != "tcp" {
		return false
	}
	if typ == "anytls" {
		if network := proxy.GetString("network"); network != "" &&
			(network != "tcp" || proxy.GetMap("reality-opts") != nil) {
			return false
		}
	}
	if typ != "vless" && proxy.GetString("network") == "xhttp" {
		return false
	}
	if proxy.GetString("network") == "ws" {
		if wsOpts := proxy.GetMap("ws-opts"); wsOpts != nil {
			// stash.js:88-92 uses a truthiness check.
			if isTruthy(wsOpts["v2ray-http-upgrade"]) {
				return false
			}
		}
	}
	return true
}

// clashFilterShadowrocket mirrors shadowrocket.js.
func clashFilterShadowrocket(proxy *model.Proxy) bool {
	typ := proxy.Type()
	if !supportsShadowsocksV2rayPluginMode(proxy, "websocket", "quic", "http2", "mkcp", "grpc") {
		return false
	}
	if typ == "snell" && !isRawIntegerInRange(proxy.Get("version"), 1, 6) {
		return false
	}
	if hasShadowrocketSnellShadowTlsObfsConflict(proxy) {
		return false
	}
	switch typ {
	case "tailscale", "sudoku", "naive", "openvpn", "gost-relay", "shadowquic", "zerotier":
		return false
	}
	return true
}

func proxyFromMap(m map[string]any) *model.Proxy {
	return model.ProxyFromMap(m)
}

func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func hasRootHeaders(proxy *model.Proxy) bool {
	headers := proxy.GetMap("headers")
	return headers != nil && len(headers) > 0
}

// isSupportedMihomoVersion mirrors clashmeta.js: undefined passes, blank
// fails, otherwise the trimmed value must be an integer in the list.
func isSupportedMihomoVersion(v any, supported ...int) bool {
	if v == nil {
		return true
	}
	normalized := strings.TrimSpace(str(v))
	if normalized == "" {
		return false
	}
	n, ok := parseStrictIntString(normalized)
	if !ok {
		return false
	}
	for _, s := range supported {
		if n == s {
			return true
		}
	}
	return false
}

func parseStrictIntString(s string) (int, bool) {
	if !allDigits(s) {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// getMihomoShadowTlsOpts mirrors clashmeta.js: plugin-opts when
// plugin === shadow-tls, or snell obfs-opts with mode shadow-tls.
func getMihomoShadowTlsOpts(proxy *model.Proxy) map[string]any {
	if proxy.GetString("plugin") == "shadow-tls" {
		if opts := proxy.GetMap("plugin-opts"); opts != nil {
			return opts
		}
	}
	if proxy.Type() == "snell" {
		if opts := proxy.GetMap("obfs-opts"); opts != nil {
			if str(opts["mode"]) == "shadow-tls" {
				return opts
			}
		}
	}
	return nil
}

// hasMihomoSnellShadowTlsObfsConflict mirrors clashmeta.js.
func hasMihomoSnellShadowTlsObfsConflict(proxy *model.Proxy) bool {
	return proxy.Type() == "snell" && proxy.GetString("plugin") == "shadow-tls" &&
		(isPresent(proxy, "obfs-opts.mode") ||
			isPresent(proxy, "obfs-opts.host") ||
			isPresent(proxy, "obfs-opts.path"))
}

// hasShadowrocketSnellShadowTlsObfsConflict mirrors shadowrocket.js.
func hasShadowrocketSnellShadowTlsObfsConflict(proxy *model.Proxy) bool {
	return hasMihomoSnellShadowTlsObfsConflict(proxy)
}

// isRawIntegerInRange mirrors the strict includes() checks used by
// shadowrocket.js on snell versions: only raw numeric values count.
func isRawIntegerInRange(v any, lo, hi int) bool {
	switch t := v.(type) {
	case int:
		return t >= lo && t <= hi
	case int64:
		return int(t) >= lo && int(t) <= hi
	case float64:
		if t == float64(int64(t)) {
			n := int(t)
			return n >= lo && n <= hi
		}
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i >= int64(lo) && i <= int64(hi)
		}
	}
	return false
}

// clashMap mirrors the map/normalize step in each JS producer.
func clashMap(proxy *model.Proxy, opts map[string]any, platform clashPlatform, type_ string) {
	typ := proxy.Type()

	if platform == clashPlatformMeta || platform == clashPlatformShadowrocket {
		restoreShadowTLSProxyOpts(proxy)
	}
	if platform == clashPlatformMeta {
		if proxy.GetMap("reality-opts") != nil && proxy.GetString("client-fingerprint") == "" {
			proxy.Set("client-fingerprint", "chrome")
		}
	}

	switch typ {
	case "vmess":
		if isPresent(proxy, "aead") {
			if proxy.GetBool("aead") {
				proxy.Set("alterId", 0)
			}
			proxy.Delete("aead")
		}
		if isPresent(proxy, "sni") {
			proxy.Set("servername", proxy.Get("sni"))
			proxy.Delete("sni")
		}
		if platform == clashPlatformClash || platform == clashPlatformStash {
			proxy.Set("cipher", clashVmessSecurity(proxy.GetString("cipher")))
		} else {
			proxy.Set("cipher", vmessSecurityCommon(proxy.GetString("cipher")))
		}
	case "vless":
		if isPresent(proxy, "sni") {
			proxy.Set("servername", proxy.Get("sni"))
			proxy.Delete("sni")
		}
		if platform == clashPlatformMeta && proxy.GetString("network") == "xhttp" {
			if ds := getMapNested(proxy.Fields(), "xhttp-opts", "download-settings"); ds != nil {
				// block Reality inheritance for the download stream when
				// the main stream uses Reality
				if isTruthy(ds["tls"]) && isTruthy(proxy.Get("tls")) &&
					proxy.GetMap("reality-opts") != nil && ds["reality-opts"] == nil {
					ds["reality-opts"] = map[string]any{"public-key": ""}
				}
			}
		}
	case "tuic":
		if platform == clashPlatformStash || platform == clashPlatformMeta || platform == clashPlatformShadowrocket {
			if isPresent(proxy, "alpn") {
				proxy.Set("alpn", toArray(proxy.Get("alpn")))
			} else if platform == clashPlatformStash {
				proxy.Set("alpn", []any{"h3"})
			}
			if isPresent(proxy, "tfo") && !isPresent(proxy, "fast-open") {
				proxy.Set("fast-open", proxy.Get("tfo"))
				if platform == clashPlatformStash {
					proxy.Delete("tfo")
				}
			}
			if isTokenEmpty(proxy.Get("token")) && !isPresent(proxy, "version") {
				proxy.Set("version", 5)
			}
		}
	case "hysteria":
		if platform == clashPlatformMeta || platform == clashPlatformStash || platform == clashPlatformShadowrocket {
			if isPresent(proxy, "auth_str") && !isPresent(proxy, "auth-str") {
				// clashmeta.js:221-226 / stash.js:135-141: only set('auth-str'),
				// auth_str is kept in the output.
				proxy.Set("auth-str", proxy.Get("auth_str"))
			}
			if isPresent(proxy, "alpn") {
				proxy.Set("alpn", toArray(proxy.Get("alpn")))
			}
			if isPresent(proxy, "tfo") && !isPresent(proxy, "fast-open") {
				proxy.Set("fast-open", proxy.Get("tfo"))
				if platform == clashPlatformStash {
					proxy.Delete("tfo")
				}
			}
			if platform == clashPlatformStash {
				if isPresent(proxy, "down") && !isPresent(proxy, "down-speed") {
					proxy.Set("down-speed", proxy.Get("down"))
					proxy.Delete("down")
				}
				if isPresent(proxy, "up") && !isPresent(proxy, "up-speed") {
					proxy.Set("up-speed", proxy.Get("up"))
					proxy.Delete("up")
				}
				if isPresent(proxy, "down-speed") {
					proxy.Set("down-speed", extractFirstDigits(proxy.Get("down-speed")))
				}
				if isPresent(proxy, "up-speed") {
					proxy.Set("up-speed", extractFirstDigits(proxy.Get("up-speed")))
				}
			}
		}
	case "hysteria2":
		switch platform {
		case clashPlatformStash:
			if isPresent(proxy, "password") && !isPresent(proxy, "auth") {
				proxy.Set("auth", proxy.Get("password"))
				proxy.Delete("password")
			}
			if isPresent(proxy, "tfo") && !isPresent(proxy, "fast-open") {
				proxy.Set("fast-open", proxy.Get("tfo"))
				proxy.Delete("tfo")
			}
			if isPresent(proxy, "down") && !isPresent(proxy, "down-speed") {
				proxy.Set("down-speed", proxy.Get("down"))
				proxy.Delete("down")
			}
			if isPresent(proxy, "up") && !isPresent(proxy, "up-speed") {
				proxy.Set("up-speed", proxy.Get("up"))
				proxy.Delete("up")
			}
			if isPresent(proxy, "down-speed") {
				proxy.Set("down-speed", extractFirstDigits(proxy.Get("down-speed")))
			}
			if isPresent(proxy, "up-speed") {
				proxy.Set("up-speed", extractFirstDigits(proxy.Get("up-speed")))
			}
		case clashPlatformShadowrocket:
			if isPresent(proxy, "alpn") {
				proxy.Set("alpn", toArray(proxy.Get("alpn")))
			}
			if isPresent(proxy, "tfo") && !isPresent(proxy, "fast-open") {
				proxy.Set("fast-open", proxy.Get("tfo"))
			}
		}
	case "wireguard":
		keepalive := proxy.Get("keepalive")
		if keepalive == nil {
			keepalive = proxy.Get("persistent-keepalive")
		}
		proxy.Set("keepalive", keepalive)
		proxy.Set("persistent-keepalive", keepalive)
		preshared := proxy.Get("preshared-key")
		if preshared == nil {
			preshared = proxy.Get("pre-shared-key")
		}
		proxy.Set("preshared-key", preshared)
		proxy.Set("pre-shared-key", preshared)
		if platform == clashPlatformMeta || platform == clashPlatformShadowrocket {
			proxy.Set("ip", getWireGuardAddressWithCIDR(proxy, "ipv4"))
			proxy.Set("ipv6", getWireGuardAddressWithCIDR(proxy, "ipv6"))
		}
	case "snell":
		if proxy.GetInt("version") < 3 {
			proxy.Delete("udp")
		}
		if platform == clashPlatformMeta {
			// clashmeta.js:296-311: both the plugin form and the snell
			// obfs-opts form go through getMihomoShadowTlsOpts.
			if shadowTLSOpts := getMihomoShadowTlsOpts(proxy); shadowTLSOpts != nil {
				obfsOpts := map[string]any{
					"mode":     "shadow-tls",
					"host":     shadowTLSOpts["host"],
					"password": shadowTLSOpts["password"],
					"version":  shadowTLSOpts["version"],
				}
				if shadowTLSOpts["alpn"] != nil {
					obfsOpts["alpn"] = shadowTLSOpts["alpn"]
				}
				proxy.Set("obfs-opts", obfsOpts)
				proxy.Delete("plugin")
				proxy.Delete("plugin-opts")
			}
		} else if platform == clashPlatformShadowrocket {
			// shadowrocket.js:151-163 only rebuilds from the plugin form.
			if proxy.GetString("plugin") == "shadow-tls" {
				if pluginOpts := proxy.GetMap("plugin-opts"); pluginOpts != nil {
					obfsOpts := map[string]any{
						"mode":     "shadow-tls",
						"host":     pluginOpts["host"],
						"password": pluginOpts["password"],
						"version":  pluginOpts["version"],
					}
					if pluginOpts["alpn"] != nil {
						obfsOpts["alpn"] = pluginOpts["alpn"]
					}
					proxy.Set("obfs-opts", obfsOpts)
					proxy.Delete("plugin")
					proxy.Delete("plugin-opts")
				}
			}
		}
	case "ss":
		if platform == clashPlatformShadowrocket && isShadowsocksOverTls(proxy) {
			if isPresent(proxy, "sni") {
				proxy.Set("servername", proxy.Get("sni"))
			}
		}
	case "anytls":
		if platform == clashPlatformMeta || platform == clashPlatformShadowrocket {
			if v := proxy.Get("reuse"); v != nil && !isTruthy(v) {
				proxy.Set("disable-reuse", true)
				proxy.Delete("reuse")
			}
		}
	}

	if platform == clashPlatformMeta {
		if isPresent(proxy, "plugin-opts.mux") {
			if pluginOpts := proxy.GetMap("plugin-opts"); pluginOpts != nil {
				pluginOpts["mux"] = normalizePluginMuxBooleanValue(pluginOpts["mux"])
			}
		}
	}

	clashNormalizeTransport(proxy, typ)

	if pluginOpts := proxy.GetMap("plugin-opts"); pluginOpts != nil && isTruthy(pluginOpts["tls"]) {
		if isPresent(proxy, "skip-cert-verify") {
			if !isTruthy(pluginOpts["skip-cert-verify"]) {
				pluginOpts["skip-cert-verify"] = proxy.Get("skip-cert-verify")
			}
		}
	}

	delTLS := []string{"trojan", "tuic", "hysteria", "hysteria2", "juicity", "anytls", "trusttunnel", "naive"}
	if platform == clashPlatformMeta {
		delTLS = append(delTLS, "masque", "shadowquic")
	}
	if containsString(delTLS, typ) {
		proxy.Delete("tls")
	}

	if tlsFingerprint := proxy.Get("tls-fingerprint"); isTruthy(tlsFingerprint) {
		if platform == clashPlatformStash {
			proxy.Set("server-cert-fingerprint", tlsFingerprint)
		} else {
			proxy.Set("fingerprint", tlsFingerprint)
		}
	}
	proxy.Delete("tls-fingerprint")

	if platform == clashPlatformMeta || platform == clashPlatformStash || platform == clashPlatformShadowrocket {
		if underlying := proxy.Get("underlying-proxy"); isTruthy(underlying) {
			proxy.Set("dialer-proxy", underlying)
		}
		proxy.Delete("underlying-proxy")
	}

	if isPresent(proxy, "tls") {
		if _, isBool := proxy.Get("tls").(bool); !isBool {
			proxy.Delete("tls")
		}
	}

	if platform == clashPlatformStash {
		if testURL := proxy.Get("test-url"); isTruthy(testURL) {
			proxy.Set("benchmark-url", testURL)
			proxy.Delete("test-url")
		}
		if testTimeout := proxy.Get("test-timeout"); isTruthy(testTimeout) {
			proxy.Set("benchmark-timeout", testTimeout)
			proxy.Delete("test-timeout")
		}
	}

	for _, key := range []string{"subName", "collectionName", "id", "resolved", "no-resolve", "ip-cidr", "ipv6-cidr"} {
		proxy.Delete(key)
	}

	// clashmeta.js:419 allows keeping underscore fields for internal output
	// unless opts['delete-underscore-fields'] is set; clash.js:202,
	// stash.js:342 and shadowrocket.js:290 only check type !== 'internal'.
	if type_ != "internal" ||
		(platform == clashPlatformMeta && isTruthy(opts["delete-underscore-fields"])) {
		clashDeleteNullOrUnderscore(proxy)
		deleteHttpUpgradeEarlyDataMetadata(proxy.GetMap(proxy.GetString("network") + "-opts"))
	}

	if proxy.GetString("network") == "grpc" {
		if grpcOpts := proxy.GetMap("grpc-opts"); grpcOpts != nil {
			delete(grpcOpts, "_grpc-type")
			delete(grpcOpts, "_grpc-authority")
		}
	}

	if platform == clashPlatformMeta {
		if ipVersion := proxy.GetString("ip-version"); ipVersion != "" {
			switch ipVersion {
			case "dual", "ipv4", "ipv6", "ipv4-prefer", "ipv6-prefer":
				// unchanged
			case "v4-only":
				proxy.Set("ip-version", "ipv4")
			case "v6-only":
				proxy.Set("ip-version", "ipv6")
			case "prefer-v4":
				proxy.Set("ip-version", "ipv4-prefer")
			case "prefer-v6":
				proxy.Set("ip-version", "ipv6-prefer")
			}
		}
	}
}

// clashNormalizeTransport mirrors the http/h2/ws transport opts handling
// shared by all four JS producers.
func clashNormalizeTransport(proxy *model.Proxy, typ string) {
	if (typ == "vmess" || typ == "vless") && proxy.GetString("network") == "http" {
		if httpOpts := proxy.GetMap("http-opts"); httpOpts != nil {
			if isPresent(proxy, "http-opts.path") {
				if _, isArray := httpOpts["path"].([]any); !isArray {
					httpOpts["path"] = []any{httpOpts["path"]}
				}
			}
			if headers, ok := httpOpts["headers"].(map[string]any); ok {
				if isPresent(proxy, "http-opts.headers.Host") {
					if _, isArray := headers["Host"].([]any); !isArray {
						headers["Host"] = []any{headers["Host"]}
					}
				}
			}
		}
	}
	if (typ == "vmess" || typ == "vless") && proxy.GetString("network") == "h2" {
		if h2Opts := proxy.GetMap("h2-opts"); h2Opts != nil {
			if isPresent(proxy, "h2-opts.path") {
				if path, isArray := h2Opts["path"].([]any); isArray {
					if len(path) > 0 {
						h2Opts["path"] = path[0]
					} else {
						delete(h2Opts, "path")
					}
				}
			}
			// clashmeta.js:343-354: nullish-coalesced raw value; arrays are
			// kept as-is, only non-arrays get wrapped.
			var host any
			if v := getNested(proxy, "h2-opts.host"); v != nil {
				host = v
			} else if v := getNested(proxy, "h2-opts.headers.host"); v != nil {
				host = v
			} else if v := getNested(proxy, "h2-opts.headers.Host"); v != nil {
				host = v
			}
			if isPresent(proxy, "h2-opts.host") ||
				isPresent(proxy, "h2-opts.headers.host") ||
				isPresent(proxy, "h2-opts.headers.Host") {
				if hostArr, isArr := host.([]any); isArr {
					h2Opts["host"] = hostArr
				} else {
					h2Opts["host"] = []any{host}
				}
			}
			if headers, ok := h2Opts["headers"].(map[string]any); ok {
				delete(headers, "host")
				delete(headers, "Host")
				if len(headers) == 0 {
					delete(h2Opts, "headers")
				}
			}
		}
	}
	if proxy.GetString("network") == "ws" {
		wsOpts := proxy.GetMap("ws-opts")
		if wsOpts == nil {
			wsOpts = map[string]any{}
			proxy.Set("ws-opts", wsOpts)
		}
		if str(wsOpts["path"]) == "" {
			wsOpts["path"] = "/"
		}
		normalizeWebSocketEarlyDataPath(wsOpts)
	}
}

// clashDeleteNullOrUnderscore mirrors the "for key in proxy" cleanup:
// values null (nil) or keys starting with "_" are dropped.
func clashDeleteNullOrUnderscore(proxy *model.Proxy) {
	for key, value := range proxy.Fields() {
		if value == nil || strings.HasPrefix(key, "_") {
			proxy.Delete(key)
		}
	}
}

// toArray mirrors Array.isArray(v) ? v : [v].
func toArray(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	if a, ok := v.([]string); ok {
		out := make([]any, 0, len(a))
		for _, s := range a {
			out = append(out, s)
		}
		return out
	}
	return []any{v}
}

// isTokenEmpty mirrors (!proxy.token || proxy.token.length === 0).
func isTokenEmpty(v any) bool {
	if v == nil {
		return true
	}
	switch t := v.(type) {
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case []string:
		return len(t) == 0
	}
	return false
}

// extractFirstDigits mirrors `${value}`.match(/\d+/)?.[0] || 0.
func extractFirstDigits(v any) any {
	s := str(v)
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			return s[i:j]
		}
	}
	return 0
}

// clashOriginalTypes are the proxy types Clash (not Meta) supports
// (clash.js filter).
var clashOriginalTypes = map[string]bool{
	"ss": true, "ssr": true, "vmess": true, "vless": true,
	"socks5": true, "http": true, "snell": true, "trojan": true,
	"wireguard": true,
}

// clashOriginalSSCiphers are the ciphers Clash accepts for SS (clash.js).
var clashOriginalSSCiphers = map[string]bool{
	"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true,
	"rc4-md5": true, "chacha20-ietf": true, "xchacha20": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
}

// clashMetaSSCiphers are the ciphers Mihomo accepts for SS
// (clashmeta.js, superset of Clash).
var clashMetaSSCiphers = map[string]bool{
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
	"aes-128-ccm": true, "aes-192-ccm": true, "aes-256-ccm": true,
	"aes-128-gcm-siv": true, "aes-256-gcm-siv": true,
	"chacha20-ietf": true, "chacha20": true, "xchacha20": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"chacha8-ietf-poly1305": true, "xchacha8-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
	"2022-blake3-chacha20-poly1305": true,
	"lea-128-gcm": true, "lea-192-gcm": true, "lea-256-gcm": true,
	"rabbit128-poly1305": true, "aegis-128l": true, "aegis-256": true,
	"aez-384": true, "deoxys-ii-256-128": true,
	"rc4-md5": true, "none": true,
}

// clashStashTypes are the proxy types Stash supports (stash.js filter).
var clashStashTypes = map[string]bool{
	"ss": true, "ssr": true, "vmess": true, "vless": true,
	"socks5": true, "http": true, "snell": true, "trojan": true,
	"tuic": true, "wireguard": true, "hysteria": true,
	"hysteria2": true, "ssh": true, "juicity": true,
	"anytls": true, "tailscale": true, "trusttunnel": true,
	"masque": true, "mieru": true,
}

// clashStashSSCiphers are the ciphers Stash accepts for SS (stash.js).
var clashStashSSCiphers = map[string]bool{
	"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true,
	"rc4-md5": true, "chacha20-ietf": true, "xchacha20": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
}
