package producer

import (
	"encoding/json"
	"strconv"
	"strings"

	"substore/internal/model"
)

// Egern producer, mirroring Sub-Store's producers/egern.js.
//
// The original maps each supported proxy into an Egern-specific object and
// returns produceProxyListOutput(list, type, opts): a "proxies:" block with
// one inline JSON object per proxy, each object wrapped in a single key
// named after the Egern proxy type (e.g. {"shadowsocks":{...}}) with the
// inner "type" key removed. Values that are undefined in JS are dropped by
// JSON.stringify, so this port omits nil values when building the maps.

// egernSupportedTypes mirrors the type whitelist in egern.js produce().
var egernSupportedTypes = map[string]bool{
	"http": true, "https": true, "socks5": true, "ss": true, "ssr": true,
	"trojan": true, "hysteria2": true, "vless": true, "vmess": true,
	"tuic": true, "wireguard": true, "anytls": true, "ssh": true, "snell": true,
}

// egernSSCiphers mirrors the exact SS cipher whitelist in egern.js
// (including the upstream "tbale" typo). Case-sensitive, like includes().
var egernSSCiphers = map[string]bool{
	"chacha20-ietf-poly1305": true, "chacha20-poly1305": true,
	"aes-256-gcm": true, "aes-128-gcm": true, "none": true,
	"tbale": true, "rc4": true, "rc4-md5": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true,
	"bf-cfb": true, "camellia-128-cfb": true, "camellia-192-cfb": true,
	"camellia-256-cfb": true, "cast5-cfb": true, "des-cfb": true,
	"idea-cfb": true, "rc2-cfb": true, "seed-cfb": true,
	"salsa20": true, "chacha20": true, "chacha20-ietf": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
}

// egernTransportNetworks is the vmess/vless transport whitelist.
var egernTransportNetworks = map[string]bool{
	"h2": true, "http": true, "ws": true, "tcp": true, "grpc": true,
}

// egernSSRMethods / Protocols / Obfs mirror the SSR whitelists in egern.js.
var egernSSRMethods = map[string]bool{
	"none": true, "dummy": true, "rc4-md5": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true,
	"chacha20": true, "chacha20-ietf": true, "xchacha20": true,
}

var egernSSRProtocols = map[string]bool{
	"origin": true, "auth_sha1_v4": true, "auth_aes128_md5": true,
	"auth_aes128_sha1": true, "auth_chain_a": true, "auth_chain_b": true,
}

var egernSSRObfs = map[string]bool{
	"plain": true, "http_simple": true, "http_post": true,
	"random_head": true, "tls1.2_ticket_auth": true,
	"tls1.2_ticket_fastauth": true,
}

// egernShadowTLSRootTypes mirrors the original types the shadow-tls
// post-processing block applies to (hysteria2/tuic/wireguard excluded).
var egernShadowTLSRootTypes = map[string]bool{
	"http": true, "https": true, "socks5": true, "ss": true, "ssr": true,
	"trojan": true, "vless": true, "vmess": true, "anytls": true,
	"ssh": true, "snell": true,
}

// egernBlockQuicTypes mirrors the types the block-quic block applies to
// (http/https excluded).
var egernBlockQuicTypes = map[string]bool{
	"socks5": true, "ss": true, "ssr": true, "trojan": true, "vless": true,
	"vmess": true, "wireguard": true, "tuic": true, "hysteria2": true,
	"anytls": true, "ssh": true, "snell": true,
}

// ProduceEgern outputs Egern-style proxy entries.
func ProduceEgern(proxies []*model.Proxy, options map[string]any) (string, error) {
	list := make([]map[string]any, 0, len(proxies))
	for _, p := range proxies {
		if entry := egernMapProxy(p); entry != nil {
			list = append(list, entry)
		}
	}
	return produceProxyListOutput(list, "external", options)
}

// egernMapProxy mirrors the filter + map steps of egern.js for one proxy.
// It returns nil when the original drops the proxy (filter mismatch or a
// thrown error inside the per-type mapping).
func egernMapProxy(p *model.Proxy) map[string]any {
	typ := p.Type()
	if !egernSupportedTypes[typ] {
		return nil
	}
	if !egernFilter(p, typ) {
		return nil
	}

	// `original` in egern.js is a copy taken before any mutation.
	orig := p.Clone()

	// if (proxy.tls && !proxy.sni) proxy.sni = proxy.server
	if egernTruthy(p.Get("tls")) && p.GetString("sni") == "" {
		p.Set("sni", p.Server())
	}

	out := map[string]any{}
	var outType string
	var transport map[string]any

	set := func(key string, v any) { egernSetNotNil(out, key, v) }

	switch typ {
	case "http":
		tls := egernTruthy(p.Get("tls"))
		outType = "http"
		if tls {
			outType = "https"
		}
		set("name", p.Get("name"))
		set("server", p.Get("server"))
		set("port", p.Get("port"))
		set("username", p.Get("username"))
		set("password", p.Get("password"))
		if hs := p.GetMap("headers"); hs != nil && len(hs) > 0 {
			out["headers"] = hs
		}
		out["tfo"] = egernGetTfo(p)
		if tls {
			set("sni", p.Get("sni"))
			set("skip_tls_verify", p.Get("skip-cert-verify"))
			if r := egernGetReality(p); r != nil {
				out["reality"] = r
			}
		}

	case "https":
		outType = "https"
		set("name", p.Get("name"))
		set("server", p.Get("server"))
		set("port", p.Get("port"))
		set("username", p.Get("username"))
		set("password", p.Get("password"))
		if hs := p.GetMap("headers"); hs != nil && len(hs) > 0 {
			out["headers"] = hs
		}
		out["tfo"] = egernGetTfo(p)
		set("sni", p.Get("sni"))
		set("skip_tls_verify", p.Get("skip-cert-verify"))
		if r := egernGetReality(p); r != nil {
			out["reality"] = r
		}

	case "socks5":
		tls := egernTruthy(p.Get("tls"))
		outType = "socks5"
		if tls {
			outType = "socks5_tls"
		}
		set("name", p.Get("name"))
		set("server", p.Get("server"))
		set("port", p.Get("port"))
		set("username", p.Get("username"))
		set("password", p.Get("password"))
		out["tfo"] = egernGetTfo(p)
		if ur := egernGetUdpRelay(p); ur != nil {
			out["udp_relay"] = ur
		}
		if tls {
			set("sni", p.Get("sni"))
			set("skip_tls_verify", p.Get("skip-cert-verify"))
			if r := egernGetReality(p); r != nil {
				out["reality"] = r
			}
		}

	case "ss":
		outType = "shadowsocks"
		if c := p.Get("cipher"); c != nil {
			if strAny(c) == "chacha20-ietf-poly1305" {
				out["method"] = "chacha20-poly1305"
			} else {
				out["method"] = c
			}
		}
		set("name", p.Get("name"))
		set("server", p.Get("server"))
		set("port", p.Get("port"))
		set("password", p.Get("password"))
		out["tfo"] = egernGetTfo(p)
		if ur := egernGetUdpRelay(p); ur != nil {
			out["udp_relay"] = ur
		}
		if plugin := orig.Get("plugin"); plugin != nil {
			switch strAny(plugin) {
			case "obfs":
				opts := orig.GetMap("plugin-opts")
				if opts == nil {
					// JS throws on missing plugin-opts -> proxy dropped
					return nil
				}
				set("obfs", opts["mode"])
				set("obfs_host", opts["host"])
				set("obfs_uri", opts["path"])
			case "shadow-tls":
				// handled by the shadow_tls post-processing block
			default:
				// JS throws "plugin ... is not supported"
				return nil
			}
		}

	case "ssr":
		outType = "shadowsocksr"
		set("name", p.Get("name"))
		set("method", egernNormalizeSsrMethod(p.Get("cipher")))
		set("server", p.Get("server"))
		set("port", p.Get("port"))
		set("password", p.Get("password"))
		set("protocol", egernNormalizeSsrPlugin(p.Get("protocol")))
		set("protocol_param", p.Get("protocol-param"))
		set("obfs", egernNormalizeSsrPlugin(p.Get("obfs")))
		set("obfs_param", p.Get("obfs-param"))
		out["tfo"] = egernGetTfo(p)
		if ur := egernGetUdpRelay(p); ur != nil {
			out["udp_relay"] = ur
		}

	case "hysteria2":
		outType = "hysteria2"
		set("name", p.Get("name"))
		set("server", p.Get("server"))
		set("port", p.Get("port"))
		set("auth", p.Get("password"))
		if isPresent(p, "up") {
			bandwidth := 0
			if n, ok := egernFirstDigitRun(strAny(p.Get("up"))); ok {
				bandwidth = n
			}
			out["bandwidth"] = bandwidth
		}
		out["tfo"] = egernGetTfo(p)
		if ur := egernGetUdpRelay(p); ur != nil {
			out["udp_relay"] = ur
		}
		set("sni", p.Get("sni"))
		set("skip_tls_verify", p.Get("skip-cert-verify"))
		set("port_hopping", p.Get("ports"))
		set("port_hopping_interval", p.Get("hop-interval"))
		if pw := orig.Get("obfs-password"); egernTruthy(pw) &&
			strAny(orig.Get("obfs")) == "salamander" {
			out["obfs"] = "salamander"
			set("obfs_password", pw)
		}

	case "tuic":
		outType = "tuic"
		set("name", p.Get("name"))
		set("server", p.Get("server"))
		set("port", p.Get("port"))
		set("uuid", p.Get("uuid"))
		set("password", p.Get("password"))
		set("sni", p.Get("sni"))
		// alpn: Array.isArray(alpn) ? alpn : [alpn || 'h3']
		if arr := p.GetArray("alpn"); arr != nil {
			out["alpn"] = arr
		} else if v := p.Get("alpn"); v != nil && egernTruthy(v) {
			out["alpn"] = []any{v}
		} else {
			out["alpn"] = []any{"h3"}
		}
		set("skip_tls_verify", p.Get("skip-cert-verify"))
		set("port_hopping", p.Get("ports"))
		set("port_hopping_interval", p.Get("hop-interval"))

	case "trojan":
		outType = "trojan"
		var websocket map[string]any
		if p.GetString("network") == "ws" {
			websocket = map[string]any{}
			if v := getNested(p, "ws-opts.path"); v != nil {
				websocket["path"] = v
			}
			if v := getNested(p, "ws-opts.headers.Host"); v != nil {
				websocket["host"] = v
			}
		}
		set("name", p.Get("name"))
		set("server", p.Get("server"))
		set("port", p.Get("port"))
		set("password", p.Get("password"))
		out["tfo"] = egernGetTfo(p)
		if ur := egernGetUdpRelay(p); ur != nil {
			out["udp_relay"] = ur
		}
		set("sni", p.Get("sni"))
		set("skip_tls_verify", p.Get("skip-cert-verify"))
		if r := egernGetReality(p); r != nil {
			out["reality"] = r
		}
		if websocket != nil {
			out["websocket"] = websocket
		}

	case "anytls":
		outType = "anytls"
		set("name", p.Get("name"))
		set("server", p.Get("server"))
		set("port", p.Get("port"))
		set("password", p.Get("password"))
		out["tfo"] = egernGetTfo(p)
		if ur := egernGetUdpRelay(p); ur != nil {
			out["udp_relay"] = ur
		}
		set("sni", p.Get("sni"))
		set("skip_tls_verify", p.Get("skip-cert-verify"))
		if r := egernGetReality(p); r != nil {
			out["reality"] = r
		}

	case "vmess":
		outType = "vmess"
		network := p.GetString("network")
		tls := egernTruthy(p.Get("tls"))
		switch {
		case network == "ws":
			transport = egernWsTransport(p, tls)
		case network == "http":
			transport = egernHttp1Transport(p)
		case network == "h2":
			transport = egernHttp2Transport(p)
		case network == "grpc":
			transport = map[string]any{"grpc": egernGrpcTransport(p)}
		case (network == "tcp" || network == "") && tls:
			inner := map[string]any{}
			egernSetNotNil(inner, "sni", p.Get("sni"))
			egernSetNotNil(inner, "skip_tls_verify", p.Get("skip-cert-verify"))
			transport = map[string]any{"tls": inner}
		}
		legacy := false
		if aead := p.Get("aead"); aead != nil && !egernTruthy(aead) {
			legacy = true
		} else if aid := p.Get("alterId"); aid != nil && egernStrictNonZero(aid) {
			legacy = true
		}
		set("name", p.Get("name"))
		set("server", p.Get("server"))
		set("port", p.Get("port"))
		set("user_id", p.Get("uuid"))
		out["security"] = vmessSecurityCommon(p.GetString("cipher"))
		out["tfo"] = egernGetTfo(p)
		out["legacy"] = legacy
		if ur := egernGetUdpRelay(p); ur != nil {
			out["udp_relay"] = ur
		}
		if transport != nil {
			out["transport"] = transport
		}

	case "vless":
		if e := p.GetString("encryption"); e != "" && e != "none" {
			// JS throws "VLESS encryption is not supported"
			return nil
		}
		outType = "vless"
		network := p.GetString("network")
		tls := egernTruthy(p.Get("tls"))
		var flow any
		switch {
		case network == "ws":
			transport = egernWsTransport(p, tls)
		case network == "http":
			transport = egernHttp1Transport(p)
		case network == "h2":
			transport = egernHttp2Transport(p)
		case network == "grpc":
			transport = map[string]any{"grpc": egernGrpcTransport(p)}
		default: // network === 'tcp' || !network (others are filtered out)
			inner := map[string]any{}
			if tls {
				egernSetNotNil(inner, "sni", p.Get("sni"))
				egernSetNotNil(inner, "skip_tls_verify", p.Get("skip-cert-verify"))
			}
			if r := egernGetReality(p); r != nil {
				inner["reality"] = r
			}
			key := "tcp"
			if tls {
				key = "tls"
			}
			transport = map[string]any{key: inner}
			flow = p.Get("flow")
			if s, ok := flow.(string); ok && s == "" {
				flow = nil
			}
		}
		set("name", p.Get("name"))
		set("server", p.Get("server"))
		set("port", p.Get("port"))
		set("user_id", p.Get("uuid"))
		set("security", p.Get("cipher"))
		out["tfo"] = egernGetTfo(p)
		if ur := egernGetUdpRelay(p); ur != nil {
			out["udp_relay"] = ur
		}
		if transport != nil {
			out["transport"] = transport
		}
		set("flow", flow)

	case "wireguard":
		outType = "wireguard"
		if peers := p.GetArray("peers"); len(peers) > 0 {
			if peer, ok := peers[0].(map[string]any); ok {
				// JS assigns unconditionally (undefined clears the field);
				// a nil Set is equivalent for the omit-nil build below.
				p.Set("server", peer["server"])
				p.Set("port", peer["port"])
				p.Set("ip", peer["ip"])
				p.Set("ipv6", peer["ipv6"])
				p.Set("public-key", peer["public-key"])
				p.Set("preshared-key", peer["pre-shared-key"])
				p.Set("allowed-ips", peer["allowed-ips"])
				p.Set("reserved", peer["reserved"])
			}
		}
		set("name", p.Get("name"))
		if v := getWireGuardAddressWithCIDR(p, "ipv4"); v != "" {
			out["local_ipv4"] = v
		}
		if v := getWireGuardAddressWithCIDR(p, "ipv6"); v != "" {
			out["local_ipv6"] = v
		}
		set("server", p.Get("server"))
		set("port", p.Get("port"))
		set("private_key", p.Get("private-key"))
		set("peer_public_key", p.Get("public-key"))
		set("preshared_key", p.Get("preshared-key"))
		if v := p.Get("reserved"); v != nil && egernTruthy(v) {
			if arr, ok := v.([]any); ok {
				out["reserved"] = arr
			} else {
				out["reserved"] = egernSplitList(v, "/")
			}
		}
		if v := p.Get("dns"); v != nil && egernTruthy(v) {
			if arr, ok := v.([]any); ok {
				out["dns_servers"] = arr
			} else {
				out["dns_servers"] = egernSplitList(v, ",")
			}
		}
		set("mtu", p.Get("mtu"))
		set("keepalive", p.Get("keepalive"))

	case "ssh":
		outType = "ssh"
		set("name", p.Get("name"))
		set("server", p.Get("server"))
		set("port", p.Get("port"))
		set("username", p.Get("username"))
		set("password", p.Get("password"))
		set("private_key", p.Get("private-key"))
		// private_key_passphrase intentionally not produced (commented out
		// in the original).
		set("host_keys", p.Get("host-key"))
		out["tfo"] = egernGetTfo(p)

	case "snell":
		outType = "snell"
		version, hasVersion, valid := egernSnellVersion(p.Get("version"))
		if !valid {
			return nil
		}
		set("name", p.Get("name"))
		set("server", p.Get("server"))
		set("port", p.Get("port"))
		set("psk", p.Get("psk"))
		if hasVersion {
			out["version"] = version
		}
		if !hasVersion || version >= 3 {
			if ur := egernGetUdpRelay(p); ur != nil {
				out["udp_relay"] = ur
			}
		}
		set("reuse", p.Get("reuse"))
		set("obfs", egernFirstTruthy(getNested(p, "obfs-opts.mode"), p.Get("obfs")))
		set("obfs_host", egernFirstTruthy(getNested(p, "obfs-opts.host"),
			p.Get("obfs-host"), p.Get("obfs_host")))
		out["tfo"] = egernGetTfo(p)
	}

	// shadow-tls plugin post-processing
	if egernShadowTLSRootTypes[typ] {
		if strAny(orig.Get("plugin")) == "shadow-tls" {
			if opts := orig.GetMap("plugin-opts"); opts != nil {
				if !egernIsLooseThree(opts["version"]) {
					// JS throws "shadow-tls version ... is not supported"
					return nil
				}
				st := map[string]any{}
				egernSetNotNil(st, "password", opts["password"])
				egernSetNotNil(st, "sni", opts["host"])
				out["shadow_tls"] = st
			}
		}
	}

	// tls-fingerprint -> fingerprint_sha256
	fingerprint := egernGetFingerprintSha256(orig)
	if fingerprint != "" {
		if egernSupportsRootFingerprintSha256(typ, outType) {
			out["fingerprint_sha256"] = fingerprint
		}
		if t, ok := out["transport"].(map[string]any); ok {
			for _, k := range []string{"grpc", "http2", "tls", "wss"} {
				if inner, ok := t[k].(map[string]any); ok {
					inner["fingerprint_sha256"] = fingerprint
				}
			}
		}
	}

	// block-quic
	if egernBlockQuicTypes[typ] {
		if v, ok := egernBlockQuicValue(orig.Get("block-quic")); ok {
			out["block_quic"] = v
		}
	}

	// udp_port for ss/ssr + shadow-tls
	if (typ == "ss" || typ == "ssr") && out["shadow_tls"] != nil {
		if n := orig.GetInt("udp-port"); n > 0 && n <= 65535 {
			out["udp_port"] = n
		}
	}

	// transport cleanup: drop non-grpc entries that are empty (all values
	// null in the original; nil values are omitted here, so an empty map is
	// equivalent), then drop the transport itself when nothing remains.
	if t, ok := out["transport"].(map[string]any); ok {
		for k, v := range t {
			if k == "grpc" {
				continue
			}
			inner, isMap := v.(map[string]any)
			if !isMap || len(inner) == 0 {
				delete(t, k)
			}
		}
		if len(t) == 0 {
			delete(out, "transport")
		}
	}

	// prev_hop (truthy fallback chain, computed from the original proxy)
	if v := egernPrevHop(orig); v != nil {
		out["prev_hop"] = v
	}

	// { [proxy.type]: { ...proxy, type: undefined, prev_hop } }
	return map[string]any{outType: out}
}

// egernFilter mirrors the filter step in egern.js produce().
func egernFilter(p *model.Proxy, typ string) bool {
	switch typ {
	case "ss":
		if p.GetString("plugin") == "obfs" {
			mode := strAny(getNested(p, "plugin-opts.mode"))
			if mode != "http" && mode != "tls" {
				return false
			}
		}
		if !egernSSCiphers[p.GetString("cipher")] {
			return false
		}
	case "vmess", "vless":
		network := p.GetString("network")
		if network != "" && !egernTransportNetworks[network] {
			return false
		}
		if !egernGrpcGun(p) {
			return false
		}
		if typ == "vless" {
			// typeof flow !== 'undefined' && flow not in ['xtls-rprx-vision','']
			if v := p.Get("flow"); v != nil {
				s, isStr := v.(string)
				if !isStr || (s != "xtls-rprx-vision" && s != "") {
					return false
				}
			}
		}
	case "trojan":
		network := p.GetString("network")
		if network != "" && network != "http" && network != "ws" && network != "tcp" {
			return false
		}
	case "tuic":
		// proxy.token && proxy.token.length !== 0
		if tok := p.Get("token"); tok != nil {
			switch t := tok.(type) {
			case string:
				if t != "" {
					return false
				}
			case []any:
				if len(t) != 0 {
					return false
				}
			default:
				if egernTruthy(tok) {
					return false
				}
			}
		}
	case "snell":
		if _, _, ok := egernSnellVersion(p.Get("version")); !ok {
			return false
		}
	case "ssr":
		if !egernSsrSupported(p) {
			return false
		}
	case "anytls":
		if n := p.GetString("network"); n != "" && n != "tcp" {
			return false
		}
	}
	// ws + v2ray-http-upgrade is unsupported
	if p.GetString("network") == "ws" {
		if wsOpts := p.GetMap("ws-opts"); wsOpts != nil &&
			egernTruthy(wsOpts["v2ray-http-upgrade"]) {
			return false
		}
	}
	return true
}

// egernGetTfo mirrors getTfo: !!(proxy.tfo ?? proxy['fast-open']).
func egernGetTfo(p *model.Proxy) bool {
	v := p.Get("tfo")
	if v == nil {
		v = p.Get("fast-open")
	}
	return egernTruthy(v)
}

// egernGetUdpRelay mirrors getUdpRelay: proxy.udp ?? proxy.udp_relay.
func egernGetUdpRelay(p *model.Proxy) any {
	v := p.Get("udp")
	if v == nil {
		v = p.Get("udp_relay")
	}
	return v
}

// egernGetReality mirrors getReality: reality-opts -> {public_key, short_id},
// undefined when both are missing/empty.
func egernGetReality(p *model.Proxy) any {
	opts := p.GetMap("reality-opts")
	if opts == nil {
		return nil
	}
	reality := map[string]any{}
	if pk := egernNonEmptyValue(opts["public-key"]); pk != nil {
		reality["public_key"] = pk
	}
	if sid := egernNonEmptyValue(opts["short-id"]); sid != nil {
		reality["short_id"] = sid
	}
	if len(reality) == 0 {
		return nil
	}
	return reality
}

// egernNonEmptyValue mirrors getNonEmptyValue: null/undefined/"" -> undefined.
func egernNonEmptyValue(v any) any {
	if v == nil {
		return nil
	}
	if s, ok := v.(string); ok && s == "" {
		return nil
	}
	return v
}

// egernGrpcTransport mirrors getGrpcTransport.
func egernGrpcTransport(p *model.Proxy) map[string]any {
	t := map[string]any{}
	egernSetNotNil(t, "service_name", getNested(p, "grpc-opts.grpc-service-name"))
	egernSetNotNil(t, "sni", p.Get("sni"))
	if r := egernGetReality(p); r != nil {
		t["reality"] = r
	}
	egernSetNotNil(t, "skip_tls_verify", p.Get("skip-cert-verify"))
	return t
}

// egernGrpcGun mirrors isEgernGrpcGun.
func egernGrpcGun(p *model.Proxy) bool {
	if p.GetString("network") != "grpc" {
		return true
	}
	grpcType := getNested(p, "grpc-opts._grpc-type")
	if grpcType == nil {
		return true
	}
	return strings.ToLower(strings.TrimSpace(strAny(grpcType))) == "gun"
}

// egernWsTransport builds the ws/wss transport object for vmess/vless.
func egernWsTransport(p *model.Proxy, tls bool) map[string]any {
	key := "ws"
	if tls {
		key = "wss"
	}
	inner := map[string]any{}
	if v := getNested(p, "ws-opts.path"); v != nil {
		inner["path"] = v
	}
	headers := map[string]any{}
	if h := getNested(p, "ws-opts.headers.Host"); h != nil {
		headers["Host"] = h
	}
	inner["headers"] = headers
	if tls {
		egernSetNotNil(inner, "sni", p.Get("sni"))
		egernSetNotNil(inner, "skip_tls_verify", p.Get("skip-cert-verify"))
	}
	return map[string]any{key: inner}
}

// egernHttp1Transport builds the http1 transport object for vmess/vless.
func egernHttp1Transport(p *model.Proxy) map[string]any {
	inner := map[string]any{}
	egernSetNotNil(inner, "method", getNested(p, "http-opts.method"))
	egernSetNotNil(inner, "path", egernFirstOfArrayOrValue(getNested(p, "http-opts.path")))
	headers := map[string]any{}
	if h := egernFirstOfArrayOrValue(getNested(p, "http-opts.headers.Host")); h != nil {
		headers["Host"] = h
	}
	inner["headers"] = headers
	egernSetNotNil(inner, "skip_tls_verify", p.Get("skip-cert-verify"))
	return map[string]any{"http1": inner}
}

// egernHttp2Transport builds the http2 transport object for vmess/vless.
func egernHttp2Transport(p *model.Proxy) map[string]any {
	inner := map[string]any{}
	egernSetNotNil(inner, "method", getNested(p, "h2-opts.method"))
	egernSetNotNil(inner, "path", egernFirstOfArrayOrValue(getNested(p, "h2-opts.path")))
	if h := egernH2Headers(p.GetMap("h2-opts")); h != nil {
		inner["headers"] = h
	}
	egernSetNotNil(inner, "sni", p.Get("sni"))
	egernSetNotNil(inner, "skip_tls_verify", p.Get("skip-cert-verify"))
	return map[string]any{"http2": inner}
}

// egernFirstOfArrayOrValue mirrors Array.isArray(v) ? v[0] : v.
func egernFirstOfArrayOrValue(v any) any {
	if arr, ok := v.([]any); ok {
		if len(arr) > 0 {
			return arr[0]
		}
		return nil
	}
	return v
}

// egernH2Headers mirrors getH2Headers.
func egernH2Headers(h2Opts map[string]any) map[string]any {
	headers := map[string]any{}
	if hs, ok := h2Opts["headers"].(map[string]any); ok {
		for k, v := range hs {
			if strings.EqualFold(k, "host") {
				continue
			}
			if hv := egernGetFirstValue(v); hv != nil {
				headers[k] = hv
			}
		}
	}
	if host := egernH2Host(h2Opts); egernTruthy(host) {
		headers["Host"] = host
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

// egernH2Host mirrors getFirstH2Host.
func egernH2Host(h2Opts map[string]any) any {
	if v := egernGetFirstValue(h2Opts["host"]); egernTruthy(v) {
		return v
	}
	if hs, ok := h2Opts["headers"].(map[string]any); ok {
		for _, k := range []string{"host", "Host"} {
			if v := egernGetFirstValue(hs[k]); egernTruthy(v) {
				return v
			}
		}
	}
	return nil
}

// egernGetFirstValue mirrors getFirstValue.
func egernGetFirstValue(v any) any {
	if arr, ok := v.([]any); ok {
		if len(arr) > 0 {
			return arr[0]
		}
		return nil
	}
	if v == nil {
		return nil
	}
	return v
}

// egernNormalizeSsrPlugin mirrors normalizeSsrPlugin: trim + lowercase,
// null/empty -> undefined (nil).
func egernNormalizeSsrPlugin(v any) any {
	if v == nil {
		return nil
	}
	s := strings.ToLower(strings.TrimSpace(strAny(v)))
	if s == "" {
		return nil
	}
	return s
}

// egernNormalizeSsrMethod mirrors normalizeSsrMethod: 'plain' -> 'none'.
func egernNormalizeSsrMethod(cipher any) any {
	method := egernNormalizeSsrPlugin(cipher)
	if s, ok := method.(string); ok && s == "plain" {
		return "none"
	}
	return method
}

// egernSsrSupported mirrors isEgernSsr.
func egernSsrSupported(p *model.Proxy) bool {
	method, ok := egernNormalizeSsrMethod(p.Get("cipher")).(string)
	if !ok || !egernSSRMethods[method] {
		return false
	}
	// protocol / obfs may be empty: Egern fills origin / plain itself.
	if proto := egernNormalizeSsrPlugin(p.Get("protocol")); proto != nil {
		s, ok := proto.(string)
		if !ok || !egernSSRProtocols[s] {
			return false
		}
	}
	if obfs := egernNormalizeSsrPlugin(p.Get("obfs")); obfs != nil {
		s, ok := obfs.(string)
		if !ok || !egernSSRObfs[s] {
			return false
		}
	}
	return true
}

// egernSnellVersion mirrors normalizeSnellVersion. A missing value is valid
// with hasVersion=false; a value outside /^[1-5]$/ is invalid.
func egernSnellVersion(v any) (version int, hasVersion bool, valid bool) {
	if v == nil {
		return 0, false, true
	}
	s := strings.TrimSpace(strAny(v))
	if len(s) == 1 && s[0] >= '1' && s[0] <= '5' {
		return int(s[0] - '0'), true, true
	}
	return 0, false, false
}

// egernGetFingerprintSha256 mirrors getFingerprintSha256.
func egernGetFingerprintSha256(p *model.Proxy) string {
	s, ok := p.Get("tls-fingerprint").(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// egernSupportsRootFingerprintSha256 mirrors supportsRootFingerprintSha256.
func egernSupportsRootFingerprintSha256(origType, outType string) bool {
	switch origType {
	case "anytls", "https", "hysteria2", "trojan", "tuic":
		return true
	case "socks5":
		return outType == "socks5_tls"
	case "http":
		return outType == "https"
	}
	return false
}

// egernPrevHop mirrors the prev_hop truthy fallback chain.
func egernPrevHop(p *model.Proxy) any {
	for _, k := range []string{"prev_hop", "underlying-proxy", "dialer-proxy", "detour"} {
		if v := p.Get(k); egernTruthy(v) {
			return v
		}
	}
	return nil
}

// egernBlockQuicValue mirrors the includes()-based block-quic mapping
// (SameValueZero: '1' and 1 are distinct members of the respective sets).
func egernBlockQuicValue(v any) (val bool, ok bool) {
	switch t := v.(type) {
	case string:
		switch t {
		case "on", "true", "1":
			return true, true
		case "off", "false", "0":
			return false, true
		}
	case bool:
		return t, true
	case int:
		if t == 1 {
			return true, true
		}
		if t == 0 {
			return false, true
		}
	case int64:
		if t == 1 {
			return true, true
		}
		if t == 0 {
			return false, true
		}
	case float64:
		if t == 1 {
			return true, true
		}
		if t == 0 {
			return false, true
		}
	case json.Number:
		switch t.String() {
		case "1":
			return true, true
		case "0":
			return false, true
		}
	}
	return false, false
}

// egernIsLooseThree mirrors the loose `version != 3` check for shadow-tls
// (JS "3" == 3 is true).
func egernIsLooseThree(v any) bool {
	switch t := v.(type) {
	case int:
		return t == 3
	case int64:
		return t == 3
	case float64:
		return t == 3
	case json.Number:
		return t.String() == "3"
	case string:
		return t == "3"
	}
	return false
}

// egernStrictNonZero mirrors the strict proxy.alterId !== 0 check.
func egernStrictNonZero(v any) bool {
	switch t := v.(type) {
	case int:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	case json.Number:
		f, err := t.Float64()
		return err != nil || f != 0
	default:
		// strings/bools/... are !== 0 in JS
		return true
	}
}

// egernTruthy mirrors JS truthiness for the value types in play.
func egernTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
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
		f, err := t.Float64()
		return err == nil && f != 0
	default:
		return true
	}
}

// egernFirstTruthy mirrors the JS || fallback chain.
func egernFirstTruthy(vals ...any) any {
	for _, v := range vals {
		if egernTruthy(v) {
			return v
		}
	}
	return nil
}

// egernSplitList mirrors "a,b".split(/\s*,\s*/).map(trim).filter(len>0).
func egernSplitList(v any, sep string) []any {
	parts := strings.Split(strAny(v), sep)
	out := make([]any, 0, len(parts))
	for _, part := range parts {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// egernFirstDigitRun mirrors String(up).match(/\d+/)?.[0] -> parseInt.
func egernFirstDigitRun(s string) (int, bool) {
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			if start == -1 {
				start = i
			}
		} else if start != -1 {
			n, _ := strconv.Atoi(s[start:i])
			return n, true
		}
	}
	if start != -1 {
		n, _ := strconv.Atoi(s[start:])
		return n, true
	}
	return 0, false
}

func egernSetNotNil(m map[string]any, key string, v any) {
	if v != nil {
		m[key] = v
	}
}
