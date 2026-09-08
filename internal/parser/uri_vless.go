package parser

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"substore/internal/model"
)

func init() {
	MustRegister(&Parser{
		Name: "URI VLESS Parser",
		Test: func(line string) bool { return strings.HasPrefix(line, "vless://") },
		Parse: func(line string) (*model.Proxy, error) {
			return parseVless(strings.TrimPrefix(line, "vless://"))
		},
	})
}

// vlessRe mirrors the URI_VLESS line grammar in parsers/index.js.
var vlessRe = regexp.MustCompile(`^(.*?)@(.*?):(\d+)\/?(\?(.*?))?(?:#(.*?))?$`)

// shadowrocketVlessSplitRe splits a base64-encoded Shadowrocket VLESS line
// into the base64 payload and the trailing query string.
var shadowrocketVlessSplitRe = regexp.MustCompile(`^(.*?)(\?.*)$`)

func parseVless(payload string) (*model.Proxy, error) {
	line := payload
	isShadowrocket := false
	parsed := vlessRe.FindStringSubmatch(line)
	if parsed == nil {
		m := shadowrocketVlessSplitRe.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("invalid vless link")
		}
		decoded, err := Base64Decode(m[1])
		if err != nil {
			return nil, fmt.Errorf("invalid vless link")
		}
		line = decoded + m[2]
		parsed = vlessRe.FindStringSubmatch(line)
		if parsed == nil {
			return nil, fmt.Errorf("invalid vless link")
		}
		isShadowrocket = true
	}

	uuid := parsed[1]
	server := parsed[2]
	portStr := parsed[3]
	addons := parsed[5]
	nameRaw := parsed[6]

	if isShadowrocket {
		// strip the "cipher:" prefix from the base64 user info (mirrors
		// uuid.replace(/^.*?:/g, ''))
		if idx := strings.Index(uuid, ":"); idx != -1 {
			uuid = uuid[idx+1:]
		}
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid vless port")
	}
	uuid = decodeURIComponent(uuid)
	name := ""
	if nameRaw != "" {
		name = decodeURIComponent(nameRaw)
	}

	params := map[string]string{}
	for _, addon := range strings.Split(addons, "&") {
		if addon == "" {
			continue
		}
		key := addon
		valueRaw := ""
		if sep := strings.Index(addon, "="); sep != -1 {
			key = addon[:sep]
			valueRaw = addon[sep+1:]
		}
		params[key] = decodeURIComponent(valueRaw)
	}

	p := model.NewProxy()
	p.Set("type", "vless")
	p.Set("server", server)
	p.Set("port", port)
	p.Set("uuid", uuid)
	p.Set("udp", true)
	if name != "" {
		p.Set("name", name)
	} else if remarks := params["remarks"]; remarks != "" {
		p.Set("name", remarks)
	} else if remark := params["remark"]; remark != "" {
		p.Set("name", remark)
	} else {
		p.Set("name", fmt.Sprintf("VLESS %s:%s", server, portStr))
	}

	if sec := params["security"]; sec != "" {
		p.Set("tls", sec != "none")
	}
	if params["pbk"] != "" {
		params["security"] = "reality"
	}
	if isShadowrocket && trueBool(params["tls"]) {
		p.Set("tls", true)
		if params["security"] == "" {
			params["security"] = "reality"
		}
	}
	if sni := params["sni"]; sni != "" {
		p.Set("sni", sni)
	} else if peer := params["peer"]; peer != "" {
		p.Set("sni", peer)
	}
	flow := params["flow"]
	if flow == "" && isShadowrocket && params["xtls"] != "" {
		// "none" is undefined
		switch params["xtls"] {
		case "1":
			flow = "xtls-rprx-direct"
		case "2":
			flow = "xtls-rprx-vision"
		}
	}
	if flow != "" {
		p.Set("flow", flow)
	}
	if fp := params["fp"]; fp != "" {
		p.Set("client-fingerprint", fp)
	}
	if alpn := params["alpn"]; alpn != "" {
		p.Set("alpn", strings.Split(alpn, ","))
	}
	p.Set("skip-cert-verify", trueBool(params["allowInsecure"]))
	if ech := params["ech"]; ech != "" {
		p.Set("_echConfigList", ech)
	}
	if echOpts := buildMihomoEchOptsFromXrayFields(params["ech"], "", ""); echOpts != nil {
		p.Set("ech-opts", echOpts)
	}
	if pcs := params["pcs"]; pcs != "" {
		p.Set("tls-fingerprint", pcs)
	}
	if vcn := params["vcn"]; vcn != "" {
		var vcnList []any
		for _, item := range strings.Split(vcn, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				vcnList = append(vcnList, item)
			}
		}
		if len(vcnList) > 0 {
			p.Set("_vcn", vcnList)
			p.Set("name-cert-verify", vcnList[0])
		}
	}
	p.Set("_h2", trueBool(params["h2"]))

	switch strings.ToLower(strings.TrimSpace(params["packetEncoding"])) {
	case "none":
		p.Set("packet-encoding", "")
	case "packet":
		p.Set("packet-encoding", "packetaddr")
	default:
		p.Set("packet-encoding", "xudp")
	}

	if params["security"] == "reality" {
		opts := map[string]any{}
		if v := params["pbk"]; v != "" {
			opts["public-key"] = v
		}
		if v := params["sid"]; v != "" {
			opts["short-id"] = v
		}
		if v := params["spx"]; v != "" {
			opts["_spider-x"] = v
		}
		if len(opts) > 0 {
			p.Set("reality-opts", opts)
		}
	}

	httpupgrade := false
	network := params["type"]
	if network == "" {
		network = "tcp"
	}
	if network == "tcp" && params["headerType"] == "http" {
		network = "http"
	} else if network == "http" {
		network = "h2"
	} else if network == "httpupgrade" {
		network = "ws"
		httpupgrade = true
	}
	if params["type"] == "" && isShadowrocket && params["obfs"] != "" {
		network = params["obfs"]
		if network == "none" {
			network = "tcp"
		}
	}
	if network == "websocket" {
		network = "ws"
	}
	p.Set("network", network)

	if network != "tcp" && network != "none" {
		opts := map[string]any{}
		pathEarlyData := ""
		host := params["host"]
		if host == "" {
			host = params["obfsParam"]
		}
		if host != "" {
			if params["obfsParam"] != "" {
				var parsedHeaders map[string]any
				if err := json.Unmarshal([]byte(host), &parsedHeaders); err == nil {
					opts["headers"] = parsedHeaders
				} else {
					opts["headers"] = map[string]any{"Host": host}
				}
			} else {
				opts["headers"] = map[string]any{"Host": host}
			}
			if headers, ok := opts["headers"].(map[string]any); ok {
				if network == "xhttp" {
					if hostVal, ok := headers["Host"].(string); ok {
						opts["host"] = hostVal
						delete(headers, "Host")
						if len(headers) == 0 {
							delete(opts, "headers")
						}
					}
				}
				if network == "h2" {
					h2Host, ok := headers["Host"].(string)
					if !ok {
						h2Host, _ = headers["host"].(string)
					}
					if h2Host != "" {
						opts["host"] = splitURIHostList(h2Host)
						delete(headers, "Host")
						delete(headers, "host")
						if len(headers) == 0 {
							delete(opts, "headers")
						}
					}
				}
			}
		}
		if serviceName := params["serviceName"]; serviceName != "" {
			opts[network+"-service-name"] = serviceName
			if network == "grpc" && params["authority"] != "" {
				opts["_grpc-authority"] = params["authority"]
			}
		} else if isShadowrocket && params["path"] != "" {
			if network != "ws" && network != "http" && network != "h2" {
				opts[network+"-service-name"] = params["path"]
			}
		}
		if path := params["path"]; path != "" {
			transportPath := path
			if network == "ws" {
				extractedPath, ed := extractEarlyDataFromPath(path)
				transportPath = extractedPath
				pathEarlyData = ed
			}
			opts["path"] = transportPath
		} else if network == "h2" {
			opts["path"] = "/"
		}
		if network == "http" && params["method"] != "" {
			opts["method"] = params["method"]
		}
		if network == "grpc" {
			mode := params["mode"]
			if mode == "" {
				mode = "gun"
			}
			opts["_grpc-type"] = mode
		}
		if httpupgrade {
			opts["v2ray-http-upgrade"] = true
		}
		earlyDataRaw := pathEarlyData
		if earlyDataRaw == "" {
			earlyDataRaw = params["ed"]
		}
		if earlyDataRaw != "" {
			maxEarlyData, err := parseEarlyDataSizeStrict(earlyDataRaw)
			if err != nil {
				return nil, err
			}
			if httpupgrade {
				opts["v2ray-http-upgrade-fast-open"] = true
				opts["_v2ray-http-upgrade-ed"] = earlyDataRaw
			} else if network == "ws" {
				opts["max-early-data"] = maxEarlyData
				eh := params["eh"]
				if eh == "" {
					eh = "Sec-WebSocket-Protocol"
				}
				opts["early-data-header-name"] = eh
			}
		}
		if eh := params["eh"]; eh != "" && (network == "ws" || httpupgrade) {
			opts["early-data-header-name"] = eh
		}
		if len(opts) > 0 {
			p.Set(network+"-opts", opts)
		}
		if network == "kcp" {
			if seed := params["seed"]; seed != "" {
				p.Set("seed", seed)
			}
			headerType := params["headerType"]
			if headerType == "" {
				headerType = "none"
			}
			p.Set("headerType", headerType)
		}
		if extra := params["extra"]; extra != "" && network != "xhttp" {
			p.Set("_extra", extra)
		}
		if network == "xhttp" {
			var extra any = map[string]any{}
			invalidRawExtra := ""
			if extraStr := params["extra"]; extraStr != "" {
				if err := json.Unmarshal([]byte(extraStr), &extra); err != nil {
					invalidRawExtra = extraStr
				}
			}
			xhttpOpts := opts
			if mode := params["mode"]; mode != "" {
				xhttpOpts["mode"] = mode
			}
			applyXhttpExtraFields(xhttpOpts, extra)
			if extraMap, ok := extra.(map[string]any); ok {
				if downloadSettings := parseDownloadSettings(extraMap["downloadSettings"]); downloadSettings != nil {
					xhttpOpts["download-settings"] = downloadSettings
				}
			}
			if len(xhttpOpts) > 0 {
				p.Set("xhttp-opts", xhttpOpts)
			}
			if invalidRawExtra != "" {
				p.Set("_extra", invalidRawExtra)
			}
			if unsupportedExtra := collectUnsupportedRootXhttpExtra(extra); unsupportedExtra != nil {
				p.Set("_extra_unsupported", unsupportedExtra)
			}
		} else if mode := params["mode"]; mode != "" {
			p.Set("_mode", mode)
		}
	}

	if encryption := params["encryption"]; encryption != "" {
		p.Set("encryption", encryption)
	}
	if pqv := params["pqv"]; pqv != "" {
		p.Set("_pqv", pqv)
	}
	return p, nil
}

func init() {
	MustRegister(&Parser{
		Name: "URI Trojan Parser",
		Test: func(line string) bool { return strings.HasPrefix(line, "trojan://") },
		Parse: func(line string) (*model.Proxy, error) {
			return parseTrojan(line)
		},
	})
}

// trojanWrapperRe mirrors the port-presence check of Sub-Store URI_Trojan.
var trojanWrapperRe = regexp.MustCompile(`^(trojan://.*?@.*?)(:(\d+))?/?(\?.*?)?$`)

// trojanRe mirrors the peggy trojan-uri grammar.
var trojanRe = regexp.MustCompile(`^trojan://([^@]+)@(\[[^\]]+\]|[^/?#]+):(\d+)(?:/)?(?:\?([^#]*))?(?:#(.*))?$`)

// unsafePathSegments mirrors trojan-uri.js's prototype-pollution guard.
var unsafePathSegments = map[string]bool{"__proto__": true, "constructor": true, "prototype": true}

func checkUnsafePath(key string) bool {
	for _, seg := range regexp.MustCompile(`[^.[\]]+`).FindAllString(key, -1) {
		if unsafePathSegments[seg] {
			return true
		}
	}
	return false
}

func parseTrojan(line string) (*model.Proxy, error) {
	// URI_Trojan: append ":443" when the link carries no port.
	m := trojanWrapperRe.FindStringSubmatch(line)
	if m != nil && m[2] == "" {
		line = strings.Replace(line, m[1], m[1]+":443", 1)
	}

	// peggy trojan-uri: split name on the raw "#".
	nameRaw := ""
	newLine := line
	if idx := strings.Index(line, "#"); idx != -1 {
		newLine = line[:idx]
		nameRaw = line[idx+1:]
	}

	mm := trojanRe.FindStringSubmatch(newLine)
	if mm == nil {
		return nil, fmt.Errorf("invalid trojan url")
	}
	password := decodeWithFallback(mm[1])
	server := mm[2]
	portStr := mm[3]
	query := mm[4]

	normalizedServer := strings.TrimPrefix(strings.TrimSuffix(server, "]"), "[")
	if (strings.HasPrefix(server, "[") || strings.Contains(server, ":")) && !isIPv6String(normalizedServer) {
		return nil, fmt.Errorf("invalid trojan server")
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid trojan port")
	}

	p := model.NewProxy()
	p.Set("type", "trojan")
	p.Set("password", password)
	p.Set("server", server)
	p.Set("port", port)
	if nameRaw != "" {
		p.Set("name", decodeWithFallback(nameRaw))
	} else {
		p.Set("name", server+":"+portStr)
	}

	params := map[string]string{}
	if query != "" {
		for _, item := range strings.Split(query, "&") {
			separatorIndex := strings.Index(item, "=")
			key := item
			val := "true"
			if separatorIndex != -1 {
				key = item[:separatorIndex]
				val = decodeWithFallback(item[separatorIndex+1:])
			}
			params[key] = val
		}
	}

	if trueBool(params["allowInsecure"]) {
		p.Set("skip-cert-verify", true)
	}
	if sni := params["sni"]; sni != "" {
		p.Set("sni", sni)
	} else if peer := params["peer"]; peer != "" {
		p.Set("sni", peer)
	}
	if fp := params["fp"]; fp != "" {
		p.Set("client-fingerprint", fp)
	}
	if pcs := params["pcs"]; pcs != "" {
		p.Set("tls-fingerprint", pcs)
	}
	if vcn := params["vcn"]; vcn != "" {
		var vcnList []any
		for _, item := range strings.Split(vcn, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				vcnList = append(vcnList, item)
			}
		}
		if len(vcnList) > 0 {
			p.Set("_vcn", vcnList)
			p.Set("name-cert-verify", vcnList[0])
		}
	}
	if alpn := params["alpn"]; alpn != "" {
		p.Set("alpn", strings.Split(alpn, ","))
	}

	if trueBool(params["ws"]) {
		p.Set("network", "ws")
		if wspath := params["wspath"]; wspath != "" {
			p.Set("ws-opts", map[string]any{"path": wspath})
		}
	}

	if typ := params["type"]; typ != "" {
		httpupgrade := false
		httpUpgradeEd := ""
		pathEarlyData := ""
		network := typ
		if checkUnsafePath(network) {
			return nil, fmt.Errorf("unsafe property path")
		}
		if network == "httpupgrade" {
			network = "ws"
			httpupgrade = true
		}
		p.Set("network", network)

		if network == "grpc" {
			opts := map[string]any{}
			if v := params["serviceName"]; v != "" {
				opts["grpc-service-name"] = v
			}
			if v := params["mode"]; v != "" {
				opts["_grpc-type"] = v
			}
			if v := params["authority"]; v != "" {
				opts["_grpc-authority"] = v
			}
			p.Set("grpc-opts", opts)
		} else {
			if path := params["path"]; path != "" {
				if network == "ws" {
					ed := getPathQueryParam(path, "ed")
					if isNumericEarlyData(ed) {
						extractedPath, _ := extractPathQueryParam(path, "ed")
						path = extractedPath
						if httpupgrade {
							httpUpgradeEd = ed
						} else {
							pathEarlyData = ed
						}
					}
				}
				optsKey := network + "-opts"
				if checkUnsafePath(optsKey + ".path") {
					return nil, fmt.Errorf("unsafe property path")
				}
				opts := map[string]any{"path": path}
				if host := params["host"]; host != "" {
					opts["headers"] = map[string]any{"Host": host}
				}
				p.Set(optsKey, opts)
			} else if host := params["host"]; host != "" {
				if checkUnsafePath(network + "-opts.headers.Host") {
					return nil, fmt.Errorf("unsafe property path")
				}
				p.Set(network+"-opts", map[string]any{"headers": map[string]any{"Host": host}})
			}
			if httpupgrade {
				if httpUpgradeEd == "" && isNumericEarlyData(params["ed"]) {
					httpUpgradeEd = params["ed"]
				}
				wsOpts := p.Get("ws-opts")
				var m map[string]any
				if wsOpts == nil {
					m = map[string]any{}
					p.Set("ws-opts", m)
				} else {
					m = wsOpts.(map[string]any)
				}
				m["v2ray-http-upgrade"] = true
				if httpUpgradeEd != "" {
					m["v2ray-http-upgrade-fast-open"] = true
					m["_v2ray-http-upgrade-ed"] = httpUpgradeEd
				}
			} else if network == "ws" && pathEarlyData != "" {
				wsOpts := p.Get("ws-opts")
				var m map[string]any
				if wsOpts == nil {
					m = map[string]any{}
					p.Set("ws-opts", m)
				} else {
					m = wsOpts.(map[string]any)
				}
				if n, err := strconv.Atoi(pathEarlyData); err == nil {
					m["max-early-data"] = n
				}
				m["early-data-header-name"] = "Sec-WebSocket-Protocol"
			}
		}

		if params["security"] == "reality" {
			opts := map[string]any{}
			if v := params["pbk"]; v != "" {
				opts["public-key"] = v
			}
			if v := params["sid"]; v != "" {
				opts["short-id"] = v
			}
			if v := params["spx"]; v != "" {
				opts["_spider-x"] = v
			}
			if len(opts) > 0 {
				p.Set("reality-opts", opts)
			}
			if v := params["mode"]; v != "" {
				p.Set("_mode", v)
			}
			if v := params["extra"]; v != "" {
				p.Set("_extra", v)
			}
		}
	}

	if trueBool(params["udp"]) {
		p.Set("udp", true)
	}
	if trueBool(params["tfo"]) {
		p.Set("tfo", true)
	}
	return p, nil
}

func decodeWithFallback(s string) string {
	if d, err := urlUnescape(s); err == nil {
		return d
	}
	return s
}
