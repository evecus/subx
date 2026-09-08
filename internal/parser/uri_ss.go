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
		Name: "URI SS Parser",
		Test: func(line string) bool { return strings.HasPrefix(line, "ss://") },
		Parse: func(line string) (*model.Proxy, error) {
			return parseSS(strings.TrimPrefix(line, "ss://"))
		},
	})
}

// Mirrors Sub-Store URI_SS: the serverAndPort capture stops at the first
// "/", "?" or end of string when an "@" is present.
var ssServerAndPortRe = regexp.MustCompile(`@([^/?]*)(/|\?|$)`)
var ssServerAndPortRe2 = regexp.MustCompile(`@([^/@]*)(/|$)`)
var legacyUserInfoRe = regexp.MustCompile(`^(.*)@`)
var ssUserInfoRe = regexp.MustCompile(`^(.*?):(.*)$`)
var legacyV2rayPluginRe = regexp.MustCompile(`(&|\?)v2ray-plugin=(.*?)(&|$)`)
var ssUotRe = regexp.MustCompile(`(?i)(&|\?)uot=(1|true)`)
var ssTfoRe = regexp.MustCompile(`(?i)(&|\?)tfo=(1|true)`)

func parseSS(payload string) (*model.Proxy, error) {
	content, name := DecodeURIFragment(payload)
	p := model.NewProxy()
	p.Set("type", "ss")

	serverAndPortArray := ssServerAndPortRe.FindStringSubmatch(content)
	userInfoStr := decodeSSUserInfo(strings.SplitN(content, "@", 2)[0])

	query := ""
	if serverAndPortArray == nil {
		// legacy base64 form: the query must be stripped before decoding
		if strings.Contains(content, "?") {
			parsed := strings.SplitN(content, "?", 2)
			content = parsed[0]
			query = "?" + parsed[1]
		}
		decoded, err := Base64Decode(content)
		if err != nil {
			return nil, err
		}
		content = decoded
		if query != "" {
			// legacy v2ray-plugin= payloads carry base64 JSON
			if m := legacyV2rayPluginRe.FindStringSubmatch(query); m != nil {
				if d, err := Base64Decode(m[2]); err == nil {
					var opts map[string]any
					if err := json.Unmarshal([]byte(d), &opts); err == nil {
						p.Set("plugin", "v2ray-plugin")
						p.Set("plugin-opts", opts)
					}
				}
			}
			content = content + query
		}
		ui := legacyUserInfoRe.FindStringSubmatch(content)
		if len(ui) == 2 {
			userInfoStr = ui[1]
		}
		serverAndPortArray = ssServerAndPortRe2.FindStringSubmatch(content)
	} else if strings.Contains(content, "?") {
		query = content[strings.Index(content, "?"):]
	}
	if len(serverAndPortArray) < 2 {
		return nil, fmt.Errorf("invalid ss link")
	}

	// query params: valueless keys behave like the JS "undefined" string
	params := map[string]string{}
	for _, addon := range strings.Split(strings.TrimPrefix(query, "?"), "&") {
		if addon == "" {
			continue
		}
		kv := strings.SplitN(addon, "=", 2)
		key := kv[0]
		val := "undefined"
		if len(kv) == 2 {
			val = decodeURIComponent(kv[1])
		}
		params[key] = val
	}

	// security / tls
	if sec := params["security"]; sec != "" && sec != "none" {
		p.Set("tls", true)
	}
	if params["allowInsecure"] != "" {
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
	if alpn := params["alpn"]; alpn != "" {
		p.Set("alpn", strings.Split(decodeURIComponent(alpn), ","))
	}

	// bare "ws" flag
	if params["ws"] != "" {
		p.Set("network", "ws")
		opts := map[string]any{}
		if path := params["wspath"]; path != "" {
			opts["path"] = path
		}
		if len(opts) > 0 {
			p.Set("ws-opts", opts)
		}
	}

	// transport type
	if t := params["type"]; t != "" {
		httpupgrade := false
		httpUpgradeEd := ""
		pathEarlyData := ""
		network := t
		if network == "httpupgrade" {
			network = "ws"
			httpupgrade = true
		}
		p.Set("network", network)
		if network == "grpc" {
			p.Set("grpc-opts", map[string]any{
				"grpc-service-name": params["serviceName"],
				"_grpc-type":        params["mode"],
				"_grpc-authority":   params["authority"],
			})
		} else {
			opts := map[string]any{}
			if path := params["path"]; path != "" {
				tp := path
				if network == "ws" {
					extractedPath, extractedEd := extractEarlyDataFromPath(tp)
					tp = extractedPath
					if httpupgrade {
						httpUpgradeEd = extractedEd
					} else {
						pathEarlyData = extractedEd
					}
				}
				opts["path"] = tp
			}
			if host := params["host"]; host != "" {
				opts["headers"] = map[string]any{"Host": decodeURIComponent(host)}
			}
			if httpupgrade {
				if httpUpgradeEd == "" && isNumericEarlyData(params["ed"]) {
					httpUpgradeEd = params["ed"]
				}
				opts["v2ray-http-upgrade"] = true
				if httpUpgradeEd != "" {
					opts["v2ray-http-upgrade-fast-open"] = true
					opts["_v2ray-http-upgrade-ed"] = httpUpgradeEd
				}
			} else if network == "ws" && pathEarlyData != "" {
				opts["max-early-data"] = parseEarlyDataSize(pathEarlyData)
				opts["early-data-header-name"] = "Sec-WebSocket-Protocol"
			}
			p.Set(network+"-opts", opts)
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

	if params["udp"] != "" {
		p.Set("udp", true)
	}

	// server and port: port is the first digit run after the last colon
	serverAndPort := serverAndPortArray[1]
	portIdx := strings.LastIndex(serverAndPort, ":")
	var host, portStr string
	if portIdx == -1 {
		host = ""
		portStr = serverAndPort
	} else {
		host = serverAndPort[:portIdx]
		portStr = serverAndPort[portIdx+1:]
	}
	portMatch := digitRunRe.FindString(portStr)
	if portMatch == "" || host == "" {
		return nil, fmt.Errorf("invalid ss server:port")
	}
	p.Set("server", host)
	p.Set("port", portMatch)

	// cipher:password from userinfo
	ui := ssUserInfoRe.FindStringSubmatch(userInfoStr)
	if len(ui) != 3 {
		return nil, fmt.Errorf("invalid ss userinfo")
	}
	p.Set("cipher", ui[1])
	p.Set("password", ui[2])

	// plugins
	parseSSPlugins(content, query, p)

	if ssUotRe.MatchString(query) {
		p.Set("udp-over-tcp", true)
	}
	if ssTfoRe.MatchString(query) {
		p.Set("tfo", true)
	}

	if name != "" {
		p.Set("name", name)
	} else {
		p.Set("name", "SS "+host+":"+portMatch)
	}
	return p, nil
}

var digitRunRe = regexp.MustCompile(`\d+`)

func decodeSSUserInfo(raw string) string {
	// raw may be "method:password" (possibly url-encoded) or base64
	if idx := strings.Index(raw, ":"); idx != -1 {
		left := decodeURIComponent(raw[:idx])
		right := decodeURIComponent(raw[idx+1:])
		return left + ":" + right
	}
	decoded := decodeURIComponent(raw)
	if strings.Contains(decoded, ":") {
		return decoded
	}
	if d, err := Base64Decode(decoded); err == nil {
		return d
	}
	return decoded
}

func parseSSPlugins(content, query string, p *model.Proxy) {
	_ = query

	pluginMatch := pluginParamRe.FindStringSubmatch(content)
	if pluginMatch != nil {
		pluginInfo := strings.Split("plugin="+decodeURIComponent(pluginMatch[1]), ";")
		params := map[string]any{}
		for _, item := range pluginInfo {
			if item == "" {
				continue
			}
			sep := strings.Index(item, "=")
			if sep == -1 {
				params[item] = true
				continue
			}
			key := item[:sep]
			val := strings.ReplaceAll(item[sep+1:], "\\=", "=")
			if key != "" {
				// mirrors index.js:439 `params[key] = val || true`:
				// an empty value (";tls=") becomes boolean true
				if val == "" {
					params[key] = true
				} else {
					params[key] = val
				}
			}
		}
		switch params["plugin"] {
		case "obfs-local", "simple-obfs":
			p.Set("plugin", "obfs")
			opts := map[string]any{"mode": params["obfs"]}
			if host := getString(params, "obfs-host"); host != "" {
				opts["host"] = host
			}
			p.Set("plugin-opts", opts)
		case "v2ray-plugin":
			p.Set("plugin", "v2ray-plugin")
			opts := map[string]any{}
			mode := getIfNotBlank(params["obfs"])
			if mode == "" {
				mode = getIfNotBlank(params["mode"])
			}
			if mode == "" {
				mode = "websocket"
			}
			opts["mode"] = mode
			if host := getIfNotBlank(params["obfs-host"]); host != "" {
				opts["host"] = host
			} else if host := getIfNotBlank(params["host"]); host != "" {
				opts["host"] = host
			}
			if path := getIfNotBlank(params["path"]); path != "" {
				opts["path"] = path
			}
			if tlsVal, ok := params["tls"]; ok && tlsVal != "" {
				opts["tls"] = tlsVal == "true" || tlsVal == "1" || tlsVal == true
			}
			// mirrors index.js:462 `sni: getIfPresent(params.sni)`: the key
			// is written whenever present, including the boolean true
			// produced by the valueless ";sni" form
			if sni, ok := params["sni"]; ok {
				opts["sni"] = sni
			}
			// mirrors index.js:463 ['1','true',1,true].includes(...) so the
			// valueless ";skip-cert-verify" form (boolean true) also matches
			scvBool := false
			switch v := params["skip-cert-verify"].(type) {
			case bool:
				scvBool = v
			case string:
				scvBool = v == "1" || v == "true"
			}
			opts["skip-cert-verify"] = scvBool
			if mux, ok := params["mux"]; ok {
				if ms, isStr := mux.(string); isStr && digitRunRe.MatchString(ms) && ms == digitRunRe.FindString(ms) {
					if n, err := strconv.Atoi(ms); err == nil {
						opts["mux"] = n
					}
				}
			}
			p.Set("plugin-opts", opts)
		case "shadow-tls":
			p.Set("plugin", "shadow-tls")
			opts := map[string]any{}
			if host := getIfNotBlank(params["host"]); host != "" {
				opts["host"] = host
			}
			if password := getIfNotBlank(params["password"]); password != "" {
				opts["password"] = password
			}
			if version := getIfNotBlank(params["version"]); version != "" {
				if n, err := strconv.Atoi(version); err == nil {
					opts["version"] = n
				}
			}
			p.Set("plugin-opts", opts)
		default:
			return
		}
	}

	// shadow-tls=... (Shadowrocket style, base64 JSON, not percent-decoded)
	if m := shadowTlsPayloadRe.FindStringSubmatch(content); m != nil {
		if d, err := Base64Decode(m[1]); err == nil {
			var cfg map[string]any
			if err := json.Unmarshal([]byte(d), &cfg); err == nil {
				p.Set("plugin", "shadow-tls")
				opts := map[string]any{}
				if host := getIfNotBlank(cfg["host"]); host != "" {
					opts["host"] = host
				}
				if password := getIfNotBlank(cfg["password"]); password != "" {
					opts["password"] = password
				}
				if version, ok := cfg["version"].(string); ok && version != "" {
					if n, err := strconv.Atoi(version); err == nil {
						opts["version"] = n
					}
				} else if version, ok := cfg["version"].(float64); ok {
					opts["version"] = int(version)
				}
				p.Set("plugin-opts", opts)
				if a := getIfNotBlank(cfg["address"]); a != "" {
					p.Set("server", a)
				}
				if pt := getIfNotBlank(cfg["port"]); pt != "" {
					if n, err := strconv.Atoi(pt); err == nil {
						p.Set("port", n)
					}
				}
			}
		}
	}

	// gost=... (Shadowrocket style, percent-encoded base64 JSON)
	if m := gostPayloadRe.FindStringSubmatch(content); m != nil {
		if d, err := Base64Decode(decodeURIComponent(m[1])); err == nil {
			var cfg map[string]any
			if err := json.Unmarshal([]byte(d), &cfg); err == nil {
				route := strings.ToLower(strings.TrimSpace(getIfNotBlank(cfg["route"])))
				isWebsocketRoute := route == "ws" || route == "wss" || route == "websocket"
				mode := route
				if isWebsocketRoute {
					mode = "websocket"
				}
				p.Set("plugin", "gost-plugin")
				opts := map[string]any{"mode": mode}
				if host := getIfNotBlank(cfg["host"]); host != "" {
					opts["host"] = host
				}
				if path := getIfNotBlank(cfg["path"]); path != "" {
					opts["path"] = path
				}
				if route == "wss" {
					opts["tls"] = true
				}
				p.Set("plugin-opts", opts)
				if a := getIfNotBlank(cfg["address"]); a != "" {
					p.Set("server", a)
				}
				if pt := getIfNotBlank(cfg["port"]); pt != "" {
					if n, err := strconv.Atoi(pt); err == nil {
						p.Set("port", n)
					}
				}
			}
		}
	}
}

var pluginParamRe = regexp.MustCompile(`[?&]plugin=([^&]+)`)
var shadowTlsPayloadRe = regexp.MustCompile(`[?&]shadow-tls=([^&]+)`)
var gostPayloadRe = regexp.MustCompile(`[?&]gost=([^&]+)`)

func getIfNotBlank(v any) string {
	if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
		return s
	}
	return ""
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// decodeURIComponent mirrors the JS builtin: percent-decoding without the
// "+" to space conversion.
func decodeURIComponent(s string) string {
	if out, err := urlUnescape(s); err == nil {
		return out
	}
	return s
}

// decodeQueryComponent mirrors transport-path.js: decodeURIComponent after
// converting "+" to "%20".
func decodeQueryComponent(s string) string {
	return decodeURIComponent(strings.ReplaceAll(s, "+", "%20"))
}

func splitQueryPart(part string) (key, value string) {
	sep := strings.Index(part, "=")
	if sep == -1 {
		return decodeQueryComponent(part), ""
	}
	return decodeQueryComponent(part[:sep]), decodeQueryComponent(part[sep+1:])
}

// extractPathQueryParam mirrors transport-path.js: removes the named query
// parameter from the path and returns the remaining path plus its value.
func extractPathQueryParam(rawPath, paramName string) (string, string) {
	qIdx := strings.Index(rawPath, "?")
	if qIdx == -1 {
		return rawPath, ""
	}
	basePath := rawPath[:qIdx]
	query := rawPath[qIdx+1:]
	kept := []string{}
	value := ""
	for _, part := range strings.Split(query, "&") {
		if part == "" {
			continue
		}
		key, val := splitQueryPart(part)
		if key == paramName {
			if value == "" && val != "" {
				value = val
			}
			continue
		}
		kept = append(kept, part)
	}
	path := basePath
	if len(kept) > 0 {
		path = basePath + "?" + strings.Join(kept, "&")
	}
	return path, value
}

func getPathQueryParam(rawPath, paramName string) string {
	qIdx := strings.Index(rawPath, "?")
	if qIdx == -1 {
		return ""
	}
	for _, part := range strings.Split(rawPath[qIdx+1:], "&") {
		if part == "" {
			continue
		}
		key, val := splitQueryPart(part)
		if key == paramName && val != "" {
			return val
		}
	}
	return ""
}

func isNumericEarlyData(value string) bool {
	if !digitRunRe.MatchString(value) || value != digitRunRe.FindString(value) {
		return false
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return false
	}
	return n <= 9007199254740991
}

func extractEarlyDataFromPath(path string) (string, string) {
	ed := getPathQueryParam(path, "ed")
	if !isNumericEarlyData(ed) {
		return path, ""
	}
	p, _ := extractPathQueryParam(path, "ed")
	return p, ed
}

func parseEarlyDataSize(value string) int {
	n, _ := strconv.ParseInt(value, 10, 64)
	return int(n)
}

// parseEarlyDataSizeStrict mirrors the throwing parseEarlyDataSize of
// parsers/index.js: only all-digit values within the JS safe-integer range
// are accepted.
func parseEarlyDataSizeStrict(value string) (int, error) {
	if !digitRunRe.MatchString(value) || value != digitRunRe.FindString(value) {
		return 0, fmt.Errorf("bad WebSocket max early data size: %s", value)
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n > 9007199254740991 {
		return 0, fmt.Errorf("bad WebSocket max early data size: %s", value)
	}
	return int(n), nil
}
