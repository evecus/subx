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
		Name: "URI VMess Parser",
		Test: func(line string) bool { return strings.HasPrefix(line, "vmess://") },
		Parse: func(line string) (*model.Proxy, error) {
			return parseVMess(strings.TrimPrefix(line, "vmess://"))
		},
	})
}

// qxVmessRe detects the Quantumult X comma format ("...=vmess,...").
var qxVmessRe = regexp.MustCompile(`=\s*vmess`)

// shadowrocketVmessSplitRe mirrors the Shadowrocket fallback split in
// URI_VMess: base64 payload (with optional trailing "/") plus query string.
var shadowrocketVmessSplitRe = regexp.MustCompile(`^(.*?)\/?\?(.*)$`)

// vmessUserInfoRe mirrors the Shadowrocket user-info grammar
// "cipher:uuid@server:port".
var vmessUserInfoRe = regexp.MustCompile(`^([^:]+?):([^:]+?)@(.*):(\d+)$`)

// qxQuotedRe mirrors the quoted-value handling of the QX VMess URI format.
var qxQuotedRe = regexp.MustCompile(`^"(.*)"$`)

// qxObfsHostRe mirrors the Host extraction from the QX obfs-header value.
var qxObfsHostRe = regexp.MustCompile(`Host:\s*([a-zA-Z0-9-.]*)`)

func parseVMess(payload string) (*model.Proxy, error) {
	lineWithoutFragment, fragmentName := splitURIFragment(payload)
	content := lineWithoutFragment
	if qIdx := strings.Index(content, "?"); qIdx != -1 {
		content = content[:qIdx]
	}
	decoded, err := Base64Decode(content)
	if err != nil {
		return nil, err
	}

	// Quantumult X vmess format: name=vmess,server,port,method,uuid...
	if qxVmessRe.MatchString(decoded) {
		return parseVmessQX(decoded, fragmentName)
	}

	// V2rayN URI format (JSON)
	var params map[string]any
	if err := json.Unmarshal([]byte(decoded), &params); err == nil {
		return parseVmessV2rayN(params, fragmentName)
	}

	// Shadowrocket URI format
	return parseVmessShadowrocket(lineWithoutFragment, fragmentName)
}

func parseVmessQX(decoded, fragmentName string) (*model.Proxy, error) {
	rawParts := strings.Split(decoded, ",")
	partitions := make([]string, len(rawParts))
	for i, part := range rawParts {
		partitions[i] = strings.TrimSpace(part)
	}
	params := map[string]string{}
	for _, part := range partitions {
		if idx := strings.Index(part, "="); idx != -1 {
			params[strings.TrimSpace(part[:idx])] = strings.TrimSpace(part[idx+1:])
		}
	}

	uuidMatch := qxQuotedRe.FindStringSubmatch(partitions[4])
	if uuidMatch == nil {
		return nil, fmt.Errorf("invalid vmess qx uuid")
	}
	cipher := partitions[3]
	if strings.TrimSpace(cipher) == "" {
		cipher = "auto"
	}

	p := model.NewProxy()
	p.Set("name", strings.TrimSpace(strings.SplitN(partitions[0], "=", 2)[0]))
	p.Set("type", "vmess")
	p.Set("server", partitions[1])
	p.Set("port", partitions[2])
	p.Set("cipher", normalizeVmessSecurity(cipher))
	p.Set("uuid", uuidMatch[1])
	p.Set("tls", params["obfs"] == "wss")
	if _, ok := params["udp-relay"]; ok {
		p.Set("udp", params["udp-relay"])
	}
	if _, ok := params["fast-open"]; ok {
		p.Set("tfo", params["fast-open"])
	}
	if v, ok := params["tls-verification"]; ok {
		// mirror the reference: !params['tls-verification'] is plain string
		// truthiness, so only an empty value yields true
		p.Set("skip-cert-verify", v == "")
	}

	if v, ok := params["obfs"]; ok {
		if v == "ws" || v == "wss" {
			p.Set("network", "ws")
			path := params["obfs-path"]
			if path == "" {
				path = "/"
			}
			if m := qxQuotedRe.FindStringSubmatch(path); m != nil {
				path = m[1]
			}
			opts := map[string]any{"path": path}
			obfsHost := params["obfs-header"]
			if obfsHost != "" && strings.Contains(obfsHost, "Host") {
				if m := qxObfsHostRe.FindStringSubmatch(obfsHost); m != nil {
					obfsHost = m[1]
				}
			}
			if isNotBlank(obfsHost) {
				opts["headers"] = map[string]any{"Host": obfsHost}
			}
			p.Set("ws-opts", opts)
		} else {
			return nil, fmt.Errorf("unsupported obfs: %s", v)
		}
	}
	if isNotBlank(fragmentName) {
		p.Set("name", fragmentName)
	}
	return p, nil
}

func parseVmessShadowrocket(lineWithoutFragment, fragmentName string) (*model.Proxy, error) {
	m := shadowrocketVmessSplitRe.FindStringSubmatch(lineWithoutFragment)
	if m == nil {
		return nil, fmt.Errorf("invalid vmess shadowrocket link")
	}
	decoded, err := Base64Decode(m[1])
	if err != nil {
		return nil, fmt.Errorf("invalid vmess shadowrocket link")
	}
	params := map[string]any{}
	for _, addon := range strings.Split(m[2], "&") {
		if addon == "" {
			continue
		}
		key := addon
		valueRaw := ""
		if sep := strings.Index(addon, "="); sep != -1 {
			key = addon[:sep]
			valueRaw = addon[sep+1:]
		}
		value := decodeURIComponent(valueRaw)
		if strings.Contains(value, ",") {
			params[key] = strings.Split(value, ",")
		} else {
			params[key] = value
		}
	}
	um := vmessUserInfoRe.FindStringSubmatch(decoded)
	if um == nil {
		return nil, fmt.Errorf("invalid vmess shadowrocket link")
	}
	params["scy"] = um[1]
	params["id"] = um[2]
	params["port"] = um[4]
	params["add"] = um[3]
	return parseVmessV2rayN(params, fragmentName)
}

func parseVmessV2rayN(params map[string]any, fragmentName string) (*model.Proxy, error) {
	server := getString(params, "add")
	port := parseIntCoerced(params["port"], 0)

	p := model.NewProxy()
	p.Set("type", "vmess")
	p.Set("server", server)
	p.Set("port", port)
	p.Set("cipher", normalizeVmessSecurity(anyToString(params["scy"])))
	p.Set("uuid", getString(params, "id"))
	aid := params["aid"]
	if aid == nil {
		aid = params["alterId"]
	}
	p.Set("alterId", parseIntCoerced(aid, 0))

	tlsVal := params["tls"]
	tls := tlsVal == "tls" || tlsVal == "1" || tlsVal == true ||
		tlsVal == float64(1) || tlsVal == int(1)
	p.Set("tls", tls)

	if v, ok := params["verify_cert"]; ok {
		p.Set("skip-cert-verify", jsFalsy(v))
	} else if v, ok := params["allowInsecure"]; ok {
		p.Set("skip-cert-verify", trueBool(fmt.Sprint(v)))
	}

	if tls {
		if sni, ok := params["sni"]; ok && anyToString(sni) != "" {
			p.Set("sni", anyToString(sni))
		} else if peer, ok := params["peer"]; ok && anyToString(peer) != "" {
			p.Set("sni", anyToString(peer))
		}
	}

	httpupgrade := false
	network := ""
	net := anyToString(params["net"])
	obfs := anyToString(params["obfs"])
	typ := anyToString(params["type"])
	if net == "ws" || obfs == "websocket" {
		network = "ws"
	} else if obfs == "http" || typ == "http" {
		network = "http"
	} else if net == "http" {
		network = "h2"
	} else if net == "grpc" || net == "kcp" || net == "quic" {
		network = net
	} else if net == "httpupgrade" {
		network = "ws"
		httpupgrade = true
	} else if net == "h2" {
		network = "h2"
	}

	if network != "" {
		p.Set("network", network)
		transportHost := params["host"]
		if transportHost == nil {
			transportHost = params["obfsParam"]
		}
		if s, ok := transportHost.(string); ok && s != "" {
			var parsed struct {
				Host any `json:"Host"`
			}
			if err := json.Unmarshal([]byte(s), &parsed); err == nil && parsed.Host != nil {
				transportHost = parsed.Host
			}
		}
		transportPath := getString(params, "path")
		httpUpgradeEd := ""
		pathEarlyData := ""
		if network == "ws" && transportPath != "" {
			extractedPath, ed := extractEarlyDataFromPath(transportPath)
			transportPath = extractedPath
			if httpupgrade {
				httpUpgradeEd = ed
			} else {
				pathEarlyData = ed
			}
		}
		if network == "ws" {
			if transportPath == "" {
				transportPath = "/"
			}
		}
		if network == "http" {
			if s, ok := transportHost.(string); ok && s != "" {
				parts := strings.Split(s, ",")
				for i := range parts {
					parts[i] = strings.TrimSpace(parts[i])
				}
				if len(parts) > 0 {
					transportHost = parts[0]
				}
			}
			if transportPath == "" {
				transportPath = "/"
			}
		} else if network == "h2" {
			if transportPath == "" {
				transportPath = "/"
			}
		}

		hasTransportHost := false
		if s, ok := transportHost.(string); ok && s != "" {
			hasTransportHost = true
		} else if _, ok := transportHost.([]any); ok {
			hasTransportHost = true
		}
		if transportPath != "" || hasTransportHost || network == "kcp" || network == "quic" {
			if network == "grpc" {
				opts := map[string]any{}
				if v := getIfNotBlank(transportPath); v != "" {
					opts["grpc-service-name"] = v
				}
				if v := getIfNotBlank(typ); v != "" {
					opts["_grpc-type"] = v
				}
				if v := getIfNotBlank(anyToString(params["authority"])); v != "" {
					opts["_grpc-authority"] = v
				}
				p.Set("grpc-opts", opts)
			} else if network == "kcp" || network == "quic" {
				opts := map[string]any{}
				if v := getIfNotBlank(typ); v != "" {
					opts["_"+network+"-type"] = v
				}
				if v := getIfNotBlank(anyToString(transportHost)); v != "" {
					opts["_"+network+"-host"] = v
				}
				if v := getIfNotBlank(transportPath); v != "" {
					opts["_"+network+"-path"] = v
				}
				p.Set(network+"-opts", opts)
			} else {
				opts := map[string]any{}
				if v := getIfNotBlank(transportPath); v != "" {
					opts["path"] = v
				}
				normalizedTransportHost := getIfNotBlank(anyToString(transportHost))
				if network == "h2" {
					if hosts := splitURIHostList(normalizedTransportHost); hosts != nil {
						opts["host"] = hosts
					}
				} else {
					opts["headers"] = map[string]any{"Host": normalizedTransportHost}
				}
				if httpupgrade {
					opts["v2ray-http-upgrade"] = true
					if httpUpgradeEd == "" && isNumericEarlyData(anyToString(params["ed"])) {
						httpUpgradeEd = anyToString(params["ed"])
					}
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
		}
	}

	if fp, ok := params["fp"]; ok && fp != nil {
		p.Set("client-fingerprint", fmt.Sprint(fp))
	}
	if alpn := getString(params, "alpn"); alpn != "" {
		p.Set("alpn", strings.Split(alpn, ","))
	}

	ps := getString(params, "ps")
	if ps == "" {
		ps = getString(params, "remarks")
	}
	if ps == "" {
		ps = getString(params, "remark")
	}
	if ps == "" {
		ps = fmt.Sprintf("VMess %s:%d", server, port)
	}
	p.Set("name", ps)
	if isNotBlank(fragmentName) {
		p.Set("name", fragmentName)
	}
	return p, nil
}

// splitURIFragment mirrors splitURIFragment in parsers/index.js: the
// fragment is everything after the first "#" (percent-decoded).
func splitURIFragment(raw string) (content, fragment string) {
	idx := strings.Index(raw, "#")
	if idx == -1 {
		return raw, ""
	}
	return raw[:idx], decodeURIComponent(raw[idx+1:])
}

// anyToString converts a JSON-decoded value to its string form.
func anyToString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// jsFalsy mirrors JavaScript truthiness for JSON values: nil/empty strings
// and numeric zero are falsy.
func jsFalsy(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case bool:
		return !t
	case float64:
		return t == 0
	case int:
		return t == 0
	}
	return false
}

// parseIntCoerced mirrors parseInt(x, 10) for JSON values.
func parseIntCoerced(v any, def int) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		n, err := strconv.Atoi(t)
		if err != nil {
			return def
		}
		return n
	}
	return def
}
