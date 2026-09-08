package parser

import (
	"math/rand"
	"regexp"
	"strconv"
	"strings"

	"substore/internal/model"
)

func init() {
	MustRegister(
		&Parser{Name: "URI Hysteria Parser",
			Test: func(line string) bool {
				return strings.HasPrefix(line, "hy://") || strings.HasPrefix(line, "hysteria://")
			},
			Parse: func(line string) (*model.Proxy, error) {
				payload := strings.TrimPrefix(line, "hysteria://")
				payload = strings.TrimPrefix(payload, "hy://")
				return parseHysteria(payload)
			},
		},
		&Parser{Name: "URI Hysteria2 Parser",
			Test: func(line string) bool {
				return strings.HasPrefix(line, "hysteria2://") || strings.HasPrefix(line, "hy2://")
			},
			Parse: func(line string) (*model.Proxy, error) {
				payload := strings.TrimPrefix(line, "hysteria2://")
				payload = strings.TrimPrefix(payload, "hy2://")
				return parseHysteria2(payload)
			},
		},
	)
}

// Mirrors the URI_Hysteria address grammar: optional port (default 443),
// optional trailing "/", non-numeric port-ranges fold into the server.
var hysteriaAddrRe = regexp.MustCompile(`^(.*?)(?::(\d+))?/?$`)

func parseHysteria(payload string) (*model.Proxy, error) {
	content, name := DecodeURIFragment(payload)
	qIdx := strings.Index(content, "?")
	addrPart := content
	query := ""
	if qIdx != -1 {
		addrPart = content[:qIdx]
		query = content[qIdx+1:]
	}
	m := hysteriaAddrRe.FindStringSubmatch(addrPart)
	if m == nil || m[1] == "" {
		return nil, errInvalidBase64
	}
	host := m[1]
	port := m[2]
	if port == "" {
		port = "443"
	}
	p := model.NewProxy()
	p.Set("type", "hysteria")
	p.Set("server", host)
	p.Set("port", port)

	fastOpen := ""
	peer := ""
	for _, addon := range strings.Split(query, "&") {
		if addon == "" {
			continue
		}
		kv := strings.SplitN(addon, "=", 2)
		key := strings.Replace(kv[0], "_", "-", 1)
		val := ""
		if len(kv) == 2 {
			val = decodeURIComponent(kv[1])
		}
		switch key {
		case "alpn":
			if val != "" {
				p.Set("alpn", strings.Split(val, ","))
			}
		case "insecure":
			p.Set("skip-cert-verify", trueBool(val))
		case "auth":
			p.Set("auth-str", val)
		case "mport":
			p.Set("ports", val)
		case "obfsParam":
			p.Set("obfs", val)
		case "upmbps":
			p.Set("up", val)
		case "downmbps":
			p.Set("down", val)
		case "obfs":
			p.Set("_obfs", val)
		case "fast-open":
			fastOpen = val
		case "peer":
			peer = val
		default:
			if !p.Has(key) {
				p.Set(key, val)
			}
		}
	}
	// mirrors index.js:2321 `!proxy.sni && params.peer`: an explicit empty
	// sni (e.g. "?sni=") is falsy and still allows the peer fallback
	if !jsTruthy(p.Get("sni")) && peer != "" {
		p.Set("sni", peer)
	}
	if !p.Has("fast-open") && fastOpen != "" {
		p.Set("fast-open", true)
	}
	if !p.Has("protocol") {
		p.Set("protocol", "udp")
	}
	if name != "" {
		p.Set("name", name)
	} else {
		p.Set("name", "Hysteria "+host+":"+port)
	}
	return p, nil
}

func parseHysteria2(payload string) (*model.Proxy, error) {
	content, name := DecodeURIFragment(payload)
	m := hy2Re.FindStringSubmatch(content)
	if m == nil {
		return nil, errInvalidBase64
	}
	password := m[1]
	server := m[2]
	port := m[4]
	addons := m[9]

	var ports string
	if digitRunRe.MatchString(port) && port == digitRunRe.FindString(port) {
		if n, err := strconv.Atoi(port); err == nil {
			port = strconv.Itoa(n)
		}
	} else if port != "" {
		ports = port
		port = strconv.Itoa(getRandomPort(ports))
	} else {
		port = "443"
	}

	p := model.NewProxy()
	p.Set("type", "hysteria2")
	p.Set("server", server)
	p.Set("port", port)
	if ports != "" {
		p.Set("ports", ports)
	}
	p.Set("password", decodeURIComponent(password))

	params := map[string]string{}
	for _, addon := range strings.Split(addons, "&") {
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

	// mirrors index.js:2224-2227: proxy.sni = params.sni is written
	// unconditionally, so an explicit "?sni=" keeps sni as "" (the empty
	// string survives normalize via the `proxy.sni !== ''` guard)
	if sni, hasSni := params["sni"]; hasSni && sni != "" {
		p.Set("sni", sni)
	} else if peer, hasPeer := params["peer"]; hasPeer && peer != "" {
		p.Set("sni", peer)
	} else if hasSni {
		p.Set("sni", "")
	}
	if obfs := params["obfs"]; obfs != "" && obfs != "none" {
		p.Set("obfs", obfs)
	}
	if mport := params["mport"]; mport != "" {
		p.Set("ports", mport)
	}
	if obfsPassword := params["obfs-password"]; obfsPassword != "" {
		p.Set("obfs-password", obfsPassword)
	}
	// mirrors index.js:2235-2236: both flags are written unconditionally
	// via /(TRUE)|1/i.test(...), so "?insecure=0" yields false, not an
	// absent key
	p.Set("skip-cert-verify", anytlsFlag(params["insecure"]))
	p.Set("tfo", anytlsFlag(params["fastopen"]))
	if fp := params["pinSHA256"]; fp != "" {
		p.Set("tls-fingerprint", fp)
	}
	hopInterval := params["hop-interval"]
	if hopInterval == "" {
		hopInterval = params["hop_interval"]
	}
	if hopInterval != "" {
		p.Set("hop-interval", hopInterval)
	}
	if keepalive := params["keepalive"]; keepalive != "" && digitRunRe.MatchString(keepalive) && keepalive == digitRunRe.FindString(keepalive) {
		if n, err := strconv.Atoi(keepalive); err == nil {
			p.Set("keepalive", n)
		}
	}
	if up := params["upmbps"]; up != "" {
		p.Set("up", up)
	}
	if down := params["downmbps"]; down != "" {
		p.Set("down", down)
	}
	if ech := buildMihomoEchOpts(params["ech"]); ech != nil {
		p.Set("ech-opts", ech)
	}

	if name != "" {
		p.Set("name", name)
	} else {
		p.Set("name", "Hysteria2 "+server+":"+port)
	}
	return p, nil
}

// Mirrors URI_Hysteria2: optional port supports the "port-hopping" format
// with ranges joined by "," or ";".
var hy2Re = regexp.MustCompile(`^(.*?)@(.*?)(:((\d+(-\d+)?)([,;]\d+(-\d+)?)*))?/?(?:\?(.*?))?$`)

func trueBool(v string) bool {
	return strings.EqualFold(v, "true") || v == "1"
}

func getRandomPort(portString string) int {
	parts := strings.Split(portString, ",")
	if len(parts) == 0 {
		return 443
	}
	randomPart := parts[rand.Intn(len(parts))]
	if idx := strings.Index(randomPart, "-"); idx != -1 {
		min, err1 := strconv.Atoi(randomPart[:idx])
		max, err2 := strconv.Atoi(randomPart[idx+1:])
		if err1 == nil && err2 == nil && min <= max {
			return min + rand.Intn(max-min+1)
		}
		return min
	}
	if n, err := strconv.Atoi(randomPart); err == nil {
		return n
	}
	return 443
}

// buildMihomoEchOpts mirrors buildMihomoEchOptsFromXrayFields for the
// echConfigList-only form.
func buildMihomoEchOpts(echConfigList string) map[string]any {
	if strings.TrimSpace(echConfigList) == "" {
		return nil
	}
	if !strings.Contains(echConfigList, "://") {
		return map[string]any{"enable": true, "config": echConfigList}
	}
	parts := strings.Split(echConfigList, "+")
	if len(parts) == 1 && strings.TrimSpace(parts[0]) != "" {
		return map[string]any{"enable": true, "_dns": parts[0]}
	}
	if len(parts) == 2 && strings.TrimSpace(parts[0]) != "" && strings.TrimSpace(parts[1]) != "" {
		return map[string]any{"enable": true, "query-server-name": parts[0], "_dns": parts[1]}
	}
	return nil
}
