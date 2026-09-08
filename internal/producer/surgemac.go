package producer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"substore/internal/model"
)

// SurgeMac producer mirroring producers/surgemac.js. 'external' proxies are
// rendered directly; other proxies go through the Surge producer, with an
// optional Mihomo "External Proxy Program" fallback for unsupported types.

// ProduceSurgeMac outputs SurgeMac proxy lines.
func ProduceSurgeMac(proxies []*model.Proxy, opts map[string]any) (string, error) {
	var lines []string
	for _, p := range proxies {
		line, err := surgeMacLine(p, opts)
		if err != nil {
			continue
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	if merged, ok := opts["_merged"].(map[string]any); ok {
		if localPort, ok := opts["localPort"].(int); ok && localPort >= 1 {
			mergedProxy := model.ProxyFromMap(map[string]any{
				"name":       merged["name"],
				"type":       "external",
				"udp":        true,
				"exec":       merged["exec"],
				"local-port": localPort,
				"args":       []any{"-config", surgeMacBase64Config(merged, localPort)},
				"addresses":  []any{},
			})
			if line := surgeMacExternal(mergedProxy); line != "" {
				lines = append(lines, line)
			}
		}
	}
	return strings.Join(lines, "\n"), nil
}

func surgeMacBase64Config(merged map[string]any, localPort int) string {
	config, ok := merged["config"].(map[string]any)
	if !ok {
		return ""
	}
	full := map[string]any{}
	for k, v := range config {
		full[k] = v
	}
	full["mixed-port"] = localPort
	b, err := jsonMarshalSorted(full)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(b))
}

// surgeMacLine mirrors SurgeMac_Producer().produce.
func surgeMacLine(proxy *model.Proxy, opts map[string]any) (string, error) {
	if proxy.Type() == "external" {
		return surgeMacExternal(proxy), nil
	}
	if mihomoExternalRequested(opts, proxy) {
		return surgeMacMihomo(proxy, opts), nil
	}
	line, err := surgeProduceLine(proxy, opts)
	if err != nil {
		if _, isUnsupported := err.(*surgeUnsupportedError); isUnsupported &&
			useMihomoExternalOption(opts) {
			if out := surgeMacMihomo(proxy, opts); out != "" {
				return out, nil
			}
		}
		return "", err
	}
	return line, nil
}

func mihomoExternalRequested(opts map[string]any, proxy *model.Proxy) bool {
	if opts != nil {
		if b, _ := opts["mihomoExternal"].(bool); b {
			return true
		}
	}
	if b, _ := proxy.Fields()["_mihomoExternal"].(bool); b {
		return true
	}
	return false
}

func useMihomoExternalOption(opts map[string]any) bool {
	if opts == nil {
		return false
	}
	b, _ := opts["useMihomoExternal"].(bool)
	return b
}

// surgeMacExternal mirrors the external() function in surgemac.js.
func surgeMacExternal(proxy *model.Proxy) string {
	if !isTruthy(proxy.Get("exec")) || !isTruthy(proxy.Get("local-port")) {
		return ""
	}
	result := newSurgeResult(proxy)
	result.append(fmt.Sprintf("%s=external,exec=\"%s\",local-port=%s",
		proxy.GetString("name"), str(proxy.Get("exec")), str(proxy.Get("local-port"))))
	if args := proxy.GetArray("args"); len(args) > 0 {
		for _, arg := range args {
			result.append(fmt.Sprintf(`,args="%s"`, str(arg)))
		}
	}
	if addrs := proxy.GetArray("addresses"); len(addrs) > 0 {
		for _, addr := range addrs {
			result.append(`,addresses=` + str(addr))
		}
	}
	result.appendIfPresent(`,no-error-alert=`+str(proxy.Get("no-error-alert")), "no-error-alert")
	result.appendIfPresent(`,udp-relay=`+str(proxy.Get("udp")), "udp")
	if isPresent(proxy, "tfo") {
		result.append(`,tfo=` + str(proxy.Get("tfo")))
	} else if isPresent(proxy, "fast-open") {
		result.append(`,tfo=` + str(proxy.Get("fast-open")))
	}
	result.appendIfPresent(`,test-url=`+str(proxy.Get("test-url")), "test-url")
	result.appendIfPresent(`,block-quic=`+str(proxy.Get("block-quic")), "block-quic")
	return result.String()
}

var surgemacDefaultNameservers = []any{"180.76.76.76", "52.80.52.52", "119.28.28.28", "223.6.6.6"}
var surgemacDefaultNameservers2 = []any{
	"https://doh.pub/dns-query",
	"https://dns.alidns.com/dns-query",
	"https://doh-pure.onedns.net/dns-query",
}

// surgeMacMihomo mirrors the mihomo() function in surgemac.js.
func surgeMacMihomo(proxy *model.Proxy, opts map[string]any) string {
	internal := clashMapProxies([]*model.Proxy{proxy}, nil, clashPlatformMeta, "internal")
	if len(internal) == 0 {
		return ""
	}
	clashProxy := internal[0]

	localPort := 65535
	if opts != nil {
		if v, ok := opts["localPort"].(int); ok {
			localPort = v
		}
	}
	if v, ok := proxy.Fields()["_localPort"].(int); ok && localPort == 65535 && !hasOptLocalPort(opts) {
		localPort = v
	}
	ipv6 := true
	switch proxy.GetString("ip-version") {
	case "ipv4", "v4-only":
		ipv6 = false
	}
	optsLocal := func(key string, fallback any) any {
		if opts != nil {
			if v, ok := opts[key]; ok {
				return v
			}
		}
		if v, ok := proxy.Fields()["_"+key]; ok {
			return v
		}
		return fallback
	}
	defaultNameserver := optsLocal("defaultNameserver", surgemacDefaultNameservers)
	nameserver := optsLocal("nameserver", surgemacDefaultNameservers2)
	dns := map[string]any{
		"enable":             true,
		"ipv6":               ipv6,
		"default-nameserver": defaultNameserver,
		"nameserver":         nameserver,
	}
	merge := false
	if opts != nil {
		if v, ok := opts["merge"].(bool); ok {
			merge = v
		}
	}
	if v, ok := proxy.Fields()["_merge"].(bool); ok && !merge {
		merge = v
	}

	if merge {
		socks5 := model.ProxyFromMap(map[string]any{
			"name":   proxy.GetString("name"),
			"type":   "socks5",
			"server": "127.0.0.1",
			"port":   localPort,
			"udp":    true,
		})
		line, err := surgeProduceLine(socks5, opts)
		if err != nil {
			return ""
		}

		merged, _ := opts["_merged"].(map[string]any)
		if merged == nil {
			mergedName := "mihomo merged"
			if opts != nil {
				if v, ok := opts["mergeName"].(string); ok {
					mergedName = v
				}
			}
			if v, ok := proxy.Fields()["_mergeName"].(string); ok && mergedName == "mihomo merged" && !hasOptMergeName(opts) {
				mergedName = v
			}
			exec := "/usr/local/bin/mihomo"
			if opts != nil {
				if v, ok := opts["exec"].(string); ok {
					exec = v
				}
			}
			if v, ok := proxy.Fields()["_exec"].(string); ok && exec == "/usr/local/bin/mihomo" && !hasOptExec(opts) {
				exec = v
			}
			merged = map[string]any{
				"name": mergedName,
				"exec": exec,
				"config": map[string]any{
					"ipv6":   ipv6,
					"mode":   "global",
					"dns":    dns,
					"proxies": []any{},
					"proxy-groups": []any{
						map[string]any{
							"name":    "GLOBAL",
							"type":    "fallback",
							"proxies": []any{},
						},
					},
					"listeners": []any{},
				},
			}
			opts["_merged"] = merged
		}
		config, _ := merged["config"].(map[string]any)
		proxyName := fmt.Sprintf("%d", localPort)
		listeners, _ := config["listeners"].([]any)
		listeners = append(listeners, map[string]any{
			"name":   fmt.Sprintf("socks5-%d", localPort),
			"type":   "socks",
			"port":   localPort,
			"listen": "127.0.0.1",
			"udp":    true,
			"proxy":  proxyName,
		})
		config["listeners"] = listeners
		groups, _ := config["proxy-groups"].([]any)
		if len(groups) > 0 {
			group, _ := groups[0].(map[string]any)
			groupProxies, _ := group["proxies"].([]any)
			group["proxies"] = append(groupProxies, proxyName)
		}
		config["proxy-groups"] = groups
		proxies, _ := config["proxies"].([]any)
		namedProxy := cloneAny(clashProxy)
		if m, ok := namedProxy.(map[string]any); ok {
			m["name"] = proxyName
		}
		config["proxies"] = append(proxies, namedProxy)
		if opts != nil {
			if extra, ok := opts["config"].(map[string]any); ok {
				for k, v := range extra {
					config[k] = v
				}
			}
		}
		if extra, ok := proxy.Fields()["_config"].(map[string]any); ok {
			for k, v := range extra {
				config[k] = v
			}
		}
		if opts != nil {
			opts["localPort"] = localPort - 1
		}
		return line
	}

	externalProxy := map[string]any{
		"name":       proxy.GetString("name"),
		"type":       "external",
		"udp":        true,
		"exec":       surgeMacOptString(opts, "exec", proxy, "_exec", "/usr/local/bin/mihomo"),
		"local-port": localPort,
		"args": []any{
			"-config",
			surgeMacBase64Args(clashProxy, localPort, ipv6, dns, opts, proxy),
		},
		"addresses": []any{},
	}
	if isIP(proxy.Server()) {
		externalProxy["addresses"] = []any{proxy.Server()}
	}
	if opts != nil {
		opts["localPort"] = localPort - 1
	}
	return surgeMacExternal(model.ProxyFromMap(externalProxy))
}

func hasOptLocalPort(opts map[string]any) bool {
	if opts == nil {
		return false
	}
	_, ok := opts["localPort"]
	return ok
}

func hasOptMergeName(opts map[string]any) bool {
	if opts == nil {
		return false
	}
	_, ok := opts["mergeName"]
	return ok
}

func hasOptExec(opts map[string]any) bool {
	if opts == nil {
		return false
	}
	_, ok := opts["exec"]
	return ok
}

func surgeMacOptString(opts map[string]any, optKey string, proxy *model.Proxy, fieldKey, fallback string) string {
	if opts != nil {
		if v, ok := opts[optKey].(string); ok {
			return v
		}
	}
	if v, ok := proxy.Fields()[fieldKey].(string); ok {
		return v
	}
	return fallback
}

func surgeMacBase64Args(clashProxy map[string]any, localPort int, ipv6 bool, dns map[string]any, opts map[string]any, proxy *model.Proxy) string {
	named := cloneAny(clashProxy).(map[string]any)
	named["name"] = "proxy"
	config := map[string]any{
		"mixed-port": localPort,
		"ipv6":       ipv6,
		"mode":       "global",
		"dns":        dns,
		"proxies":    []any{named},
		"proxy-groups": []any{
			map[string]any{
				"name":    "GLOBAL",
				"type":    "select",
				"proxies": []any{"proxy"},
			},
		},
	}
	if opts != nil {
		if extra, ok := opts["config"].(map[string]any); ok {
			for k, v := range extra {
				config[k] = v
			}
		}
	}
	if extra, ok := proxy.Fields()["_config"].(map[string]any); ok {
		for k, v := range extra {
			config[k] = v
		}
	}
	b, err := jsonMarshalSorted(config)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(b))
}

// jsonMarshalSortedConfig is kept for parity with json.Marshal usage.
var _ = json.Marshal
