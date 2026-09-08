package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"substore/internal/model"
)

func init() {
	MustRegister(
		&Parser{Name: "URI TUIC Parser",
			Test: func(line string) bool { return strings.HasPrefix(line, "tuic://") },
			Parse: func(line string) (*model.Proxy, error) {
				return parseTuic(strings.TrimPrefix(line, "tuic://"))
			},
		},
		&Parser{Name: "URI AnyTLS Parser",
			Test: func(line string) bool { return strings.HasPrefix(line, "anytls://") },
			Parse: func(line string) (*model.Proxy, error) {
				return parseAnyTLS(line)
			},
		},
		&Parser{Name: "URI WireGuard Parser",
			Test: func(line string) bool {
				return strings.HasPrefix(line, "wireguard://") || strings.HasPrefix(line, "wg://")
			},
			Parse: func(line string) (*model.Proxy, error) {
				payload := strings.TrimPrefix(line, "wireguard://")
				payload = strings.TrimPrefix(payload, "wg://")
				return parseWireGuard(payload)
			},
		},
	)
}

var tuicRe = regexp.MustCompile(`^(.*?)@(.*?)(?::(\d+))?/?(?:\?(.*?))?(?:#(.*?))?$`)

func parseTuic(payload string) (*model.Proxy, error) {
	m := tuicRe.FindStringSubmatch(payload)
	if m == nil || m[1] == "" || m[2] == "" {
		return nil, fmt.Errorf("invalid tuic link")
	}
	auth := decodeURIComponent(m[1])
	server := m[2]
	port := m[3]
	addons := m[4]
	name := m[5]

	if port == "" {
		port = "443"
	}
	uuid, password := splitFirstColon(auth)
	password = decodeURIComponent(password)

	p := model.NewProxy()
	p.Set("type", "tuic")
	p.Set("server", server)
	p.Set("port", port)
	p.Set("password", password)
	p.Set("uuid", uuid)

	for _, addon := range strings.Split(addons, "&") {
		if addon == "" {
			continue
		}
		kv := strings.SplitN(addon, "=", 2)
		key := strings.ReplaceAll(kv[0], "_", "-")
		val := ""
		if len(kv) == 2 {
			val = decodeURIComponent(kv[1])
		}
		switch {
		case key == "alpn":
			if val != "" {
				p.Set("alpn", strings.Split(val, ","))
			}
		case key == "allow-insecure" || key == "insecure":
			p.Set("skip-cert-verify", trueBool(val))
		case key == "fast-open":
			p.Set("tfo", true)
		case key == "disable-sni" || key == "reduce-rtt":
			p.Set(key, trueBool(val))
		case key == "congestion-control":
			p.Set("congestion-controller", val)
		default:
			if !p.Has(key) {
				p.Set(key, val)
			}
		}
	}
	if name != "" {
		p.Set("name", decodeURIComponent(name))
	} else {
		p.Set("name", "TUIC "+server+":"+port)
	}
	return p, nil
}

var anytlsRe = regexp.MustCompile(`^(.*?)@(.*?)(?::(\d+))?/?(?:\?(.*?))?(?:#(.*?))?$`)

// vlessAlwaysWritten lists the keys the original URI_VLESS writes onto the
// proxy object unconditionally (even when the value is undefined, e.g.
// `proxy.sni = params.sni || params.peer`). URI_AnyTLS only accepts an
// original query param when the key is absent from the VLESS result, so
// these keys must be treated as present even though the Go parseVless only
// materializes non-empty values (parsers/index.js:2142-2144).
var vlessAlwaysWritten = map[string]bool{
	"type": true, "name": true, "server": true, "port": true,
	"uuid": true, "udp": true, "tls": true, "sni": true, "flow": true,
	"client-fingerprint": true, "alpn": true, "skip-cert-verify": true,
	"_echConfigList": true, "tls-fingerprint": true, "_vcn": true,
	"name-cert-verify": true, "_h2": true, "packet-encoding": true,
	"network": true,
}

// anytlsFlagRe mirrors /(TRUE)|1/i of URI_AnyTLS.
var anytlsFlagRe = regexp.MustCompile(`(?i)(TRUE)|1`)

// anytlsFlag mirrors /(TRUE)|1/i.test(value) of URI_AnyTLS.
func anytlsFlag(v string) bool {
	return anytlsFlagRe.MatchString(v)
}

// parseAnyTLS mirrors Sub-Store URI_AnyTLS: the line is parsed through the
// VLESS parser (anytls -> vless), the anytls password/server/port fields
// are applied on top, and the original anytls query params are only merged
// for keys the VLESS result does not carry. Transport metadata coming from
// the VLESS grammar (sni / flow / fp / reality-opts / network / *-opts /
// packet-encoding / encryption ...) is therefore preserved.
func parseAnyTLS(line string) (*model.Proxy, error) {
	payload := strings.TrimPrefix(line, "anytls://")
	content, fragName := DecodeURIFragment(payload)
	m := anytlsRe.FindStringSubmatch(content)
	if m == nil || m[1] == "" || m[2] == "" {
		return nil, fmt.Errorf("invalid anytls link")
	}
	password := decodeURIComponent(decodeURIComponent(m[1]))
	server := m[2]
	portStr := m[3]
	addons := m[4]
	port := 443
	if portStr != "" {
		if n, err := strconv.Atoi(portStr); err == nil {
			port = n
		}
	}
	name := fragName
	if name == "" {
		name = fmt.Sprintf("AnyTLS %s:%d", server, port)
	}

	// 原版先整行 replace('anytls', 'vless') 复用 URI_VLESS；端口缺省时
	// 补 :443 保证 VLESS 语法（强依赖端口）可匹配。
	vlessPayload := content
	if portStr == "" {
		after := content[len(m[1])+1+len(m[2]):]
		vlessPayload = m[1] + "@" + m[2] + ":443" + after
	}
	parsed, err := parseVless(vlessPayload)
	if err != nil {
		return nil, err
	}

	// 覆盖 anytls 自身字段（原版展开 VLESS 结果后覆盖；uuid 显式置
	// undefined，即从结果中移除）。
	parsed.Delete("uuid")
	parsed.Set("type", "anytls")
	parsed.Set("name", name)
	parsed.Set("server", server)
	parsed.Set("port", port)
	parsed.Set("password", password)

	for _, addon := range strings.Split(addons, "&") {
		if addon == "" {
			continue
		}
		kv := strings.SplitN(addon, "=", 2)
		key := strings.ReplaceAll(kv[0], "_", "-")
		val := ""
		if len(kv) == 2 {
			val = decodeURIComponent(kv[1])
		}
		switch {
		case key == "alpn":
			if val != "" {
				parsed.Set("alpn", strings.Split(val, ","))
			} else {
				// 原版置 undefined，等于从结果中移除
				parsed.Delete("alpn")
			}
		case key == "insecure":
			parsed.Set("skip-cert-verify", anytlsFlag(val))
		case key == "udp":
			parsed.Set("udp", anytlsFlag(val))
		default:
			if !parsed.Has(key) && !vlessAlwaysWritten[key] {
				parsed.Set(key, val)
			}
		}
	}

	if parsed.GetString("network") == "tcp" && !parsed.Has("reality-opts") {
		parsed.Delete("network")
		parsed.Delete("security")
	}
	return parsed, nil
}

var wgRe = regexp.MustCompile(`^((.*?)@)?(.*?)(:(\d+))?/?(?:\?(.*?))?(?:#(.*?))?$`)

func parseWireGuard(payload string) (*model.Proxy, error) {
	// the line may contain a #fragment which must survive in the name
	line := payload
	nameRaw := ""
	if idx := strings.Index(line, "#"); idx != -1 {
		nameRaw = line[idx+1:]
		line = line[:idx]
	}
	m := wgRe.FindStringSubmatch(line)
	if m == nil || m[3] == "" {
		return nil, fmt.Errorf("invalid wireguard link")
	}
	privateKey := ""
	if m[2] != "" {
		privateKey = decodeURIComponent(m[2])
	}
	server := m[3]
	port := m[5]
	addons := m[6]

	if port == "" {
		port = "51820"
	}
	name := "WireGuard " + server + ":" + port
	if nameRaw != "" {
		name = decodeURIComponent(nameRaw)
	}

	p := model.NewProxy()
	p.Set("type", "wireguard")
	p.Set("name", name)
	p.Set("server", server)
	p.Set("port", port)
	p.Set("private-key", privateKey)
	p.Set("udp", true)

	for _, addon := range strings.Split(addons, "&") {
		if addon == "" {
			continue
		}
		equalIndex := strings.Index(addon, "=")
		key := addon
		val := ""
		if equalIndex != -1 {
			key = addon[:equalIndex]
			val = decodeURIComponent(addon[equalIndex+1:])
		}
		key = strings.Replace(key, "_", "-", 1)
		switch {
		case key == "reserved":
			parsed := []any{}
			for _, item := range strings.Split(val, ",") {
				if n, err := strconv.Atoi(strings.TrimSpace(item)); err == nil {
					parsed = append(parsed, n)
				}
			}
			if len(parsed) == 3 {
				p.Set("reserved", parsed)
			}
		case key == "address" || key == "ip":
			for _, item := range strings.Split(val, ",") {
				addr, ok := parseWireGuardURIAddressValue(item)
				if !ok {
					continue
				}
				if addr.family == "ipv4" {
					p.Set("ip", addr.address)
					if addr.cidr >= 0 {
						p.Set("ip-cidr", addr.cidr)
					}
				} else {
					p.Set("ipv6", addr.address)
					if addr.cidr >= 0 {
						p.Set("ipv6-cidr", addr.cidr)
					}
				}
			}
		case key == "mtu":
			if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
				p.Set("mtu", n)
			}
		case regexp.MustCompile(`(?i)publickey`).MatchString(key):
			p.Set("public-key", val)
		case regexp.MustCompile(`(?i)privatekey`).MatchString(key):
			p.Set("private-key", val)
		case key == "udp":
			p.Set("udp", trueBool(val))
		default:
			if !p.Has(key) && key != "flag" {
				p.Set(key, val)
			}
		}
	}
	return p, nil
}

type wgAddress struct {
	family  string
	address string
	cidr    int
}

func parseWireGuardURIAddressValue(value string) (wgAddress, bool) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return wgAddress{}, false
	}
	m := wgAddressRe.FindStringSubmatch(raw)
	hostRaw := raw
	cidrRaw := ""
	if m != nil {
		if m[1] != "" {
			hostRaw = m[1]
		}
		cidrRaw = m[2]
	}
	host := strings.Trim(strings.Trim(strings.TrimSpace(hostRaw), "]"), "[")
	cidr := -1
	if cidrRaw != "" {
		if regexp.MustCompile(`^\d+$`).MatchString(cidrRaw) {
			if n, err := strconv.Atoi(cidrRaw); err == nil {
				cidr = n
			}
		}
	}
	if isIPv4String(host) {
		if cidr > 32 {
			cidr = -1
		}
		return wgAddress{"ipv4", host, cidr}, true
	}
	if isIPv6String(host) {
		if cidr > 128 {
			cidr = -1
		}
		return wgAddress{"ipv6", host, cidr}, true
	}
	return wgAddress{}, false
}

var wgAddressRe = regexp.MustCompile(`^(.*?)(?:/(\d+))?$`)

func splitFirstColon(s string) (string, string) {
	idx := strings.Index(s, ":")
	if idx == -1 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}
