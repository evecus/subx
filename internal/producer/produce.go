package producer

import (
	"fmt"
	"math/rand"
	"net"
	"strings"

	"substore/internal/model"
)

// prepareProxies mirrors the pre-processing in index.js produce(): it
// filters unsupported proxies (unless include-unsupported-proxy is set),
// applies the disable-sni / ports / name / wireguard normalization and
// returns deep clones so producers never mutate the shared input.
func prepareProxies(proxies []*model.Proxy, targetPlatform string, opts map[string]any) []*model.Proxy {
	normalizedTarget := strings.ToLower(targetPlatform)
	includeUnsupported := false
	if opts != nil {
		includeUnsupported, _ = opts["include-unsupported-proxy"].(bool)
	}

	filtered := make([]*model.Proxy, 0, len(proxies))
	for _, proxy := range proxies {
		if !includeUnsupported && proxy.SupportedPlatforms() != nil {
			if v, ok := proxy.SupportedPlatforms()[targetPlatform]; ok && v == false {
				continue
			}
		}
		if !includeUnsupported && hasRootProxyHeaders(proxy) &&
			isRootHeaderSensitiveProxy(proxy) &&
			!supportsRootProxyHeaders(proxy, targetPlatform) {
			continue
		}
		if !includeUnsupported && isShadowsocksOverTls(proxy) &&
			!isQXLikeTarget(normalizedTarget) {
			continue
		}
		if proxy.Type() == "vless" || proxy.Type() == "vmess" {
			if proxy.Type() == "vless" {
				if reality := proxy.GetMap("reality-opts"); reality != nil &&
					strings.TrimSpace(str(reality["public-key"])) == "" {
					continue
				}
				if proxy.GetString("network") == "xhttp" {
					xhttpOpts := proxy.GetMap("xhttp-opts")
					if xhttpOpts != nil && str(xhttpOpts["mode"]) == "stream-one" &&
						getMapNested(xhttpOpts, "download-settings") != nil {
						continue
					}
					if ds := getMapNested(xhttpOpts, "download-settings", "reality-opts"); ds != nil {
						mainPk := str(proxy.GetMap("reality-opts")["public-key"])
						dsPk, hasDS := ds["public-key"].(string)
						if hasDS && dsPk == "" {
							// explicit empty string cancels Reality inheritance
							// for the download stream; requires a valid main
							// reality public-key
							if strings.TrimSpace(mainPk) == "" {
								continue
							}
						} else if strings.TrimSpace(str(ds["public-key"])) == "" {
							continue
						}
					}
				}
			}
		}
		filtered = append(filtered, proxy)
	}

	out := make([]*model.Proxy, 0, len(filtered))
	for _, proxy := range filtered {
		c := proxy.Clone()
		c.Set("_resolved", c.Get("resolved"))
		if strings.TrimSpace(c.GetString("name")) == "" {
			c.Set("name", fmt.Sprintf("%s %s:%d", c.Type(), c.Server(), c.Port()))
		}
		if c.GetBool("disable-sni") {
			switch {
			case normalizedTarget == "surge" || normalizedTarget == "surgemac" ||
				normalizedTarget == "shadowrocket":
				c.Set("sni", "off")
			case c.Type() != "tuic" && normalizedTarget != "sing-box" && normalizedTarget != "singbox":
				if isIP(c.Server()) {
					c.Set("sni", c.Server())
				} else {
					c.Set("sni", "127.0.0.1")
				}
			}
		}
		if ports := c.Get("ports"); ports != nil {
			c.Set("ports", str(ports))
			if !isMetaTarget(normalizedTarget) {
				c.Set("ports", strings.ReplaceAll(str(ports), "/", ","))
			}
			if c.Port() == 0 {
				c.Set("port", getRandomPort(c.GetString("ports")))
			}
		}
		if c.Type() == "wireguard" {
			normalizeWireGuardInterface(c)
		}
		out = append(out, c)
	}
	return out
}

func isQXLikeTarget(normalizedTarget string) bool {
	return normalizedTarget == "qx" || normalizedTarget == "quantumultx" ||
		normalizedTarget == "shadowrocket"
}

func isMetaTarget(normalizedTarget string) bool {
	switch normalizedTarget {
	case "meta", "clashmeta", "clash.meta", "mihomo":
		return true
	}
	return false
}

func hasRootProxyHeaders(p *model.Proxy) bool {
	headers := p.GetMap("headers")
	return headers != nil && len(headers) > 0
}

func isRootHeaderSensitiveProxy(p *model.Proxy) bool {
	switch p.Type() {
	case "http", "h2-connect", "trusttunnel":
		return true
	}
	return false
}

func supportsRootProxyHeaders(p *model.Proxy, targetPlatform string) bool {
	normalizedTarget := strings.ToLower(targetPlatform)
	switch {
	case strings.HasPrefix(normalizedTarget, "surge"):
		return isRootHeaderSensitiveProxy(p)
	case normalizedTarget == "egern":
		return p.Type() == "http"
	case isMetaTarget(normalizedTarget):
		return p.Type() == "http"
	case normalizedTarget == "singbox" || normalizedTarget == "sing-box":
		return p.Type() == "http"
	case normalizedTarget == "json":
		return isRootHeaderSensitiveProxy(p)
	}
	return false
}

func isIP(s string) bool {
	host := strings.Trim(s, "[]")
	if net.ParseIP(host) == nil {
		return false
	}
	return true
}

// getRandomPort mirrors ProxyUtils.getRandomPort: a random port from a
// comma/slash separated port list.
func getRandomPort(ports string) int {
	parts := strings.FieldsFunc(ports, func(r rune) bool {
		return r == ',' || r == '/'
	})
	if len(parts) == 0 {
		return 0
	}
	p := parts[rand.Intn(len(parts))]
	n := 0
	fmt.Sscanf(p, "%d", &n)
	return n
}
