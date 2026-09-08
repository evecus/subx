package parser

import (
	"fmt"
	"strings"

	"substore/internal/model"
)

func init() {
	MustRegister(
		&Parser{Name: "URI SOCKS Parser",
			Test: func(line string) bool {
				return strings.HasPrefix(line, "socks://")
			},
			Parse: func(line string) (*model.Proxy, error) {
				// Mirrors Sub-Store URI_SOCKS (index.js:208):
				// ^(socks)?:\/\/(?:(.*)@)?(.*?)(?::(\d+?))?(\?.*?)?(?:#(.*?))?$
				// The optional query group strips "?..." before host/port
				// extraction, so "socks://h:1080?x=1" keeps port 1080.
				m := socksURIRe.FindStringSubmatch(line)
				if m == nil {
					return nil, fmt.Errorf("invalid socks link")
				}
				auth, server, port, name := m[2], m[3], m[4], m[6]
				if port == "" {
					return nil, fmt.Errorf("port is not present in line")
				}
				p := model.NewProxy()
				p.Set("type", "socks5")
				p.Set("server", server)
				p.Set("port", port)
				if auth != "" {
					if d, err := Base64Decode(decodeURIComponent(auth)); err == nil {
						parts := strings.SplitN(d, ":", 2)
						if len(parts) == 2 {
							p.Set("username", parts[0])
							p.Set("password", parts[1])
						}
					}
				}
				if n := decodeURIComponent(name); n != "" {
					p.Set("name", n)
				} else {
					p.Set("name", "Socks5 "+server+":"+port)
				}
				return p, nil
			},
		},
		&Parser{Name: "URI Proxy Parser",
			Test: func(line string) bool {
				return proxyURISchemeRe.MatchString(line)
			},
			Parse: func(line string) (*model.Proxy, error) {
				m := proxyURISchemeRe.FindStringSubmatch(line)
				if len(m) != 9 {
					return nil, fmt.Errorf("invalid proxy link")
				}
				// The auth group is optional: when it participated in the
				// match, username/password are written even if empty
				// (mirrors index.js:189-192 `username != null`).
				loc := proxyURISchemeRe.FindStringSubmatchIndex(line)
				typ := m[1]
				tls := m[2] != ""
				username := m[3]
				password := m[4]
				server := m[5]
				port := m[6]
				name := m[8]
				if port == "" {
					if tls {
						port = "443"
					} else if typ == "http" {
						port = "80"
					} else {
						return nil, fmt.Errorf("port not present in line")
					}
				}
				p := model.NewProxy()
				p.Set("type", typ)
				p.Set("tls", tls)
				p.Set("server", server)
				p.Set("port", port)
				if loc[6] != -1 {
					p.Set("username", decodeURIComponent(username))
				}
				if loc[8] != -1 {
					p.Set("password", decodeURIComponent(password))
				}
				if n := decodeURIComponent(name); n != "" {
					p.Set("name", n)
				} else {
					p.Set("name", typ+" "+server+":"+port)
				}
				return p, nil
			},
		},
	)
}

// Mirrors Sub-Store's URI_PROXY regex: "https" is parsed as type "http"
// with the trailing "s" captured by the tls group.
var proxyURISchemeRe = regexMust(`^(socks5|http|http)(\+tls|s)?:\/\/(?:(.*?):(.*?)@)?(.*?)(?::(\d+?))?\/?(\?.*?)?(?:#(.*?))?$`)

// Mirrors Sub-Store URI_SOCKS (index.js:208); the optional query group
// keeps "?..." out of the server/port captures.
var socksURIRe = regexMust(`^(socks)?://(?:(.*)@)?(.*?)(?::(\d+?))?(\?.*?)?(?:#(.*?))?$`)
