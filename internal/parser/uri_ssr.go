package parser

import (
	"fmt"
	"regexp"
	"strings"

	"substore/internal/model"
)

func init() {
	MustRegister(&Parser{
		Name: "URI SSR Parser",
		Test: func(line string) bool { return strings.HasPrefix(line, "ssr://") },
		Parse: func(line string) (*model.Proxy, error) {
			decoded, err := Base64Decode(strings.TrimPrefix(line, "ssr://"))
			if err != nil {
				return nil, err
			}
			// server:port:protocol:method:obfs:base64(password)/?params
			rest := decoded
			paramsPart := ""
			if idx := strings.Index(rest, "/?"); idx != -1 {
				paramsPart = rest[idx+2:]
				rest = rest[:idx]
			}
			parts := strings.Split(rest, ":")
			if len(parts) < 6 {
				return nil, fmt.Errorf("invalid ssr link")
			}
			server := strings.Join(parts[:len(parts)-5], ":")
			port := parts[len(parts)-5]
			protocol := parts[len(parts)-4]
			cipher := parts[len(parts)-3]
			obfs := parts[len(parts)-2]
			password, err := Base64Decode(parts[len(parts)-1])
			if err != nil {
				return nil, err
			}
			p := model.NewProxy()
			p.Set("type", "ssr")
			p.Set("server", server)
			p.Set("port", port)
			p.Set("protocol", protocol)
			p.Set("cipher", cipher)
			p.Set("obfs", obfs)
			p.Set("password", password)

			// mirror URI_SSR other-params handling: values are trimmed and
			// empty / "(null)" placeholders are dropped
			other := map[string]string{}
			for _, pair := range strings.Split(paramsPart, "&") {
				if pair == "" {
					continue
				}
				kv := strings.SplitN(pair, "=", 2)
				if len(kv) != 2 {
					continue
				}
				val := strings.TrimSpace(kv[1])
				if val != "" && val != "(null)" {
					other[kv[0]] = val
				}
			}
			name := server
			if r := other["remarks"]; r != "" {
				if d, err := Base64Decode(r); err == nil {
					name = d
				}
			}
			// protoparam || protocolparam alias, like the original
			protoParam := other["protoparam"]
			if protoParam == "" {
				protoParam = other["protocolparam"]
			}
			if protoParam != "" {
				if d, err := Base64Decode(protoParam); err == nil {
					if v := stripAllWhitespace(d); v != "" {
						p.Set("protocol-param", v)
					}
				}
			}
			if obfsParam := other["obfsparam"]; obfsParam != "" {
				if d, err := Base64Decode(obfsParam); err == nil {
					if v := stripAllWhitespace(d); v != "" {
						p.Set("obfs-param", v)
					}
				}
			}
			p.Set("name", name)
			return p, nil
		},
	})
}

// stripAllWhitespace mirrors the original `.replace(/\s/g, '')`.
var whitespaceRe = regexp.MustCompile(`\s`)

func stripAllWhitespace(s string) string {
	return whitespaceRe.ReplaceAllString(s, "")
}
