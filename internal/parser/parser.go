package parser

import (
	"errors"
	"strings"

	"substore/internal/model"
)

// Errors returned by parsers.
var (
	errInvalidBase64 = errors.New("invalid base64")
	errInvalidJSON   = errors.New("invalid json")
)

// Parser is a single node-line parser.
type Parser struct {
	Name  string
	Test  func(line string) bool
	Parse func(line string) (*model.Proxy, error)
}

// registry holds all line parsers in priority order.
var registry []*Parser

// Register adds a parser to the registry.
func Register(p *Parser) {
	registry = append(registry, p)
}

// Parsers returns the current registry.
func Parsers() []*Parser {
	return registry
}

// ErrUnparsedLine is reported when no parser could handle a line.
var ErrUnparsedLine = errors.New("failed to parse line")

// ParseText parses raw subscription text into a list of proxies.
// It iterates lines, keeping the last used parser as a hint. Lines that
// cannot be parsed are skipped.
func ParseText(raw string) []*model.Proxy {
	lines := strings.Split(raw, "\n")
	proxies := make([]*model.Proxy, 0, len(lines))
	var lastParser *Parser

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var proxy *model.Proxy
		var err error
		if lastParser != nil {
			proxy, err = tryParse(lastParser, line)
		}
		if proxy == nil {
			for _, p := range registry {
				proxy, err = tryParse(p, line)
				if err == nil {
					lastParser = p
					break
				}
			}
		}
		if err != nil {
			continue
		}
		// mirror Sub-Store's parseAll filter: hysteria2 proxies with an obfs
		// but no obfs-password are dropped (applied regardless of which
		// parser handled the line)
		if proxy != nil && proxy.Type() == "hysteria2" {
			if proxy.GetString("obfs") != "" && proxy.GetString("obfs-password") == "" {
				proxy = nil
			}
		}
		if proxy != nil {
			proxies = append(proxies, proxy)
		}
	}
	return proxies
}

func tryParse(p *Parser, line string) (*model.Proxy, error) {
	if !p.Test(line) {
		return nil, errInvalidBase64
	}
	proxy, err := p.Parse(line)
	if err != nil {
		return nil, err
	}
	normalizeProxy(proxy)
	return proxy, nil
}

// MustRegister registers parsers, panicking on duplicate names.
func MustRegister(ps ...*Parser) {
	for _, p := range ps {
		if p == nil || p.Name == "" {
			panic("parser with empty name")
		}
		Register(p)
	}
}
