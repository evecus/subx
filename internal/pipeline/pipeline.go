package pipeline

import (
	"fmt"
	"strings"

	"substore/internal/model"
	"substore/internal/parser"
	"substore/internal/processor"
	"substore/internal/producer"
)

// Request carries everything needed to process a subscription.
type Request struct {
	Raw            string
	Target         string
	IncludeProxies bool
	UrlBase        string
	Options        map[string]any
	Operators      []model.Operator
	PrependLines   []string
	AppendLines    []string
	Useless        bool
	// SubName / SubDisplayName tag every parsed proxy with `_subName` /
	// `_subDisplayName` after parsing and before any operator runs
	// (restful/sync.js:453-456).
	SubName        string
	SubDisplayName string
}

// Process runs the full parse -> process -> produce pipeline.
func Process(req Request) (string, error) {
	if req.Target == "" {
		return "", fmt.Errorf("target format not specified")
	}
	if !producer.Known(req.Target) {
		return "", fmt.Errorf("unsupported target: %s", req.Target)
	}

	proxies := Parse(req.Raw)
	// restful/sync.js:453-456: tag the source subscription before the
	// useless filter / operators run.
	if req.SubName != "" {
		for _, p := range proxies {
			p.Set("_subName", req.SubName)
			p.Set("_subDisplayName", req.SubDisplayName)
		}
	}
	if req.Useless {
		var err error
		proxies, err = processor.UselessFilter(proxies)
		if err != nil {
			return "", err
		}
	}
	var err error
	proxies, err = processor.Apply(proxies, req.Operators, &processor.Context{
		Source: map[string]any{},
	})
	if err != nil {
		return "", err
	}

	produce, _ := producer.Get(req.Target)
	body, err := produce(proxies, req.Options)
	if err != nil {
		return "", err
	}

	lines := make([]string, 0, len(req.PrependLines)+len(req.AppendLines)+1)
	lines = append(lines, req.PrependLines...)
	lines = append(lines, body)
	lines = append(lines, req.AppendLines...)

	// share download replaces url with the original sub link when possible
	if req.UrlBase != "" {
		for i := range lines {
			if strings.HasPrefix(strings.TrimSpace(lines[i]), "url = ") {
				lines[i] = "url = " + req.UrlBase
			}
		}
	}

	return strings.Join(lines, "\n"), nil
}

// Parse preprocesses raw text and parses it into proxies.
func Parse(raw string) []*model.Proxy {
	text := parser.Preprocess(raw)
	return parser.ParseText(text)
}
