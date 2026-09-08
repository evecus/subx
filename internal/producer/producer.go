package producer

import (
	"fmt"
	"sort"
	"strings"

	"substore/internal/model"
)

// Producer converts a list of proxies into a target format string.
type Producer func(proxies []*model.Proxy, options map[string]any) (string, error)

// Registry maps target names to producers.
type Registry map[string]Producer

// Target describes a canonical output format with a human-readable label.
type Target struct {
	Name  string `json:"name"`
	Label string `json:"label"`
}

var registry = Registry{}

// canonicalTargets is the curated list shown in the UI.  Aliases (e.g.
// "meta", "clashmeta", "v2") are intentionally omitted — they still work at
// the download endpoint via the registry, but should not clutter the picker.
var canonicalTargets = []Target{
	{Name: "mihomo", Label: "Clash / Mihomo"},
	{Name: "clash", Label: "Clash"},
	{Name: "stash", Label: "Stash"},
	{Name: "surge", Label: "Surge"},
	{Name: "surge-mac", Label: "Surge Mac"},
	{Name: "surfboard", Label: "Surfboard"},
	{Name: "loon", Label: "Loon"},
	{Name: "shadowrocket", Label: "Shadowrocket"},
	{Name: "qx", Label: "Quantumult X"},
	{Name: "sing-box", Label: "sing-box"},
	{Name: "v2ray", Label: "V2Ray"},
	{Name: "egern", Label: "Egern"},
	{Name: "json", Label: "JSON"},
	{Name: "uri", Label: "通用链接 (URI)"},
}

// withCommonNormalization wraps a producer with the shared pre-processing
// that index.js produce() applies before dispatching to any target producer
// (unsupported-proxy filtering, disable-sni / ports / name / wireguard
// normalization on deep clones).
func withCommonNormalization(target string, p Producer) Producer {
	return func(proxies []*model.Proxy, options map[string]any) (string, error) {
		return p(prepareProxies(proxies, target, options), options)
	}
}

func init() {
	// JSON
	registry["json"] = withCommonNormalization("json", ProduceJSON)

	// URI / V2Ray
	// index.js registers URI_Producer (type 'SINGLE', plaintext URI lines)
	// under "uri"; the whole-blob base64 form is only the v2ray target.
	registry["uri"] = withCommonNormalization("uri", ProduceURI)
	registry["v2ray"] = withCommonNormalization("v2ray", ProduceV2Ray)
	registry["v2"] = withCommonNormalization("v2ray", ProduceV2Ray)

	// Clash (original, limited protocol support)
	registry["clash"] = withCommonNormalization("clash", ProduceClashYAML)

	// Clash.Meta / Mihomo (supports all protocols)
	registry["mihomo"] = withCommonNormalization("mihomo", ProduceClashMetaYAML)
	registry["meta"] = withCommonNormalization("mihomo", ProduceClashMetaYAML)
	registry["clashmeta"] = withCommonNormalization("mihomo", ProduceClashMetaYAML)
	registry["clash.meta"] = withCommonNormalization("mihomo", ProduceClashMetaYAML)

	// Stash (more protocols than Clash, fewer than Mihomo)
	registry["stash"] = withCommonNormalization("stash", ProduceStash)

	// Surge / SurgeMac — index.js registers SurgeMac under "SurgeMac", which
	// lowercases to "surgemac" on the frontend; "surge-mac" is kept as an alias.
	registry["surge"] = withCommonNormalization("surge", ProduceSurge)
	registry["surge-mac"] = withCommonNormalization("surge-mac", ProduceSurgeMac)
	registry["surgemac"] = withCommonNormalization("surgemac", ProduceSurgeMac)

	// Surfboard
	registry["surfboard"] = withCommonNormalization("surfboard", ProduceSurfboard)

	// Loon
	registry["loon"] = withCommonNormalization("loon", ProduceLoon)

	// Quantumult X
	registry["qx"] = withCommonNormalization("qx", ProduceQX)

	// Sing-box
	registry["sing-box"] = withCommonNormalization("sing-box", ProduceSingBox)
	registry["singbox"] = withCommonNormalization("sing-box", ProduceSingBox)

	// Shadowrocket
	registry["shadowrocket"] = withCommonNormalization("shadowrocket", ProduceShadowrocket)

	// Egern (Surge-compatible format)
	registry["egern"] = withCommonNormalization("egern", ProduceEgern)
}

// Get returns a producer by target name.
func Get(name string) (Producer, bool) {
	p, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	return p, ok
}

// Known reports whether a target is supported.
func Known(name string) bool {
	_, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// Names returns sorted supported target names.
func Names() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Targets returns the curated list of canonical target formats with labels
// for the frontend target picker.  Aliases are excluded so the UI stays clean.
func Targets() []Target {
	out := make([]Target, len(canonicalTargets))
	copy(out, canonicalTargets)
	return out
}

func joinNonEmpty(lines []string) string {
	parts := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			parts = append(parts, l)
		}
	}
	return strings.Join(parts, "\n")
}

func errUnsupported(target string) error {
	return fmt.Errorf("unsupported target: %s", target)
}
