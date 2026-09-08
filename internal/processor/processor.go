package processor

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"substore/internal/model"
)

// Processor transforms a list of proxies.
type Processor func(proxies []*model.Proxy) ([]*model.Proxy, error)

// Context carries pipeline context into script-based processors.
type Context struct {
	Source  map[string]any
	Options map[string]any
	Raw     any
}

// Registry maps operator type names to factory functions.
type Registry map[string]func(args any, ctx *Context) (Processor, error)

var registry = Registry{}

func init() {
	registry["Useless Filter"] = func(_ any, _ *Context) (Processor, error) { return UselessFilter, nil }
	registry["Region Filter"] = func(args any, _ *Context) (Processor, error) { return regionFilter(args), nil }
	registry["Regex Filter"] = func(args any, _ *Context) (Processor, error) { return regexFilter(args), nil }
	registry["Type Filter"] = func(args any, _ *Context) (Processor, error) { return typeFilter(args), nil }
	registry["Conditional Filter"] = func(args any, _ *Context) (Processor, error) { return conditionalFilter(args) }
	registry["Script Filter"] = func(args any, ctx *Context) (Processor, error) { return scriptFilter(args, ctx), nil }

	registry["Quick Setting Operator"] = func(args any, _ *Context) (Processor, error) { return quickSettingOperator(args), nil }
	registry["Flag Operator"] = func(args any, _ *Context) (Processor, error) { return flagOperator(args), nil }
	registry["Sort Operator"] = func(args any, _ *Context) (Processor, error) { return sortOperator(args), nil }
	registry["Regex Sort Operator"] = func(args any, _ *Context) (Processor, error) { return regexSortOperator(args), nil }
	registry["Regex Rename Operator"] = func(args any, _ *Context) (Processor, error) { return regexRenameOperator(args, false), nil }
	registry["Regex Delete Operator"] = func(args any, _ *Context) (Processor, error) { return regexRenameOperator(args, true), nil }
	registry["Handle Duplicate Operator"] = func(args any, _ *Context) (Processor, error) { return handleDuplicateOperator(args), nil }
	registry["Resolve Domain Operator"] = func(args any, _ *Context) (Processor, error) { return resolveDomainOperator(args), nil }
	registry["Script Operator"] = func(args any, ctx *Context) (Processor, error) { return scriptOperator(args, ctx), nil }
}

// Get returns a processor factory by name.
func Get(name string) (func(args any, ctx *Context) (Processor, error), bool) {
	f, ok := registry[name]
	return f, ok
}

// Known reports whether an operator type is recognized.
func Known(name string) bool {
	_, ok := registry[name]
	return ok
}

// Apply runs a list of operators over proxies.
//
// Mirrors index.js:1716-1724: processors whose name contains "Filter" run
// through ApplyFilter (which builds a fresh result array), everything else
// runs through ApplyOperator, which deep-clones its input first
// (index.js:1676 `let output = clone(objs)`).
func Apply(proxies []*model.Proxy, operators []model.Operator, ctx *Context) ([]*model.Proxy, error) {
	for _, op := range operators {
		if op.Disabled {
			continue
		}
		factory, ok := registry[op.Type]
		if !ok {
			return nil, fmt.Errorf("unknown operator: %s", op.Type)
		}
		proc, err := factory(op.Args, ctx)
		if err != nil {
			return nil, fmt.Errorf("operator %s: %w", op.Type, err)
		}
		if strings.Contains(op.Type, "Filter") {
			proxies, err = proc(proxies)
		} else {
			proxies, err = proc(cloneProxies(proxies))
		}
		if err != nil {
			return nil, fmt.Errorf("operator %s: %w", op.Type, err)
		}
	}
	return proxies, nil
}

// cloneProxies deep-copies a proxy list, mirroring the original clone(objs).
func cloneProxies(proxies []*model.Proxy) []*model.Proxy {
	out := make([]*model.Proxy, len(proxies))
	for i, p := range proxies {
		out[i] = p.Clone()
	}
	return out
}

// UselessFilter drops proxies whose fields contain non-ASCII junk or whose
// names indicate placeholder entries (index.js:1366-1398).
func UselessFilter(proxies []*model.Proxy) ([]*model.Proxy, error) {
	out := make([]*model.Proxy, 0, len(proxies))
	for _, p := range proxies {
		if v := p.GetString("cipher"); v != "" && !isASCII(v) {
			continue
		}
		if v := p.GetString("password"); v != "" && !isASCII(v) {
			continue
		}
		// index.js:1376-1390: non-ASCII transport Host headers.
		if network := p.GetString("network"); network != "" {
			if transportHostNonASCII(p, network) {
				continue
			}
		}
		// index.js:1391-1393: plain substring test on the name.
		if isPlaceholderName(p.GetString("name")) {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// transportHostNonASCII mirrors index.js:1377-1389: hosts come from
// `${network}-opts`.headers.Host || headers.host (first truthy wins),
// are wrapped into an array, and any truthy non-ASCII entry drops the proxy.
func transportHostNonASCII(p *model.Proxy, network string) bool {
	opts := p.GetMap(network + "-opts")
	if opts == nil {
		return false
	}
	headers, _ := opts["headers"].(map[string]any)
	if headers == nil {
		return false
	}
	var host any
	if v, ok := headers["Host"]; ok && jsTruthy(v) {
		host = v
	} else if v, ok := headers["host"]; ok && jsTruthy(v) {
		host = v
	}
	if host == nil {
		return false
	}
	hosts, ok := host.([]any)
	if !ok {
		hosts = []any{host}
	}
	for _, h := range hosts {
		if !jsTruthy(h) {
			continue
		}
		if s := fmt.Sprint(h); !isASCII(s) {
			return true
		}
	}
	return false
}

// jsTruthy mirrors JS truthiness for the values transport headers carry.
func jsTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case int:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	case json.Number:
		f, _ := t.Float64()
		return f != 0
	default:
		return true
	}
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}

func isPlaceholderName(s string) bool {
	for _, kw := range []string{"网址", "流量", "时间", "应急", "过期", "Bandwidth", "expire"} {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func regionFilter(args any) Processor {
	m := toMap(args)
	keep := true
	if v, ok := m["keep"].(bool); ok {
		keep = v
	}
	regions := map[string]bool{}
	for _, v := range toStringSlice(m["value"]) {
		regions[strings.ToUpper(v)] = true
	}
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		// filters return a fresh array (index.js ApplyFilter -> objs.filter)
		out := make([]*model.Proxy, 0, len(proxies))
		for _, p := range proxies {
			flag := getFlag(p.GetString("name"))
			matched := false
			for code, emoji := range flagEmojiMap {
				if emoji == flag && regions[code] {
					matched = true
					break
				}
			}
			if matched == keep {
				out = append(out, p)
			}
		}
		return out, nil
	}
}

var flagEmojiMap = map[string]string{
	"HK": "🇭🇰", "TW": "🇹🇼", "US": "🇺🇸", "SG": "🇸🇬", "JP": "🇯🇵",
	"UK": "🇬🇧", "DE": "🇩🇪", "KR": "🇰🇷", "RU": "🇷🇺", "CA": "🇨🇦",
	"AU": "🇦🇺", "FR": "🇫🇷", "IN": "🇮🇳", "NL": "🇳🇱", "TR": "🇹🇷",
	"BR": "🇧🇷", "CN": "🇨🇳", "MO": "🇲🇴", "TH": "🇹🇭", "VN": "🇻🇳",
}

// getFlag extracts a leading flag emoji from a name, e.g. "🇭🇰 香港".
func getFlag(name string) string {
	for _, emoji := range flagEmojiMap {
		if strings.HasPrefix(name, emoji) {
			return emoji
		}
	}
	return ""
}

func regexFilter(args any) Processor {
	m := toMap(args)
	keep := true
	if v, ok := m["keep"].(bool); ok {
		keep = v
	}
	var regexes []*regexp.Regexp
	for _, r := range toStringSlice(m["regex"]) {
		if re, err := buildRegex(r); err == nil {
			regexes = append(regexes, re)
		}
	}
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		out := make([]*model.Proxy, 0, len(proxies))
		for _, p := range proxies {
			matched := false
			for _, re := range regexes {
				if re.MatchString(p.GetString("name")) {
					matched = true
					break
				}
			}
			if matched == keep {
				out = append(out, p)
			}
		}
		return out, nil
	}
}

func typeFilter(args any) Processor {
	m := toMap(args)
	keep := true
	if v, ok := m["keep"].(bool); ok {
		keep = v
	}
	types := map[string]bool{}
	for _, t := range toStringSlice(m["value"]) {
		types[t] = true
	}
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		out := make([]*model.Proxy, 0, len(proxies))
		for _, p := range proxies {
			if types[p.Type()] == keep {
				out = append(out, p)
			}
		}
		return out, nil
	}
}

func conditionalFilter(args any) (Processor, error) {
	m := toMap(args)
	rule, ok := m["rule"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("conditional filter requires a rule")
	}
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		out := make([]*model.Proxy, 0, len(proxies))
		for _, p := range proxies {
			if matchRule(rule, p) {
				out = append(out, p)
			}
		}
		return out, nil
	}, nil
}

func matchRule(rule map[string]any, p *model.Proxy) bool {
	op, _ := rule["operator"].(string)
	if op == "" {
		// leaf
		attr, _ := rule["attr"].(string)
		prop, _ := rule["proposition"].(string)
		value := rule["value"]
		switch prop {
		case "IN":
			return contains(value, p.Get(attr))
		case "CONTAINS":
			return strings.Contains(p.GetString(attr), fmt.Sprint(value))
		case "EQUALS":
			return fmt.Sprint(p.Get(attr)) == fmt.Sprint(value)
		case "EXISTS":
			// index.js:112-116: `proxy[attr] !== null || typeof proxy[attr]
			// !== 'undefined'` is always true — EXISTS matches every proxy.
			return true
		}
		return false
	}
	children, _ := rule["child"].([]any)
	switch op {
	case "AND":
		for _, c := range children {
			if cm, ok := c.(map[string]any); ok && !matchRule(cm, p) {
				return false
			}
		}
		return true
	case "OR":
		for _, c := range children {
			if cm, ok := c.(map[string]any); ok && matchRule(cm, p) {
				return true
			}
		}
		return false
	case "NOT":
		if cm, ok := children[0].(map[string]any); ok {
			return !matchRule(cm, p)
		}
	}
	return false
}

func contains(haystack, needle any) bool {
	switch v := haystack.(type) {
	case []any:
		for _, item := range v {
			if fmt.Sprint(item) == fmt.Sprint(needle) {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if item == fmt.Sprint(needle) {
				return true
			}
		}
	default:
		return fmt.Sprint(haystack) == fmt.Sprint(needle)
	}
	return false
}

func quickSettingOperator(args any) Processor {
	m := toMap(args)
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		if toBoolValue(m["useless"]) {
			var err error
			proxies, err = UselessFilter(proxies)
			if err != nil {
				return nil, err
			}
			kept := make([]*model.Proxy, 0, len(proxies))
			for _, p := range proxies {
				if port := p.Port(); port > 0 && port <= 65535 {
					kept = append(kept, p)
				}
			}
			proxies = kept
		}
		for _, p := range proxies {
			setIfPresent(p, m, "udp")
			setIfPresent(p, m, "tfo")
			if v := m["scert"]; v != nil {
				p.Set("skip-cert-verify", toBoolValue(v))
			}
			if v := m["ip-version"]; v != nil && fmt.Sprint(v) != "" {
				p.Set("ip-version", v)
			}
		}
		return proxies, nil
	}
}

func setIfPresent(p *model.Proxy, m map[string]any, key string) {
	v, ok := m[key]
	if !ok {
		return
	}
	switch fmt.Sprint(v) {
	case "ENABLED":
		p.Set(key, true)
	case "DISABLED":
		p.Set(key, false)
	}
}

func flagOperator(args any) Processor {
	m := toMap(args)
	mode := fmt.Sprint(m["mode"])
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		for _, p := range proxies {
			name := p.GetString("name")
			flag := getFlag(name)
			noFlag := strings.TrimSpace(strings.TrimPrefix(name, flag))
			if mode == "remove" {
				p.Set("name", noFlag)
				continue
			}
			if flag == "" {
				flag = getFlagByCode(p.GetString("_subName"))
			}
			if flag == "" {
				flag = inferFlag(name)
			}
			// tw handling
			if tw := fmt.Sprint(m["tw"]); tw == "ws" {
				flag = strings.ReplaceAll(flag, "🇹🇼", "🇼🇸")
			} else if tw == "" && flag == "🇹🇼" {
				flag = "🇨🇳"
			}
			p.Set("name", flag+" "+noFlag)
		}
		return proxies, nil
	}
}

func inferFlag(name string) string {
	// try to detect from name keywords
	for _, kw := range []struct {
		code string
		kw   string
	}{{"HK", "香港"}, {"HK", "hongkong"}, {"HK", "hk"}, {"TW", "台湾"}, {"TW", "taiwan"}, {"JP", "日本"}, {"JP", "japan"}, {"US", "美国"}, {"US", "united"}, {"US", "usa"}, {"SG", "新加坡"}, {"SG", "singapore"}, {"KR", "韩国"}, {"KR", "korea"}, {"UK", "英国"}, {"UK", "uk"}, {"DE", "德国"}, {"DE", "germany"}} {
		if strings.Contains(strings.ToLower(name), strings.ToLower(kw.kw)) {
			return flagEmojiMap[kw.code]
		}
	}
	return ""
}

func getFlagByCode(code string) string {
	if emoji, ok := flagEmojiMap[strings.ToUpper(code)]; ok {
		return emoji
	}
	return ""
}

func sortOperator(args any) Processor {
	order := fmt.Sprint(toMap(args)["order"])
	if order == "" {
		order = "asc"
	}
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		switch order {
		case "random":
			shuffle(proxies)
		case "desc":
			sort.SliceStable(proxies, func(i, j int) bool {
				return proxies[i].GetString("name") > proxies[j].GetString("name")
			})
		default:
			sort.SliceStable(proxies, func(i, j int) bool {
				return proxies[i].GetString("name") < proxies[j].GetString("name")
			})
		}
		return proxies, nil
	}
}

func regexSortOperator(args any) Processor {
	exprs := []*regexp.Regexp{}
	if arr, ok := args.([]any); ok {
		for _, e := range arr {
			if re, err := buildRegex(fmt.Sprint(e)); err == nil {
				exprs = append(exprs, re)
			}
		}
	} else {
		m := toMap(args)
		for _, e := range toStringSlice(m["expressions"]) {
			if re, err := buildRegex(e); err == nil {
				exprs = append(exprs, re)
			}
		}
	}
	// index.js:338: const order = input.order || 'asc'
	order := strArg(toMap(args), "order", "asc")
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		sort.SliceStable(proxies, func(i, j int) bool {
			oI := regexOrder(exprs, proxies[i].GetString("name"))
			oJ := regexOrder(exprs, proxies[j].GetString("name"))
			if oI > 0 && oJ == 0 {
				return true
			}
			if oJ > 0 && oI == 0 {
				return false
			}
			if oI > 0 && oJ > 0 {
				return oI < oJ
			}
			// index.js:356-357: keep the original order when neither
			// matches and order is 'original' (comparator returns 0,
			// i.e. "not less" for both sides with a stable sort).
			if order == "original" {
				return false
			}
			if order == "desc" {
				return proxies[i].GetString("name") > proxies[j].GetString("name")
			}
			return proxies[i].GetString("name") < proxies[j].GetString("name")
		})
		return proxies, nil
	}
}

func regexOrder(exprs []*regexp.Regexp, s string) int {
	for i, re := range exprs {
		if re.MatchString(s) {
			return i + 1
		}
	}
	return 0
}

func regexRenameOperator(args any, deleteMode bool) Processor {
	var rules []struct {
		expr *regexp.Regexp
		now  string
	}
	if deleteMode {
		for _, r := range toStringSlice(args) {
			if re, err := buildRegex(r); err == nil {
				rules = append(rules, struct {
					expr *regexp.Regexp
					now  string
				}{re, ""})
			}
		}
	} else {
		for _, item := range toSlice(args) {
			m := toMap(item)
			expr, _ := m["expr"].(string)
			now := fmt.Sprint(m["now"])
			if re, err := buildRegex(expr); err == nil {
				rules = append(rules, struct {
					expr *regexp.Regexp
					now  string
				}{re, now})
			}
		}
	}
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		for _, p := range proxies {
			name := p.GetString("name")
			for _, r := range rules {
				name = r.expr.ReplaceAllString(name, r.now)
			}
			p.Set("name", strings.TrimSpace(name))
		}
		return proxies, nil
	}
}

func handleDuplicateOperator(args any) Processor {
	// index.js:242-252 defaults (JS destructuring: defaults apply when the
	// value is undefined, i.e. the key is missing or nil).
	m := toMap(args)
	action := strArg(m, "action", "rename")
	template := strArg(m, "template", "0 1 2 3 4 5 6 7 8 9")
	link := strArg(m, "link", "-")
	position := strArg(m, "position", "back")
	fields := toStringSlice(m["field"])
	if len(fields) == 0 {
		fields = []string{"name"}
	}
	numbers := strings.Split(template, " ")
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		if action == "delete" {
			out := make([]*model.Proxy, 0, len(proxies))
			seen := map[string]bool{}
			for _, p := range proxies {
				key := joinFields(p, fields)
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, p)
			}
			return out, nil
		}
		// rename, index.js:268-308: count occurrences (1-based) and track
		// the widest number of digits for zero padding.
		counter := map[string]int{}
		maxLen := 0
		for _, p := range proxies {
			key := joinFields(p, fields)
			counter[key]++
			if l := len(fmt.Sprint(counter[key])); l > maxLen {
				maxLen = l
			}
		}
		increment := map[string]int{}
		for _, p := range proxies {
			key := joinFields(p, fields)
			if counter[key] <= 1 {
				continue
			}
			if _, ok := increment[key]; !ok {
				increment[key] = 1
			}
			cnt := increment[key]
			increment[key]++
			// build the number from the template digits (index.js:289-296)
			num := ""
			numDigits := 0
			for cnt > 0 {
				tok := "undefined"
				if idx := cnt % 10; idx < len(numbers) {
					tok = numbers[idx]
				}
				num = tok + num
				cnt /= 10
				numDigits++
			}
			// padding with the first template digit (index.js:297-300)
			for numDigits < maxLen {
				pad := "undefined"
				if len(numbers) > 0 {
					pad = numbers[0]
				}
				num = pad + num
				numDigits++
			}
			if position == "front" {
				p.Set("name", num+link+p.GetString("name"))
			} else if position == "back" {
				p.Set("name", p.GetString("name")+link+num)
			}
		}
		return proxies, nil
	}
}

func joinFields(p *model.Proxy, fields []string) string {
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		// index.js:260 lodash.get(p, f, '-') — missing fields yield '-'.
		if v := p.Get(f); v != nil {
			parts = append(parts, fmt.Sprint(v))
		} else {
			parts = append(parts, "-")
		}
	}
	return strings.Join(parts, "_")
}

// ---- helpers ----

func toMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// strArg reads a string option, applying the default when the key is
// missing, nil, or empty (mirrors JS `value || default`).
func strArg(m map[string]any, key, def string) string {
	if v, ok := m[key]; ok && v != nil {
		if s := fmt.Sprint(v); s != "" {
			return s
		}
	}
	return def
}

func toSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

func toStringSlice(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, item := range t {
			out = append(out, fmt.Sprint(item))
		}
	case []string:
		out = t
	case string:
		if t != "" {
			out = []string{t}
		}
	}
	return out
}

func toBoolValue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return isTrue(t)
	case int:
		return t != 0
	case float64:
		return t != 0
	default:
		return false
	}
}

func isTrue(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "1" || s == "true" || s == "yes" || s == "on"
}

func buildRegex(s string) (*regexp.Regexp, error) {
	if strings.HasPrefix(s, "(?i)") {
		return regexp.Compile("(?i)" + strings.TrimPrefix(s, "(?i)"))
	}
	return regexp.Compile(s)
}

func shuffle(proxies []*model.Proxy) {
	for i := len(proxies) - 1; i > 0; i-- {
		j := randInt(i + 1)
		proxies[i], proxies[j] = proxies[j], proxies[i]
	}
}
