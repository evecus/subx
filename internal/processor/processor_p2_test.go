package processor

import (
	"testing"

	"substore/internal/model"
)

func newP2Proxy(name string) *model.Proxy {
	p := model.NewProxy()
	p.Set("type", "ss")
	p.Set("name", name)
	p.Set("server", "1.2.3.4")
	p.Set("port", 443)
	p.Set("cipher", "aes-256-cfb")
	p.Set("password", "pw")
	return p
}

// Item 8: UselessFilter checks transport headers.Host for non-ASCII.
func TestP2UselessFilterTransportHostASCII(t *testing.T) {
	nonASCII := newP2Proxy("ok1")
	nonASCII.Set("network", "ws")
	nonASCII.Set("ws-opts", map[string]any{
		"headers": map[string]any{"Host": []any{"中文.example.com"}},
	})
	ascii := newP2Proxy("ok2")
	ascii.Set("network", "ws")
	ascii.Set("ws-opts", map[string]any{
		"headers": map[string]any{"Host": []any{"hk.example.com"}},
	})
	placeholderASCII := newP2Proxy("expire") // index.js:1391-1393 plain regex test

	out, err := UselessFilter([]*model.Proxy{nonASCII, ascii, placeholderASCII})
	if err != nil {
		t.Fatalf("UselessFilter: %v", err)
	}
	if len(out) != 1 || out[0].GetString("name") != "ok2" {
		names := make([]string, 0, len(out))
		for _, p := range out {
			names = append(names, p.GetString("name"))
		}
		t.Fatalf("expected only ok2 to survive, got %v", names)
	}
}

// Item 9: Conditional Filter EXISTS is always true (index.js:112-116).
func TestP2ConditionalFilterExistsAlwaysTrue(t *testing.T) {
	proxies := []*model.Proxy{newP2Proxy("a"), newP2Proxy("b")}
	proc, err := conditionalFilter(map[string]any{
		"rule": map[string]any{
			"attr":        "this-field-does-not-exist",
			"proposition": "EXISTS",
		},
	})
	if err != nil {
		t.Fatalf("conditionalFilter: %v", err)
	}
	out, err := proc(proxies)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("EXISTS should keep every proxy, kept %d", len(out))
	}
}

// Item 10: Regex Sort with order 'original' keeps the original order of
// proxies that do not match any expression.
func TestP2RegexSortOriginalOrder(t *testing.T) {
	proxies := []*model.Proxy{
		newP2Proxy("B2"),
		newP2Proxy("A1"),
		newP2Proxy("B1"),
		newP2Proxy("A2"),
	}
	proc := regexSortOperator(map[string]any{
		"order":       "original",
		"expressions": []string{"^A"},
	})
	out, err := proc(proxies)
	if err != nil {
		t.Fatalf("regexSort: %v", err)
	}
	got := make([]string, 0, len(out))
	for _, p := range out {
		got = append(got, p.GetString("name"))
	}
	want := []string{"A1", "A2", "B2", "B1"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

// Item 11: Handle Duplicate numbers from 1, zero-pads to the widest count
// and honors the template parameter.
func TestP2HandleDuplicateRename(t *testing.T) {
	names := []string{"n", "n", "n", "m", "m", "m", "m", "m", "m", "m", "m", "m", "m", "m"} // 3x n, 11x m
	var proxies []*model.Proxy
	for _, n := range names {
		proxies = append(proxies, newP2Proxy(n))
	}
	proc := handleDuplicateOperator(map[string]any{})
	out, err := proc(proxies)
	if err != nil {
		t.Fatalf("handleDuplicate: %v", err)
	}
	got := make([]string, 0, len(out))
	for _, p := range out {
		got = append(got, p.GetString("name"))
	}
	// maxLen = len("11") = 2 → zero padded with template[0] ('0')
	want := []string{
		"n-01", "n-02", "n-03",
		"m-01", "m-02", "m-03", "m-04", "m-05", "m-06", "m-07", "m-08", "m-09", "m-10", "m-11",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rename = %v, want %v", got, want)
		}
	}

	// template support: index.js:293 numbers[cnt % 10]
	var tProxies []*model.Proxy
	for i := 0; i < 3; i++ {
		tProxies = append(tProxies, newP2Proxy("x"))
	}
	proc2 := handleDuplicateOperator(map[string]any{"template": "0 a b"})
	out2, err := proc2(tProxies)
	if err != nil {
		t.Fatalf("handleDuplicate template: %v", err)
	}
	got2 := make([]string, 0, len(out2))
	for _, p := range out2 {
		got2 = append(got2, p.GetString("name"))
	}
	// cnt=1 → numbers[1]="a", cnt=2 → numbers[2]="b"; cnt=3 overruns the
	// 3-entry template, and JS `undefined + ""` renders as "undefined".
	want2 := []string{"x-a", "x-b", "x-undefined"}
	for i := range want2 {
		if got2[i] != want2[i] {
			t.Fatalf("template rename = %v, want %v", got2, want2)
		}
	}
}

// Item 12: Apply deep-clones the input before each operator; the caller's
// proxies must not be mutated.
func TestP2ApplyDeepClonesInput(t *testing.T) {
	proxies := []*model.Proxy{newP2Proxy("a")}
	_, err := Apply(proxies, []model.Operator{{
		Type: "Quick Setting Operator",
		Args: map[string]any{"udp": "ENABLED"},
	}}, &Context{Source: map[string]any{}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if proxies[0].Get("udp") != nil {
		t.Fatalf("input proxy was mutated by Apply: udp=%v", proxies[0].Get("udp"))
	}
}

// Item 13: filters build a fresh slice; appending to the result must not
// clobber the input's backing array.
func TestP2FilterReturnsNewSlice(t *testing.T) {
	third := newP2Proxy("drop-me")
	proxies := []*model.Proxy{newP2Proxy("keep1"), newP2Proxy("keep2"), third}
	proc := regexFilter(map[string]any{"regex": []string{"^keep"}, "keep": true})
	out, err := proc(proxies)
	if err != nil {
		t.Fatalf("regexFilter: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 kept, got %d", len(out))
	}
	out = append(out, newP2Proxy("appended"))
	if proxies[2] != third || proxies[2].GetString("name") != "drop-me" {
		t.Fatalf("filter reused the input backing array: %v", proxies[2].GetString("name"))
	}
	if out[2].GetString("name") != "appended" {
		t.Fatalf("append did not take effect")
	}
}
