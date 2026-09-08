package processor

import (
	"fmt"
	"strings"
	"testing"

	"substore/internal/model"
)

func proxyNamed(name string) *model.Proxy {
	p := model.NewProxy()
	p.Set("name", name)
	p.Set("type", "ss")
	p.Set("server", "1.2.3.4")
	p.Set("port", 443)
	return p
}

func names(proxies []*model.Proxy) []string {
	out := make([]string, 0, len(proxies))
	for _, p := range proxies {
		out = append(out, p.GetString("name"))
	}
	return out
}

// fakeLookup 模拟「假订阅上下文」：两个订阅 sub-a / sub-b 与一个集合 col-x。
func fakeLookup(t *testing.T) ArtifactProxiesLookup {
	t.Helper()
	return func(sourceType, sourceName string) ([]*model.Proxy, error) {
		switch sourceName {
		case "sub-a":
			return []*model.Proxy{proxyNamed("a1"), proxyNamed("a2")}, nil
		case "sub-b":
			return []*model.Proxy{proxyNamed("b1")}, nil
		default:
			return nil, fmt.Errorf("找不到订阅 %s", sourceName)
		}
	}
}

func runAddProxies(t *testing.T, args map[string]any, current []*model.Proxy) ([]*model.Proxy, error) {
	t.Helper()
	factory, ok := Get("Add Proxies From Subscription Operator")
	if !ok {
		t.Fatalf("operator not registered")
	}
	proc, err := factory(args, &Context{Source: map[string]any{}})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return proc(current)
}

func TestAddProxiesReplace(t *testing.T) {
	SetArtifactProxiesLookup(fakeLookup(t))
	defer SetArtifactProxiesLookup(nil)

	got, err := runAddProxies(t, map[string]any{"sourceName": "sub-a"}, []*model.Proxy{proxyNamed("c1")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := names(got); strings.Join(got, ",") != "a1,a2" {
		t.Fatalf("replace position: got %v", got)
	}
}

func TestAddProxiesFrontAndBack(t *testing.T) {
	SetArtifactProxiesLookup(fakeLookup(t))
	defer SetArtifactProxiesLookup(nil)

	current := []*model.Proxy{proxyNamed("c1")}

	got, err := runAddProxies(t, map[string]any{"sourceName": "sub-a", "position": "front"}, current)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := names(got); strings.Join(got, ",") != "a1,a2,c1" {
		t.Fatalf("front position: got %v", got)
	}

	got, err = runAddProxies(t, map[string]any{"sourceName": "sub-a", "position": "back"}, current)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := names(got); strings.Join(got, ",") != "c1,a1,a2" {
		t.Fatalf("back position: got %v", got)
	}
}

// 两个订阅先后合并：多次使用该算子即可叠加多个来源。
func TestAddProxiesTwoSubscriptions(t *testing.T) {
	SetArtifactProxiesLookup(fakeLookup(t))
	defer SetArtifactProxiesLookup(nil)

	proxies := []*model.Proxy{proxyNamed("c1")}
	proxies, err := runAddProxies(t, map[string]any{"sourceName": "sub-a", "position": "back"}, proxies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	proxies, err = runAddProxies(t, map[string]any{"sourceName": "sub-b", "position": "back"}, proxies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := names(proxies); strings.Join(got, ",") != "c1,a1,a2,b1" {
		t.Fatalf("two subscriptions merged: got %v", got)
	}
}

// 找不到订阅时报错（对齐原版 produceArtifact 的「找不到订阅 x」）。
func TestAddProxiesMissingSourceErrors(t *testing.T) {
	SetArtifactProxiesLookup(fakeLookup(t))
	defer SetArtifactProxiesLookup(nil)

	_, err := runAddProxies(t, map[string]any{"sourceName": "nope"}, []*model.Proxy{proxyNamed("c1")})
	if err == nil {
		t.Fatalf("expected error for missing source")
	}
	if !strings.Contains(err.Error(), "找不到订阅 nope") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestAddProxiesRequiresSourceName(t *testing.T) {
	SetArtifactProxiesLookup(fakeLookup(t))
	defer SetArtifactProxiesLookup(nil)

	if _, err := runAddProxies(t, map[string]any{}, nil); err == nil {
		t.Fatalf("expected error when sourceName is empty")
	}
}
