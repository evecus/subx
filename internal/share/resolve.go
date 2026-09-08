package share

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"substore/internal/downloader"
	"substore/internal/model"
	"substore/internal/pipeline"
	"substore/internal/processor"
	"substore/internal/producer"
	"substore/internal/store"
)

// Resolver resolves shared download requests for tokens.
type Resolver struct {
	Store *store.Store
	Fetch func(ctx context.Context, sub model.Sub) (string, error)
}

// NewResolver creates a resolver backed by the given store.
func NewResolver(s *store.Store) *Resolver {
	return &Resolver{
		Store: s,
		Fetch: func(ctx context.Context, sub model.Sub) (string, error) {
			return downloader.NewClient().Fetch(ctx, sub)
		},
	}
}

// TargetName returns the token payload for a token string.
func (r *Resolver) Lookup(token string) (map[string]any, error) {
	return r.Store.GetToken(token)
}

// CheckAndConsume validates that a token is currently usable and, for
// count-mode tokens, atomically increments its usage. It's used by share
// paths (like plain file downloads) that don't go through Resolve's
// pipeline processing.
func (r *Resolver) CheckAndConsume(tokenStr string) error {
	rec, err := r.Store.GetToken(tokenStr)
	if err != nil {
		return err
	}
	if rec == nil {
		return fmt.Errorf("invalid token")
	}
	var t model.Token
	if err := remarshal(rec, &t); err != nil {
		return err
	}
	if !t.Usable() {
		return fmt.Errorf("token expired")
	}
	if t.Mode == "count" {
		t.UsedCount++
		updated, _ := json.Marshal(t)
		var m map[string]any
		_ = json.Unmarshal(updated, &m)
		for k, v := range rec {
			if _, ok := m[k]; !ok {
				m[k] = v
			}
		}
		if err := r.Store.UpdateToken(m); err != nil {
			return err
		}
	}
	return nil
}

// Resolve processes a shared download for the given token and target.
func (r *Resolver) Resolve(ctx context.Context, tokenStr, target string) (string, error) {
	rec, err := r.Store.GetToken(tokenStr)
	if err != nil {
		return "", err
	}
	if rec == nil {
		return "", fmt.Errorf("invalid token")
	}

	var t model.Token
	if err := remarshal(rec, &t); err != nil {
		return "", err
	}
	if !t.Usable() {
		return "", fmt.Errorf("token expired")
	}

	var (
		body   string
		pErr   error
		ok     bool
		opsAny []any
	)
	if opsAny, ok = rec["process"].([]any); !ok {
		opsAny = nil
	}
	operators := decodeOperators(opsAny)

	prependLines := decodeLines(rec["prependLines"])
	appendLines := decodeLines(rec["appendLines"])

	switch t.Type {
	case "sub":
		raw, rawErr := r.resolveSubRaw(ctx, t.Name)
		if rawErr != nil {
			return "", rawErr
		}
		body, pErr = pipeline.Process(pipeline.Request{
			Raw:          raw,
			Target:       target,
			IncludeProxies: true,
			Operators:    operators,
			PrependLines: prependLines,
			AppendLines:  appendLines,
			Useless:      false,
		})
	case "col":
		// 原版 sync.js: 每个子订阅先 parse 各自原始文本（base64 逐块解码）
		// 并应用自身 process（646-674 行），再按原始顺序合并代理对象
		// （759-763 行），最后应用集合自身 process 并产出（771-805 行）。
		colRec, colErr := r.Store.GetCollection(t.Name)
		if colErr != nil {
			return "", colErr
		}
		if colRec == nil {
			return "", fmt.Errorf("组合订阅 %q 不存在", t.Name)
		}
		var col model.Collection
		if err := remarshal(colRec, &col); err != nil {
			return "", err
		}
		proxies, proxiesErr := r.CollectionProxies(ctx, col)
		if proxiesErr != nil {
			return "", proxiesErr
		}
		if len(proxies) == 0 {
			return "", fmt.Errorf("组合订阅 %s 中不含有效节点", t.Name)
		}
		body, pErr = ProcessProxies(proxies, target, nil, operators, prependLines, appendLines)
	default:
		return "", fmt.Errorf("unsupported token type: %s", t.Type)
	}
	if pErr != nil {
		return "", pErr
	}
	if t.Mode == "count" {
		t.UsedCount++
		updated, _ := json.Marshal(t)
		var m map[string]any
		_ = json.Unmarshal(updated, &m)
		for k, v := range rec {
			if _, ok := m[k]; !ok {
				m[k] = v
			}
		}
		_ = r.Store.UpdateToken(m)
	}
	return body, nil
}

func (r *Resolver) resolveSubRaw(ctx context.Context, name string) (string, error) {
	rec, err := r.Store.GetSub(name)
	if err != nil || rec == nil {
		return "", fmt.Errorf("subscription %q not found", name)
	}
	var sub model.Sub
	if err := remarshal(rec, &sub); err != nil {
		return "", err
	}
	raw, err := r.Fetch(ctx, sub)
	if err != nil {
		return "", err
	}
	// mergeSources is disabled for shared downloads (no override injection)
	return raw, nil
}

// SubProxies fetches, parses and processes a single subscription the way
// produceArtifact does for produceType 'internal' (restful/sync.js:448-466):
// parse the raw text (base64 blobs are decoded per chunk, matching the
// original's per-chunk parse at sync.js:646-648), tag _subName, then apply
// the subscription's own process operators.
func (r *Resolver) SubProxies(ctx context.Context, sub model.Sub) ([]*model.Proxy, error) {
	raw, err := r.Fetch(ctx, sub)
	if err != nil {
		return nil, err
	}
	proxies := pipeline.Parse(raw)
	for _, p := range proxies {
		p.Set("_subName", sub.Name)
		p.Set("_subDisplayName", sub.DisplayName)
	}
	return processor.Apply(proxies, sub.Process, &processor.Context{
		Source: map[string]any{},
	})
}

// CollectionProxies merges the collection's subscriptions in their original
// order, each with its own process already applied — the proxy-object merge
// of restful/sync.js:759-763. Subscriptions that cannot be fetched are
// skipped, matching the previous tolerant behavior.
func (r *Resolver) CollectionProxies(ctx context.Context, col model.Collection) ([]*model.Proxy, error) {
	var proxies []*model.Proxy
	for _, subName := range col.Subscriptions {
		subRec, err := r.Store.GetSub(subName)
		if err != nil || subRec == nil {
			continue
		}
		var sub model.Sub
		if err := remarshal(subRec, &sub); err != nil {
			continue
		}
		subProxies, err := r.SubProxies(ctx, sub)
		if err != nil {
			continue
		}
		proxies = append(proxies, subProxies...)
	}
	for _, p := range proxies {
		p.Set("_collectionName", col.Name)
		p.Set("_collectionDisplayName", col.DisplayName)
	}
	return proxies, nil
}

// LookupArtifactProxies resolves a source by name into parsed proxies with
// the source's own process applied, mirroring produceArtifact with
// produceType 'internal' (restful/sync.js:271, error messages at :299 and
// :524). It backs the "Add Proxies From Subscription Operator".
func (r *Resolver) LookupArtifactProxies(sourceType, sourceName string) ([]*model.Proxy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	switch sourceType {
	case "collection", "col":
		rec, err := r.Store.GetCollection(sourceName)
		if err != nil {
			return nil, err
		}
		if rec == nil {
			return nil, fmt.Errorf("找不到组合订阅 %s", sourceName)
		}
		var col model.Collection
		if err := remarshal(rec, &col); err != nil {
			return nil, err
		}
		proxies, err := r.CollectionProxies(ctx, col)
		if err != nil {
			return nil, err
		}
		if len(proxies) == 0 {
			return nil, fmt.Errorf("组合订阅 %s 中不含有效节点", sourceName)
		}
		return processor.Apply(proxies, col.Process, &processor.Context{
			Source: map[string]any{},
		})
	default: // "subscription", "sub"
		rec, err := r.Store.GetSub(sourceName)
		if err != nil {
			return nil, err
		}
		if rec == nil {
			return nil, fmt.Errorf("找不到订阅 %s", sourceName)
		}
		var sub model.Sub
		if err := remarshal(rec, &sub); err != nil {
			return nil, err
		}
		proxies, err := r.SubProxies(ctx, sub)
		if err != nil {
			return nil, err
		}
		if len(proxies) == 0 {
			return nil, fmt.Errorf("订阅 %s 中不含有效节点", sourceName)
		}
		return proxies, nil
	}
}

// ProcessProxies applies operators to an already-parsed proxy list and
// produces the target output — pipeline.Process minus the parse step, for
// collection flows where merging happens on proxies instead of raw text.
func ProcessProxies(proxies []*model.Proxy, target string, options map[string]any, operators []model.Operator, prependLines, appendLines []string) (string, error) {
	if target == "" {
		return "", fmt.Errorf("target format not specified")
	}
	proxies, err := processor.Apply(proxies, operators, &processor.Context{
		Source: map[string]any{},
	})
	if err != nil {
		return "", err
	}
	produce, ok := producer.Get(target)
	if !ok {
		return "", fmt.Errorf("unsupported target: %s", target)
	}
	body, err := produce(proxies, options)
	if err != nil {
		return "", err
	}
	lines := make([]string, 0, len(prependLines)+len(appendLines)+1)
	lines = append(lines, prependLines...)
	lines = append(lines, body)
	lines = append(lines, appendLines...)
	return strings.Join(lines, "\n"), nil
}

// FetchSub downloads the raw content of a subscription.
func (r *Resolver) FetchSub(ctx context.Context, sub model.Sub) (string, error) {
	return r.Fetch(ctx, sub)
}

// PreviewSub fetches and parses a subscription without producing output.
func (r *Resolver) PreviewSub(ctx context.Context, sub model.Sub) ([]*model.Proxy, error) {
	raw, err := r.Fetch(ctx, sub)
	if err != nil {
		return nil, err
	}
	return pipeline.Parse(raw), nil
}

// Remarshal converts a map into a struct via JSON.
func Remarshal(m map[string]any, v any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func remarshal(m map[string]any, v any) error {
	return Remarshal(m, v)
}

func decodeOperators(ops []any) []model.Operator {
	out := make([]model.Operator, 0, len(ops))
	for _, o := range ops {
		b, _ := json.Marshal(o)
		var op model.Operator
		if err := json.Unmarshal(b, &op); err == nil {
			out = append(out, op)
		}
	}
	return out
}

func decodeLines(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
