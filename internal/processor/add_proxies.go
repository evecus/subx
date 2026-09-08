package processor

import (
	"fmt"

	"substore/internal/model"
)

// ArtifactProxiesLookup resolves a subscription or collection by name into
// parsed proxies with the source's own process already applied. It is the Go
// equivalent of the original's produceArtifact({ type, name, platform:
// 'mihomo', produceType: 'internal' }) (backend/src/restful/sync.js:271).
type ArtifactProxiesLookup func(sourceType, sourceName string) ([]*model.Proxy, error)

// artifactProxiesLookup is installed once by the server layer. Processors
// run without a request context, so — mirroring how the original binds
// produceArtifact into the operator execution context — the lookup is
// injected as a package-level hook and reads after init only.
var artifactProxiesLookup ArtifactProxiesLookup

// SetArtifactProxiesLookup installs the lookup used by the
// "Add Proxies From Subscription Operator".
func SetArtifactProxiesLookup(fn ArtifactProxiesLookup) {
	artifactProxiesLookup = fn
}

func init() {
	registry["Add Proxies From Subscription Operator"] = func(args any, _ *Context) (Processor, error) {
		return addProxiesFromSubscription(args), nil
	}
}

// addProxiesFromSubscription mirrors AddProxiesFromSubscriptionOperator
// (backend/src/core/proxy-utils/processors/index.js:530-578): it pulls the
// named source's proxies and merges them relative to the current list.
//
// Parameters (identical to the original operator):
//   - sourceType: "subscription" (default) or "collection"
//   - sourceName: name of the subscription/collection to pull
//   - position:   "front" | "back" | "replace" (default "replace")
//   - includeUnsupportedProxy: accepted for parity; unsupported-proxy
//     filtering happens at produce time in the Go rewrite.
func addProxiesFromSubscription(args any) Processor {
	m := toMap(args)
	sourceType := fmt.Sprint(m["sourceType"])
	if sourceType == "" {
		sourceType = "subscription"
	}
	sourceName := fmt.Sprint(m["sourceName"])
	position := fmt.Sprint(m["position"])
	if position == "" {
		position = "replace"
	}
	return func(proxies []*model.Proxy) ([]*model.Proxy, error) {
		if sourceName == "" {
			return nil, fmt.Errorf("Add Proxies From Subscription: 未提供来源名称")
		}
		if artifactProxiesLookup == nil {
			return nil, fmt.Errorf("Add Proxies From Subscription: 订阅查询能力不可用")
		}
		pulled, err := artifactProxiesLookup(sourceType, sourceName)
		if err != nil {
			return nil, err
		}
		switch position {
		case "front":
			// config.proxies = [...proxies, ...currentProxies]
			return append(pulled, proxies...), nil
		case "back":
			// config.proxies = [...currentProxies, ...proxies]
			return append(proxies, pulled...), nil
		default: // replace
			return pulled, nil
		}
	}
}
