package producer

import (
	"substore/internal/model"
)

// ProduceStash outputs a Stash config. Stash supports more protocols than
// Clash but not as many as Mihomo. Mirrors producers/stash.js.
func ProduceStash(proxies []*model.Proxy, options map[string]any) (string, error) {
	return clashProduce(proxies, options, clashPlatformStash, "external")
}
