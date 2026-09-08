package producer

import (
	"substore/internal/model"
)

// ProduceShadowrocket outputs a Shadowrocket Clash-format config list.
// Mirrors producers/shadowrocket.js (Shadowrocket supports many protocols
// via Clash format and additional transports).
func ProduceShadowrocket(proxies []*model.Proxy, options map[string]any) (string, error) {
	return clashProduce(proxies, options, clashPlatformShadowrocket, "external")
}
