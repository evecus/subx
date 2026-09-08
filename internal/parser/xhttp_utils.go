package parser

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// This file mirrors the xhttp-related helpers from Sub-Store:
// xhttp-utils.js (range/integer normalization), ech-utils.js (ECH config
// parsing) and the URI_VLESS internal helpers.

const jsSafeIntegerMax = 9007199254740991

func isPlainObject(v any) bool {
	_, ok := v.(map[string]any)
	return ok
}

func isNotBlankAny(v any) bool {
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) != ""
}

func isNotBlank(s string) bool {
	return strings.TrimSpace(s) != ""
}

// isSafeIntegerFloat reports whether f is an integral float within the JS
// safe-integer range (JSON numbers arrive as float64).
func isSafeIntegerFloat(f float64) bool {
	return f == math.Trunc(f) && f >= -jsSafeIntegerMax && f <= jsSafeIntegerMax
}

func numberToString(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func parseUnsignedIntegerToken(token string) (int64, bool) {
	normalized := strings.TrimSpace(token)
	if !regexp.MustCompile(`^\+?\d+$`).MatchString(normalized) {
		return 0, false
	}
	n, err := strconv.ParseInt(normalized, 10, 64)
	if err != nil || n > jsSafeIntegerMax {
		return 0, false
	}
	return n, true
}

// parseNormalizedXhttpRangeBounds mirrors parseNormalizedXhttpRangeBounds in
// xhttp-utils.js.
func parseNormalizedXhttpRangeBounds(value any, allowZeroLowerBound, allowZeroUpperBound bool) (int64, int64, bool) {
	var normalized string
	switch t := value.(type) {
	case string:
		normalized = strings.TrimSpace(t)
	case float64:
		if !isSafeIntegerFloat(t) {
			return 0, 0, false
		}
		normalized = numberToString(t)
	case int:
		normalized = strconv.Itoa(t)
	default:
		return 0, 0, false
	}

	minLower := int64(0)
	if !allowZeroLowerBound {
		minLower = 1
	}
	minUpper := int64(0)
	if !allowZeroUpperBound {
		minUpper = 1
	}

	rangeParts := strings.Split(normalized, "-")
	if len(rangeParts) == 1 {
		n, ok := parseUnsignedIntegerToken(rangeParts[0])
		minValue := minLower
		if minUpper > minValue {
			minValue = minUpper
		}
		if !ok || n < minValue {
			return 0, 0, false
		}
		return n, n, true
	}
	if len(rangeParts) != 2 {
		return 0, 0, false
	}
	lower, ok1 := parseUnsignedIntegerToken(rangeParts[0])
	upper, ok2 := parseUnsignedIntegerToken(rangeParts[1])
	if !ok1 || !ok2 {
		return 0, 0, false
	}
	if lower < minLower || upper < minUpper || upper < lower {
		return 0, 0, false
	}
	return lower, upper, true
}

// normalizeXhttpRangeValue returns either an int64 or a "L-U" string,
// mirroring the single-value form of the JS helpers.
func normalizeXhttpRangeValue(lower, upper int64, asString bool) any {
	if lower == upper {
		if asString {
			return strconv.FormatInt(upper, 10)
		}
		return lower
	}
	return strconv.FormatInt(lower, 10) + "-" + strconv.FormatInt(upper, 10)
}

// normalizeXhttpPositiveRange mirrors normalizeXhttpPositiveRange.
func normalizeXhttpPositiveRange(value any) (any, bool) {
	lower, upper, ok := parseNormalizedXhttpRangeBounds(value, true, false)
	if !ok {
		return nil, false
	}
	return normalizeXhttpRangeValue(lower, upper, false), true
}

// normalizeXhttpStrictPositiveRangeString mirrors
// normalizeXhttpStrictPositiveRangeString.
func normalizeXhttpStrictPositiveRangeString(value any) (string, bool) {
	lower, upper, ok := parseNormalizedXhttpRangeBounds(value, false, false)
	if !ok {
		return "", false
	}
	return normalizeXhttpRangeValue(lower, upper, true).(string), true
}

// normalizeXhttpStrictPositiveRangeValue mirrors
// normalizeXhttpStrictPositiveRangeValue.
func normalizeXhttpStrictPositiveRangeValue(value any) (any, bool) {
	lower, upper, ok := parseNormalizedXhttpRangeBounds(value, false, false)
	if !ok {
		return nil, false
	}
	return normalizeXhttpRangeValue(lower, upper, false), true
}

// normalizeXhttpNonNegativeRange mirrors normalizeXhttpNonNegativeRange.
func normalizeXhttpNonNegativeRange(value any) (any, bool) {
	lower, upper, ok := parseNormalizedXhttpRangeBounds(value, true, true)
	if !ok {
		return nil, false
	}
	return normalizeXhttpRangeValue(lower, upper, false), true
}

// normalizeXhttpIntegerValue mirrors normalizeXhttpIntegerValue.
func normalizeXhttpIntegerValue(value any, allowNegative bool) (int64, bool) {
	switch t := value.(type) {
	case float64:
		if !isSafeIntegerFloat(t) {
			return 0, false
		}
		n := int64(t)
		if !allowNegative && n < 0 {
			return 0, false
		}
		return n, true
	case int:
		n := int64(t)
		if !allowNegative && n < 0 {
			return 0, false
		}
		return n, true
	case string:
		normalized := strings.TrimSpace(t)
		pattern := `^[+-]?\d+$`
		if !allowNegative {
			pattern = `^\+?\d+$`
		}
		if !regexp.MustCompile(pattern).MatchString(normalized) {
			return 0, false
		}
		n, err := strconv.ParseInt(normalized, 10, 64)
		if err != nil || n > jsSafeIntegerMax || n < -jsSafeIntegerMax {
			return 0, false
		}
		if !allowNegative && n < 0 {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

// splitURIHostList mirrors splitURIHostList in parsers/index.js.
func splitURIHostList(host any) []any {
	switch t := host.(type) {
	case []any:
		var out []any
		for _, item := range t {
			if sub := splitURIHostList(item); sub != nil {
				out = append(out, sub...)
			}
		}
		return out
	case string:
		var hosts []any
		for _, item := range strings.Split(t, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				hosts = append(hosts, item)
			}
		}
		if len(hosts) > 0 {
			return hosts
		}
		return nil
	case nil:
		return nil
	default:
		return []any{host}
	}
}

// parseXrayEchConfigList mirrors ech-utils.js. It returns the kind
// ("config" or "dns") plus the extracted values.
func parseXrayEchConfigList(echConfigList any) (kind, config, dns, queryServerName string, ok bool) {
	s, isStr := echConfigList.(string)
	if !isStr || !isNotBlank(s) {
		return "", "", "", "", false
	}
	if !strings.Contains(s, "://") {
		return "config", s, "", "", true
	}
	parts := strings.Split(s, "+")
	if len(parts) == 1 && isNotBlank(parts[0]) {
		return "dns", "", parts[0], "", true
	}
	if len(parts) == 2 && isNotBlank(parts[0]) && isNotBlank(parts[1]) {
		return "dns", "", parts[1], parts[0], true
	}
	return "", "", "", "", false
}

func isSupportedXrayEchForceQuery(forceQuery any) bool {
	s, ok := forceQuery.(string)
	if !ok {
		return false
	}
	return s == "none" || s == "half" || s == "full"
}

// buildMihomoEchOptsFromXrayFields mirrors ech-utils.js.
func buildMihomoEchOptsFromXrayFields(echConfigList, echForceQuery, echSockopt any) map[string]any {
	kind, config, dns, queryServerName, ok := parseXrayEchConfigList(echConfigList)
	if !ok {
		return nil
	}
	echOpts := map[string]any{"enable": true}
	if kind == "config" {
		echOpts["config"] = config
	} else {
		echOpts["_dns"] = dns
		if queryServerName != "" {
			echOpts["query-server-name"] = queryServerName
		}
	}
	if isSupportedXrayEchForceQuery(echForceQuery) {
		echOpts["_force-query"] = echForceQuery
	}
	if isPlainObject(echSockopt) {
		echOpts["_sockopt"] = echSockopt
	}
	return echOpts
}

// cloneUnsupportedXhttpValue mirrors URI_VLESS cloneUnsupportedXhttpValue.
func cloneUnsupportedXhttpValue(v any) any {
	switch t := v.(type) {
	case []any:
		out := make([]any, 0, len(t))
		for _, e := range t {
			out = append(out, cloneUnsupportedXhttpValue(e))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = cloneUnsupportedXhttpValue(e)
		}
		return out
	default:
		return v
	}
}

// compactUnsupportedXhttpValue mirrors URI_VLESS
// compactUnsupportedXhttpValue: empty objects collapse to nil, arrays are
// kept (with nil entries dropped).
func compactUnsupportedXhttpValue(v any) any {
	switch t := v.(type) {
	case []any:
		var out []any
		for _, e := range t {
			if c := compactUnsupportedXhttpValue(e); c != nil {
				out = append(out, c)
			}
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, e := range t {
			if c := compactUnsupportedXhttpValue(e); c != nil {
				out[k] = c
			}
		}
		if len(out) > 0 {
			return out
		}
		return nil
	default:
		return v
	}
}

// setUnsupportedXhttpField mirrors URI_VLESS setUnsupportedXhttpField.
func setUnsupportedXhttpField(target map[string]any, key string, value any) {
	normalized := compactUnsupportedXhttpValue(cloneUnsupportedXhttpValue(value))
	if normalized != nil {
		target[key] = normalized
	}
}

// isSupportedXrayEchConfigList mirrors ech-utils.js.
func isSupportedXrayEchConfigList(v any) bool {
	_, _, _, _, ok := parseXrayEchConfigList(v)
	return ok
}

// mapXmuxToReuseSettings mirrors URI_VLESS mapXmuxToReuseSettings.
func mapXmuxToReuseSettings(xmux any) map[string]any {
	if !isPlainObject(xmux) {
		return nil
	}
	m := xmux.(map[string]any)
	reuseSettings := map[string]any{}
	xmuxFieldMap := map[string]string{
		"maxConnections": "max-connections",
		"maxConcurrency": "max-concurrency",
		"cMaxReuseTimes": "c-max-reuse-times",
		"hMaxRequestTimes": "h-max-request-times",
		"hMaxReusableSecs": "h-max-reusable-secs",
	}
	for sourceKey, targetKey := range xmuxFieldMap {
		normalizedValue, ok := normalizeXhttpNonNegativeRange(m[sourceKey])
		if !ok {
			continue
		}
		switch nv := normalizedValue.(type) {
		case int64:
			reuseSettings[targetKey] = strconv.FormatInt(nv, 10)
		default:
			reuseSettings[targetKey] = nv
		}
	}
	if hKeepAlivePeriod, ok := normalizeXhttpIntegerValue(m["hKeepAlivePeriod"], true); ok {
		reuseSettings["h-keep-alive-period"] = hKeepAlivePeriod
	}
	if len(reuseSettings) > 0 {
		return reuseSettings
	}
	return nil
}

// toStringHeaderMap mirrors URI_VLESS toStringHeaderMap: only string values
// survive; empty maps collapse to nil.
func toStringHeaderMap(headers any) map[string]any {
	if !isPlainObject(headers) {
		return nil
	}
	parsed := map[string]any{}
	for key, value := range headers.(map[string]any) {
		if s, ok := value.(string); ok {
			parsed[key] = s
		}
	}
	if len(parsed) > 0 {
		return parsed
	}
	return nil
}

// collectUnsupportedXhttpHeaders mirrors URI_VLESS.
func collectUnsupportedXhttpHeaders(headers any) any {
	if headers == nil {
		return nil
	}
	if !isPlainObject(headers) {
		return cloneUnsupportedXhttpValue(headers)
	}
	unsupportedHeaders := map[string]any{}
	for key, value := range headers.(map[string]any) {
		if _, ok := value.(string); ok {
			continue
		}
		setUnsupportedXhttpField(unsupportedHeaders, key, value)
	}
	return compactUnsupportedXhttpValue(unsupportedHeaders)
}

func isSupportedXmuxFieldValue(key string, value any) bool {
	switch key {
	case "maxConnections", "maxConcurrency", "cMaxReuseTimes",
		"hMaxRequestTimes", "hMaxReusableSecs":
		_, ok := normalizeXhttpNonNegativeRange(value)
		return ok
	case "hKeepAlivePeriod":
		_, ok := normalizeXhttpIntegerValue(value, true)
		return ok
	}
	return false
}

// collectUnsupportedXmux mirrors URI_VLESS.
func collectUnsupportedXmux(xmux any) any {
	if xmux == nil {
		return nil
	}
	if !isPlainObject(xmux) {
		return cloneUnsupportedXhttpValue(xmux)
	}
	unsupportedXmux := map[string]any{}
	for key, value := range xmux.(map[string]any) {
		if isSupportedXmuxFieldValue(key, value) {
			continue
		}
		setUnsupportedXhttpField(unsupportedXmux, key, value)
	}
	return compactUnsupportedXhttpValue(unsupportedXmux)
}

// collectUnsupportedXhttpExtra mirrors URI_VLESS.
func collectUnsupportedXhttpExtra(extra any) any {
	if extra == nil {
		return nil
	}
	if !isPlainObject(extra) {
		return cloneUnsupportedXhttpValue(extra)
	}
	m := extra.(map[string]any)
	unsupportedExtra := map[string]any{}
	for key, value := range m {
		switch key {
		case "headers":
			if unsupportedHeaders := collectUnsupportedXhttpHeaders(value); unsupportedHeaders != nil {
				unsupportedExtra["headers"] = unsupportedHeaders
			}
		case "noGRPCHeader", "xPaddingObfsMode":
			if value != true {
				setUnsupportedXhttpField(unsupportedExtra, key, value)
			}
		case "xPaddingBytes":
			if _, ok := normalizeXhttpStrictPositiveRangeString(value); !ok {
				setUnsupportedXhttpField(unsupportedExtra, key, value)
			}
		case "xPaddingKey", "xPaddingHeader", "xPaddingPlacement",
			"xPaddingMethod", "uplinkHTTPMethod", "sessionIDPlacement",
			"sessionPlacement", "sessionIDKey", "sessionKey", "seqPlacement",
			"seqKey", "uplinkDataPlacement", "uplinkDataKey", "sessionIDTable":
			if _, ok := value.(string); !ok {
				setUnsupportedXhttpField(unsupportedExtra, key, value)
			}
		case "uplinkChunkSize":
			if _, ok := normalizeXhttpNonNegativeRange(value); !ok {
				setUnsupportedXhttpField(unsupportedExtra, key, value)
			}
		case "scMaxEachPostBytes":
			if _, ok := normalizeXhttpStrictPositiveRangeString(value); !ok {
				setUnsupportedXhttpField(unsupportedExtra, key, value)
			}
		case "scMinPostsIntervalMs":
			if _, ok := normalizeXhttpPositiveRange(value); !ok {
				setUnsupportedXhttpField(unsupportedExtra, key, value)
			}
		case "sessionIDLength":
			if _, ok := normalizeXhttpStrictPositiveRangeString(value); !ok {
				setUnsupportedXhttpField(unsupportedExtra, key, value)
			}
		case "xmux":
			if unsupportedXmux := collectUnsupportedXmux(value); unsupportedXmux != nil {
				unsupportedExtra["xmux"] = unsupportedXmux
			}
		default:
			setUnsupportedXhttpField(unsupportedExtra, key, value)
		}
	}
	return compactUnsupportedXhttpValue(unsupportedExtra)
}

// collectUnsupportedNestedXhttpSettings mirrors URI_VLESS.
func collectUnsupportedNestedXhttpSettings(xhttpSettings any) any {
	if xhttpSettings == nil {
		return nil
	}
	if !isPlainObject(xhttpSettings) {
		return cloneUnsupportedXhttpValue(xhttpSettings)
	}
	m := xhttpSettings.(map[string]any)
	unsupportedXhttpSettings := map[string]any{}
	for _, key := range []string{"path", "host", "mode"} {
		if v, ok := m[key]; ok && !isNotBlankAny(v) {
			setUnsupportedXhttpField(unsupportedXhttpSettings, key, v)
		}
	}
	inlineExtra := map[string]any{}
	for key, value := range m {
		if key == "path" || key == "host" || key == "mode" || key == "extra" {
			continue
		}
		inlineExtra[key] = value
	}
	if unsupportedInlineExtra := collectUnsupportedXhttpExtra(inlineExtra); isPlainObject(unsupportedInlineExtra) {
		for k, v := range unsupportedInlineExtra.(map[string]any) {
			unsupportedXhttpSettings[k] = v
		}
	}
	if v, ok := m["extra"]; ok {
		if unsupportedExtra := collectUnsupportedXhttpExtra(v); unsupportedExtra != nil {
			unsupportedXhttpSettings["extra"] = unsupportedExtra
		}
	}
	return compactUnsupportedXhttpValue(unsupportedXhttpSettings)
}

// collectUnsupportedDownloadSettings mirrors URI_VLESS.
func collectUnsupportedDownloadSettings(downloadSettings any) any {
	if downloadSettings == nil {
		return nil
	}
	if !isPlainObject(downloadSettings) {
		return cloneUnsupportedXhttpValue(downloadSettings)
	}
	m := downloadSettings.(map[string]any)
	unsupportedDownloadSettings := map[string]any{}
	for key, value := range m {
		switch key {
		case "address":
			if !isNotBlankAny(value) {
				setUnsupportedXhttpField(unsupportedDownloadSettings, key, value)
			}
		case "port":
			if _, ok := normalizeXhttpIntegerValue(value, false); !ok {
				setUnsupportedXhttpField(unsupportedDownloadSettings, key, value)
			}
		case "security":
			normalizedSecurity := ""
			if s, ok := value.(string); ok {
				normalizedSecurity = strings.ToLower(s)
			}
			if normalizedSecurity != "tls" && normalizedSecurity != "reality" {
				setUnsupportedXhttpField(unsupportedDownloadSettings, key, value)
			}
		case "tlsSettings":
			if !isPlainObject(value) {
				setUnsupportedXhttpField(unsupportedDownloadSettings, key, value)
				break
			}
			tlsMap := value.(map[string]any)
			hasSupportedEchConfigList := isSupportedXrayEchConfigList(tlsMap["echConfigList"])
			unsupportedTlsSettings := map[string]any{}
			for tlsKey, tlsValue := range tlsMap {
				switch tlsKey {
				case "serverName", "fingerprint":
					if !isNotBlankAny(tlsValue) {
						setUnsupportedXhttpField(unsupportedTlsSettings, tlsKey, tlsValue)
					}
				case "echConfigList":
					if !isSupportedXrayEchConfigList(tlsValue) {
						setUnsupportedXhttpField(unsupportedTlsSettings, tlsKey, tlsValue)
					}
				case "echForceQuery":
					if !hasSupportedEchConfigList || !isSupportedXrayEchForceQuery(tlsValue) {
						setUnsupportedXhttpField(unsupportedTlsSettings, tlsKey, tlsValue)
					}
				case "echSockopt":
					if !hasSupportedEchConfigList || !isPlainObject(tlsValue) {
						setUnsupportedXhttpField(unsupportedTlsSettings, tlsKey, tlsValue)
					}
				case "alpn":
					valid := false
					if arr, ok := tlsValue.([]any); ok && len(arr) > 0 {
						valid = true
						for _, item := range arr {
							s, ok := item.(string)
							if !ok || s == "" {
								valid = false
								break
							}
						}
					}
					if !valid {
						setUnsupportedXhttpField(unsupportedTlsSettings, tlsKey, tlsValue)
					}
				case "allowInsecure":
					if tlsValue != true {
						setUnsupportedXhttpField(unsupportedTlsSettings, tlsKey, tlsValue)
					}
				default:
					setUnsupportedXhttpField(unsupportedTlsSettings, tlsKey, tlsValue)
				}
			}
			if compacted := compactUnsupportedXhttpValue(unsupportedTlsSettings); compacted != nil {
				unsupportedDownloadSettings["tlsSettings"] = compacted
			}
		case "realitySettings":
			if !isPlainObject(value) {
				setUnsupportedXhttpField(unsupportedDownloadSettings, key, value)
				break
			}
			unsupportedRealitySettings := map[string]any{}
			for realityKey, realityValue := range value.(map[string]any) {
				switch realityKey {
				case "publicKey", "shortId", "serverName", "fingerprint":
					if !isNotBlankAny(realityValue) {
						setUnsupportedXhttpField(unsupportedRealitySettings, realityKey, realityValue)
					}
				default:
					setUnsupportedXhttpField(unsupportedRealitySettings, realityKey, realityValue)
				}
			}
			if compacted := compactUnsupportedXhttpValue(unsupportedRealitySettings); compacted != nil {
				unsupportedDownloadSettings["realitySettings"] = compacted
			}
		case "xhttpSettings":
			if unsupportedXhttpSettings := collectUnsupportedNestedXhttpSettings(value); unsupportedXhttpSettings != nil {
				unsupportedDownloadSettings["xhttpSettings"] = unsupportedXhttpSettings
			}
		case "network":
			normalizedNetwork := ""
			if s, ok := value.(string); ok {
				normalizedNetwork = strings.ToLower(s)
			}
			if normalizedNetwork != "xhttp" && normalizedNetwork != "splithttp" {
				setUnsupportedXhttpField(unsupportedDownloadSettings, key, value)
			}
		default:
			setUnsupportedXhttpField(unsupportedDownloadSettings, key, value)
		}
	}
	return compactUnsupportedXhttpValue(unsupportedDownloadSettings)
}

// collectUnsupportedRootXhttpExtra mirrors URI_VLESS.
func collectUnsupportedRootXhttpExtra(extra any) any {
	if !isPlainObject(extra) {
		return nil
	}
	m := extra.(map[string]any)
	rootInlineExtra := map[string]any{}
	for k, v := range m {
		if k == "downloadSettings" {
			continue
		}
		rootInlineExtra[k] = v
	}
	unsupportedExtra := map[string]any{}
	if u := collectUnsupportedXhttpExtra(rootInlineExtra); isPlainObject(u) {
		unsupportedExtra = u.(map[string]any)
	}
	if v, ok := m["downloadSettings"]; ok {
		if unsupportedDownloadSettings := collectUnsupportedDownloadSettings(v); unsupportedDownloadSettings != nil {
			unsupportedExtra["downloadSettings"] = unsupportedDownloadSettings
		}
	}
	return compactUnsupportedXhttpValue(unsupportedExtra)
}

// applyXhttpExtraFields mirrors URI_VLESS.
func applyXhttpExtraFields(target map[string]any, extra any) {
	if target == nil || !isPlainObject(extra) {
		return
	}
	extraMap := extra.(map[string]any)

	parsedHeaders := toStringHeaderMap(extraMap["headers"])
	if parsedHeaders != nil {
		headers := map[string]any{}
		if existing, ok := target["headers"].(map[string]any); ok {
			for k, v := range existing {
				headers[k] = v
			}
		}
		for key, value := range parsedHeaders {
			if strings.EqualFold(key, "host") {
				_, hasHost := headers["Host"]
				_, hasHostLower := headers["host"]
				if !hasHost && !hasHostLower {
					headers["Host"] = value
				}
				continue
			}
			headers[key] = value
		}
		if len(headers) > 0 {
			target["headers"] = headers
		}
	}

	if extraMap["noGRPCHeader"] == true {
		target["no-grpc-header"] = true
	}
	if xPaddingBytes, ok := normalizeXhttpStrictPositiveRangeString(extraMap["xPaddingBytes"]); ok {
		target["x-padding-bytes"] = xPaddingBytes
	}
	if extraMap["xPaddingObfsMode"] == true {
		target["x-padding-obfs-mode"] = true
	}
	if s, ok := extraMap["xPaddingKey"].(string); ok && isNotBlank(s) {
		target["x-padding-key"] = s
	}
	if s, ok := extraMap["xPaddingHeader"].(string); ok && isNotBlank(s) {
		target["x-padding-header"] = s
	}
	if s, ok := extraMap["xPaddingPlacement"].(string); ok && isNotBlank(s) {
		target["x-padding-placement"] = s
	}
	if s, ok := extraMap["xPaddingMethod"].(string); ok && isNotBlank(s) {
		target["x-padding-method"] = s
	}
	if s, ok := extraMap["uplinkHTTPMethod"].(string); ok && isNotBlank(s) {
		target["uplink-http-method"] = s
	}
	if s, ok := extraMap["sessionIDPlacement"].(string); ok && isNotBlank(s) {
		target["session-placement"] = s
	} else if s, ok := extraMap["sessionPlacement"].(string); ok && isNotBlank(s) {
		target["session-placement"] = s
	}
	if s, ok := extraMap["sessionIDKey"].(string); ok && isNotBlank(s) {
		target["session-key"] = s
	} else if s, ok := extraMap["sessionKey"].(string); ok && isNotBlank(s) {
		target["session-key"] = s
	}
	if s, ok := extraMap["sessionIDTable"].(string); ok {
		target["session-table"] = s
	}
	if sessionIDLength, ok := normalizeXhttpStrictPositiveRangeString(extraMap["sessionIDLength"]); ok {
		target["session-length"] = sessionIDLength
	}
	if s, ok := extraMap["seqPlacement"].(string); ok && isNotBlank(s) {
		target["seq-placement"] = s
	}
	if s, ok := extraMap["seqKey"].(string); ok && isNotBlank(s) {
		target["seq-key"] = s
	}
	if s, ok := extraMap["uplinkDataPlacement"].(string); ok && isNotBlank(s) {
		target["uplink-data-placement"] = s
	}
	if s, ok := extraMap["uplinkDataKey"].(string); ok && isNotBlank(s) {
		target["uplink-data-key"] = s
	}
	if uplinkChunkSize, ok := normalizeXhttpNonNegativeRange(extraMap["uplinkChunkSize"]); ok {
		target["uplink-chunk-size"] = uplinkChunkSize
	}
	if scMaxEachPostBytes, ok := normalizeXhttpStrictPositiveRangeValue(extraMap["scMaxEachPostBytes"]); ok {
		target["sc-max-each-post-bytes"] = scMaxEachPostBytes
	}
	if scMinPostsIntervalMs, ok := normalizeXhttpPositiveRange(extraMap["scMinPostsIntervalMs"]); ok {
		target["sc-min-posts-interval-ms"] = scMinPostsIntervalMs
	}
	if reuseSettings := mapXmuxToReuseSettings(extraMap["xmux"]); reuseSettings != nil {
		target["reuse-settings"] = reuseSettings
	}
}

// parseDownloadSettings mirrors URI_VLESS.
func parseDownloadSettings(downloadSettings any) map[string]any {
	if !isPlainObject(downloadSettings) {
		return nil
	}
	m := downloadSettings.(map[string]any)
	parsed := map[string]any{}
	downloadNetwork := ""
	if s, ok := m["network"].(string); ok {
		downloadNetwork = strings.ToLower(s)
	}
	if downloadNetwork == "xhttp" || downloadNetwork == "splithttp" {
		parsed["network"] = "xhttp"
	}
	if isNotBlankAny(m["address"]) {
		parsed["server"] = fmt.Sprint(m["address"])
	}
	if parsedPort, ok := normalizeXhttpIntegerValue(m["port"], false); ok {
		parsed["port"] = parsedPort
	}
	downloadSecurity := ""
	if s, ok := m["security"].(string); ok {
		downloadSecurity = strings.ToLower(s)
	}
	if downloadSecurity == "tls" || downloadSecurity == "reality" {
		parsed["tls"] = true
	}
	if isPlainObject(m["tlsSettings"]) {
		tls := m["tlsSettings"].(map[string]any)
		if s, ok := tls["serverName"].(string); ok && isNotBlank(s) {
			parsed["servername"] = s
		}
		if s, ok := tls["fingerprint"].(string); ok && isNotBlank(s) {
			parsed["client-fingerprint"] = s
		}
		if arr, ok := tls["alpn"].([]any); ok && len(arr) > 0 {
			allStrings := true
			for _, item := range arr {
				s, isStr := item.(string)
				if !isStr || s == "" {
					allStrings = false
					break
				}
			}
			if allStrings {
				parsed["alpn"] = arr
			}
		}
		if tls["allowInsecure"] == true {
			parsed["skip-cert-verify"] = true
		}
		if echOpts := buildMihomoEchOptsFromXrayFields(tls["echConfigList"], tls["echForceQuery"], tls["echSockopt"]); echOpts != nil {
			parsed["ech-opts"] = echOpts
		}
	}
	var realityOpts map[string]any
	if isPlainObject(m["realitySettings"]) {
		reality := m["realitySettings"].(map[string]any)
		realityOpts = map[string]any{}
		if s, ok := reality["publicKey"].(string); ok && isNotBlank(s) {
			realityOpts["public-key"] = s
		}
		if s, ok := reality["shortId"].(string); ok && isNotBlank(s) {
			realityOpts["short-id"] = s
		}
		if s, ok := reality["serverName"].(string); ok && isNotBlank(s) {
			parsed["servername"] = s
		}
		if s, ok := reality["fingerprint"].(string); ok && isNotBlank(s) {
			parsed["client-fingerprint"] = s
		}
	}
	if downloadSecurity == "reality" {
		if realityOpts == nil {
			realityOpts = map[string]any{}
		}
		parsed["reality-opts"] = realityOpts
	} else if len(realityOpts) > 0 {
		parsed["reality-opts"] = realityOpts
	}
	if isPlainObject(m["xhttpSettings"]) {
		xhttp := m["xhttpSettings"].(map[string]any)
		if s, ok := xhttp["path"].(string); ok && isNotBlank(s) {
			parsed["path"] = s
		}
		if s, ok := xhttp["host"].(string); ok && isNotBlank(s) {
			parsed["host"] = s
		}
		if s, ok := xhttp["mode"].(string); ok && isNotBlank(s) {
			parsed["mode"] = s
		}
		applyXhttpExtraFields(parsed, xhttp)
		if isPlainObject(xhttp["extra"]) {
			applyXhttpExtraFields(parsed, xhttp["extra"])
		}
	}
	if len(parsed) > 0 {
		return parsed
	}
	return nil
}

