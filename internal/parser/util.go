package parser

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"strings"
)

func regexMust(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}


func isIPString(s string) bool {
	return net.ParseIP(strings.Trim(s, "[]")) != nil
}

func isIPv4String(s string) bool {
	ip := net.ParseIP(strings.Trim(s, "[]"))
	return ip != nil && ip.To4() != nil
}

func isIPv6String(s string) bool {
	ip := net.ParseIP(strings.Trim(s, "[]"))
	return ip != nil && ip.To4() == nil
}

func urlUnescape(s string) (string, error) {
	return url.PathUnescape(s)
}


func base64Std(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}

// flagEmojiMap is used by the Flag operator.
var flagEmojiMap = map[string]string{
	"HK": "🇭🇰", "TW": "🇹🇼", "US": "🇺🇸", "SG": "🇸🇬", "JP": "🇯🇵",
	"UK": "🇬🇧", "DE": "🇩🇪", "KR": "🇰🇷", "RU": "🇷🇺", "CA": "🇨🇦",
	"AU": "🇦🇺", "FR": "🇫🇷", "IN": "🇮🇳", "NL": "🇳🇱", "TR": "🇹🇷",
	"BR": "🇧🇷", "CN": "🇨🇳", "MO": "🇲🇴", "TH": "🇹🇭", "VN": "🇻🇳",
	"PH": "🇵🇭", "ID": "🇮🇩", "MY": "🇲🇾", "MX": "🇲🇽", "IT": "🇮🇹",
	"ES": "🇪🇸", "SE": "🇸🇪", "NO": "🇳🇴", "FI": "🇫🇮", "DK": "🇩🇰",
	"PL": "🇵🇱", "CH": "🇨🇭", "AT": "🇦🇹", "BE": "🇧🇪", "IE": "🇮🇪",
	"CZ": "🇨🇿", "PT": "🇵🇹", "GR": "🇬🇷", "IL": "🇮🇱", "AE": "🇦🇪",
	"SA": "🇸🇦", "NG": "🇳🇬", "ZA": "🇿🇦", "AR": "🇦🇷", "CL": "🇨🇱",
	"CO": "🇨🇴", "NZ": "🇳🇿", "HK2": "🇭🇰",
}

// Base64Decode attempts to decode a base64 string, trying the standard,
// URL-safe, and raw variants (with and without padding).
func Base64Decode(s string) (string, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	return "", errInvalidBase64
}

// Base64DecodeOrSelf decodes s; when decoding fails it returns s unchanged.
func Base64DecodeOrSelf(s string) string {
	out, err := Base64Decode(s)
	if err != nil {
		return s
	}
	return out
}

// DecodeURIFragment decodes the #fragment of a URI line (percent-decoded).
// Mirrors decodeURIComponent: "+" is kept as-is (PathUnescape semantics,
// not QueryUnescape), and malformed escapes are returned undecoded.
func DecodeURIFragment(line string) (content string, fragment string) {
	idx := strings.Index(line, "#")
	if idx == -1 {
		return line, ""
	}
	frag := line[idx+1:]
	if d, err := url.PathUnescape(frag); err == nil {
		frag = d
	}
	return line[:idx], frag
}

// ParseURIParams parses a query string into key/value pairs.
func ParseURIParams(query string) map[string]string {
	params := map[string]string{}
	if query == "" {
		return params
	}
	q := strings.TrimPrefix(query, "?")
	for _, pair := range strings.Split(q, "&") {
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		key := kv[0]
		val := ""
		if len(kv) == 2 {
			val = kv[1]
		}
		if d, err := url.QueryUnescape(val); err == nil {
			val = d
		}
		params[key] = val
	}
	return params
}

// SplitHostPort splits "host:port" handling IPv6 brackets.
func SplitHostPort(hostport string) (host string, port string, ok bool) {
	hostport = strings.TrimSpace(hostport)
	if strings.HasPrefix(hostport, "[") {
		idx := strings.Index(hostport, "]")
		if idx == -1 {
			return hostport, "", false
		}
		host = hostport[1:idx]
		rest := hostport[idx+1:]
		if strings.HasPrefix(rest, ":") {
			port = rest[1:]
		}
		return host, port, true
	}
	idx := strings.LastIndex(hostport, ":")
	if idx == -1 {
		return hostport, "", false
	}
	return hostport[:idx], hostport[idx+1:], true
}

// JSONUnmarshalLoose decodes JSON into a map, tolerating JSON5-ish input by
// falling back to stripping comments/trailing commas.
func JSONUnmarshalLoose(s string, v any) error {
	if err := json.Unmarshal([]byte(s), v); err == nil {
		return nil
	}
	cleaned := stripJSON5Comments(s)
	if err := json.Unmarshal([]byte(cleaned), v); err == nil {
		return nil
	}
	return errInvalidJSON
}

var jsonCommentRe = regexp.MustCompile(`(?m)(^\s*//.*$|,\s*[}\]])`)

func stripJSON5Comments(s string) string {
	// remove line comments and trailing commas (best effort)
	out := jsonCommentRe.ReplaceAllString(s, "")
	return out
}
