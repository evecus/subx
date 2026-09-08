package producer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
)

func base64StdEncode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func base64StdDecode(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawStdEncoding.DecodeString(s)
}

// jsonMarshalNoEscape marshals v the way JS JSON.stringify does: no HTML
// escaping of <, > and & (Go's json.Marshal escapes them as \u003c etc).
// json.Encoder appends a trailing newline which is trimmed here.
func jsonMarshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// jsonMarshalIndentNoEscape is jsonMarshalNoEscape with indentation.
func jsonMarshalIndentNoEscape(v any, prefix, indent string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent(prefix, indent)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// jsonMarshalSorted marshals a map deterministically (Go sorts map keys)
// without HTML escaping, matching JSON.stringify.
func jsonMarshalSorted(m map[string]any) (string, error) {
	b, err := jsonMarshalNoEscape(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
