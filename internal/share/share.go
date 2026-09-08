package share

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"substore/internal/model"
)

// RandomToken generates a cryptographically random share token.
func RandomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// BuildTokenPayload builds the token record for a sub/collection.
func BuildTokenPayload(targetType, name string, opts map[string]any) (model.Token, error) {
	tokenStr, err := RandomToken()
	if err != nil {
		return model.Token{}, err
	}
	t := model.Token{
		Token:     tokenStr,
		Type:      targetType,
		Name:      name,
		CreatedAt: time.Now().UnixMilli(),
	}
	mode, _ := opts["mode"].(string)
	if mode == "" {
		mode = "duration"
	}
	t.Mode = mode
	t.Payload = map[string]any{}
	if v := opts["target"]; v != nil && fmt.Sprint(v) != "" {
		t.Payload["target"] = fmt.Sprint(v)
	}
	switch mode {
	case "duration":
		seconds, _ := toInt64(opts["seconds"])
		permanent, _ := opts["permanent"].(bool)
		switch {
		case permanent || seconds < 0:
			// non-expiring token: Exp stays 0, which Token.Usable() treats as
			// "never expires".
			t.ExpiresIn = "permanent"
			t.Exp = 0
		case seconds == 0:
			// no explicit duration given: fall back to the default window.
			seconds = 3600 * 24 * 7
			t.ExpiresIn = fmt.Sprintf("%ds", seconds)
			t.Exp = time.Now().Add(time.Duration(seconds) * time.Second).UnixMilli()
		default:
			t.ExpiresIn = fmt.Sprintf("%ds", seconds)
			t.Exp = time.Now().Add(time.Duration(seconds) * time.Second).UnixMilli()
		}
	case "datetime":
		if v, ok := opts["exp"].(int64); ok && v > 0 {
			t.Exp = v
		}
	case "count":
		if n, _ := toInt64(opts["count"]); n > 0 {
			t.Count = int(n)
		}
	}
	return t, nil
}

// BuildTokenPayloadFromMap builds a token from arbitrary request JSON.
func BuildTokenPayloadFromMap(targetType, name string, m map[string]any) (model.Token, error) {
	return BuildTokenPayload(targetType, name, m)
}

func toInt64(v any) (int64, error) {
	switch t := v.(type) {
	case int:
		return int64(t), nil
	case int64:
		return t, nil
	case float64:
		return int64(t), nil
	case string:
		var n int64
		_, err := fmt.Sscanf(t, "%d", &n)
		return n, err
	default:
		return 0, fmt.Errorf("invalid number")
	}
}
