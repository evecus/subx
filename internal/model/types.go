package model

import "encoding/json"

// Operator is a single processing rule (filter or operator) applied to a
// subscription or collection.
type Operator struct {
	Type       string `json:"type"`
	Args       any    `json:"args,omitempty"`
	Disabled   bool   `json:"disabled,omitempty"`
	CustomName string `json:"customName,omitempty"`
}

// Sub represents a subscription.
type Sub struct {
	Name                  string         `json:"name"`
	DisplayName           string         `json:"displayName,omitempty"`
	URL                   string         `json:"url,omitempty"`
	Source                string         `json:"source,omitempty"` // "local" | "remote"
	Content               string         `json:"content,omitempty"`
	UpdateCron            string         `json:"updateCron,omitempty"`    // 5-field cron; empty = no scheduled refresh
	CachedContent         string         `json:"cachedContent,omitempty"` // last cron-refreshed snapshot for remote subs
	CachedAt              int64          `json:"cachedAt,omitempty"`      // unix millis of the last successful cron refresh
	UA                    string         `json:"ua,omitempty"`
	Proxy                 string         `json:"proxy,omitempty"`
	Process               []Operator     `json:"process,omitempty"`
	NoCache               bool           `json:"noCache,omitempty"`
	MergeSources          string         `json:"mergeSources,omitempty"`
	PassThroughUA         bool           `json:"passThroughUA,omitempty"`
	SubUserinfo           string         `json:"subUserinfo,omitempty"`
	IgnoreFailedRemoteSub string         `json:"ignoreFailedRemoteSub,omitempty"`
	Tags                  []string       `json:"tag,omitempty"`
	Extra                 map[string]any `json:"-"`
}

// MarshalJSON flattens Extra fields into the JSON object.
func (s Sub) MarshalJSON() ([]byte, error) {
	type alias Sub
	m := map[string]any{}
	b, err := json.Marshal((*alias)(&s))
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(b, &m)
	for k, v := range s.Extra {
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

// Collection aggregates multiple subscriptions.
type Collection struct {
	Name                  string         `json:"name"`
	DisplayName           string         `json:"displayName,omitempty"`
	Subscriptions         []string       `json:"subscriptions"`
	Process               []Operator     `json:"process,omitempty"`
	Proxy                 string         `json:"proxy,omitempty"`
	SubUserinfo           string         `json:"subUserinfo,omitempty"`
	IgnoreFailedRemoteSub string         `json:"ignoreFailedRemoteSub,omitempty"`
	SubscriptionTags      []string       `json:"subscriptionTags,omitempty"`
	Extra                 map[string]any `json:"-"`
}

// MarshalJSON flattens Extra fields into the JSON object.
func (c Collection) MarshalJSON() ([]byte, error) {
	type alias Collection
	m := map[string]any{}
	b, err := json.Marshal((*alias)(&c))
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(b, &m)
	for k, v := range c.Extra {
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

// Token represents a share token for a subscription or collection.
type Token struct {
	Token     string         `json:"token"`
	Type      string         `json:"type"` // "sub" | "col" | "file"
	Name      string         `json:"name"`
	Mode      string         `json:"mode,omitempty"` // "duration" | "datetime" | "count"
	Exp       int64          `json:"exp,omitempty"`
	Count     int            `json:"count,omitempty"`
	UsedCount int            `json:"usedCount,omitempty"`
	ExpiresIn string         `json:"expiresIn,omitempty"`
	CreatedAt int64          `json:"createdAt"`
	Payload   map[string]any `json:"-"`
}

// MarshalJSON flattens Payload fields.
func (t Token) MarshalJSON() ([]byte, error) {
	type alias Token
	m := map[string]any{}
	b, err := json.Marshal((*alias)(&t))
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(b, &m)
	for k, v := range t.Payload {
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

// Usable reports whether the token is still usable.
func (t *Token) Usable() bool {
	if t.Exp > 0 && t.Exp <= nowMillis() {
		return false
	}
	if t.Mode == "count" {
		return t.Count > 0 && t.UsedCount >= 0 && t.UsedCount < t.Count
	}
	return true
}

// Settings holds global application settings.
type Settings struct {
	DefaultUserAgent string         `json:"defaultUserAgent,omitempty"`
	DefaultTimeout   int            `json:"defaultTimeout,omitempty"`
	DefaultProxy     string         `json:"defaultProxy,omitempty"`
	CacheThreshold   int            `json:"cacheThreshold,omitempty"`
	GithubProxy      string         `json:"githubProxy,omitempty"`
	GithubProxyRegex string         `json:"githubProxyRegex,omitempty"`
	Extra            map[string]any `json:"-"`
}
