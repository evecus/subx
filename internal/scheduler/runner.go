package scheduler

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"substore/internal/model"
	"substore/internal/store"
)

// Fetcher fetches raw subscription content, matching the signature used
// elsewhere in the codebase (see downloader.Client.Fetch).
type Fetcher func(ctx context.Context, sub model.Sub) (string, error)

// Runner periodically checks all subscriptions and refreshes any remote
// subscription whose UpdateCron schedule is due, caching the result into
// CachedContent/CachedAt.
type Runner struct {
	Store *store.Store
	Fetch Fetcher

	// last tracks the last successful refresh time we've already applied,
	// keyed by subscription name, so a restart doesn't immediately re-fire
	// every due job at once (best-effort; not persisted across restarts).
	last map[string]time.Time
}

// NewRunner creates a scheduler runner.
func NewRunner(s *store.Store, fetch Fetcher) *Runner {
	return &Runner{Store: s, Fetch: fetch, last: map[string]time.Time{}}
}

// Start launches the background ticking loop. It checks every minute and
// stops when ctx is cancelled.
func (r *Runner) Start(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	go func() {
		defer ticker.Stop()
		// run an initial pass shortly after startup so schedules due
		// "right now" aren't skipped until the first minute boundary
		r.tick()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.tick()
			}
		}
	}()
}

func (r *Runner) tick() {
	subs, err := r.Store.ListSubs()
	if err != nil {
		log.Printf("scheduler: list subs failed: %v", err)
		return
	}
	now := time.Now()
	for _, rec := range subs {
		var sub model.Sub
		if err := remarshal(rec, &sub); err != nil {
			continue
		}
		if sub.Source != "remote" || sub.UpdateCron == "" || sub.URL == "" {
			continue
		}
		sched, err := Parse(sub.UpdateCron)
		if err != nil {
			continue // invalid cron; skip silently, validated at save time
		}
		if !r.due(sub.Name, sched, now) {
			continue
		}
		r.refresh(rec, sub, now)
	}
}

// due reports whether the schedule fired at or before `now` since the last
// time we ran it (or since startup, if never run in this process).
func (r *Runner) due(name string, sched *Schedule, now time.Time) bool {
	from, ok := r.last[name]
	if !ok {
		// first check in this process: look back one minute so a schedule
		// matching the current minute fires immediately.
		from = now.Add(-time.Minute)
	}
	next := sched.Next(from)
	return !next.IsZero() && !next.After(now)
}

func (r *Runner) refresh(rec map[string]any, sub model.Sub, now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	content, err := r.Fetch(ctx, model.Sub{URL: sub.URL, UA: sub.UA})
	if err != nil {
		log.Printf("scheduler: refresh %q failed: %v", sub.Name, err)
		r.last[sub.Name] = now
		return
	}
	rec["cachedContent"] = content
	rec["cachedAt"] = now.UnixMilli()
	if err := r.Store.UpsertSub(sub.Name, rec, "bottom"); err != nil {
		log.Printf("scheduler: save %q failed: %v", sub.Name, err)
		return
	}
	r.last[sub.Name] = now
	log.Printf("scheduler: refreshed %q", sub.Name)
}

func remarshal(m map[string]any, v any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
