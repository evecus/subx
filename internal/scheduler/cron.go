// Package scheduler implements a minimal, dependency-free cron scheduler
// used to periodically refresh remote subscriptions on a user-defined
// schedule (standard 5-field cron syntax: minute hour day month weekday).
package scheduler

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// field bounds for each of the 5 standard cron fields.
var fieldBounds = [5][2]int{
	{0, 59}, // minute
	{0, 23}, // hour
	{1, 31}, // day of month
	{1, 12}, // month
	{0, 6},  // day of week (0 = Sunday)
}

// Schedule is a parsed 5-field cron expression.
type Schedule struct {
	minutes  map[int]bool
	hours    map[int]bool
	days     map[int]bool
	months   map[int]bool
	weekdays map[int]bool
}

// Parse parses a standard 5-field cron expression ("0 0 * * *"). It returns
// an error for anything else, including the 6-field (seconds-first) variant.
func Parse(expr string) (*Schedule, error) {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron expression must have exactly 5 fields (minute hour day month weekday), got %d", len(fields))
	}
	sched := &Schedule{}
	sets := [5]*map[int]bool{&sched.minutes, &sched.hours, &sched.days, &sched.months, &sched.weekdays}
	for i, f := range fields {
		set, err := parseField(f, fieldBounds[i][0], fieldBounds[i][1])
		if err != nil {
			return nil, fmt.Errorf("field %d (%q): %w", i+1, f, err)
		}
		*sets[i] = set
	}
	return sched, nil
}

// Valid reports whether expr is a syntactically valid 5-field cron
// expression, without allocating a Schedule for the caller.
func Valid(expr string) bool {
	_, err := Parse(expr)
	return err == nil
}

func parseField(f string, lo, hi int) (map[int]bool, error) {
	out := map[int]bool{}
	for _, part := range strings.Split(f, ",") {
		if part == "" {
			return nil, fmt.Errorf("empty term")
		}
		step := 1
		base := part
		if i := strings.IndexByte(part, '/'); i >= 0 {
			base = part[:i]
			s, err := strconv.Atoi(part[i+1:])
			if err != nil || s <= 0 {
				return nil, fmt.Errorf("invalid step %q", part[i+1:])
			}
			step = s
		}
		start, end := lo, hi
		switch {
		case base == "*":
			// full range, already set
		case strings.Contains(base, "-"):
			bits := strings.SplitN(base, "-", 2)
			if len(bits) != 2 {
				return nil, fmt.Errorf("invalid range %q", base)
			}
			a, err1 := strconv.Atoi(bits[0])
			b, err2 := strconv.Atoi(bits[1])
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid range %q", base)
			}
			start, end = a, b
		default:
			v, err := strconv.Atoi(base)
			if err != nil {
				return nil, fmt.Errorf("invalid value %q", base)
			}
			start, end = v, v
		}
		if start < lo || end > hi || start > end {
			return nil, fmt.Errorf("value out of range [%d-%d]", lo, hi)
		}
		for v := start; v <= end; v += step {
			out[v] = true
		}
	}
	return out, nil
}

// Next returns the next time strictly after `after` that matches the
// schedule, searching at minute resolution up to 4 years ahead.
func (s *Schedule) Next(after time.Time) time.Time {
	t := after.Truncate(time.Minute).Add(time.Minute)
	limit := after.AddDate(4, 0, 0)
	for t.Before(limit) {
		if s.matches(t) {
			return t
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}
}

func (s *Schedule) matches(t time.Time) bool {
	if !s.minutes[t.Minute()] {
		return false
	}
	if !s.hours[t.Hour()] {
		return false
	}
	if !s.months[int(t.Month())] {
		return false
	}
	dayOK := s.days[t.Day()]
	weekdayOK := s.weekdays[int(t.Weekday())]
	dayUnrestricted := len(s.days) == 31        // day-of-month field was "*" (1-31)
	weekdayUnrestricted := len(s.weekdays) == 7 // day-of-week field was "*" (0-6)
	switch {
	case dayUnrestricted && weekdayUnrestricted:
		return true
	case dayUnrestricted:
		return weekdayOK
	case weekdayUnrestricted:
		return dayOK
	default:
		// standard cron: when both day-of-month and day-of-week are
		// restricted, a match on either one is sufficient (OR semantics).
		return dayOK || weekdayOK
	}
}
