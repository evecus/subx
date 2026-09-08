package server

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// rateLimiter is a simple in-memory fixed-window rate limiter keyed by an
// arbitrary string (typically client IP, optionally combined with a
// per-account key for login attempts). It's intentionally dependency-free.
//
// This is process-local: it resets on restart and doesn't share state across
// multiple server instances. That's an acceptable tradeoff for a
// single-process, single-admin deployment like this one.
type rateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	visitors map[string]*visitor
}

type visitor struct {
	count     int
	windowEnd time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		limit:    limit,
		window:   window,
		visitors: map[string]*visitor{},
	}
	go rl.cleanupLoop()
	return rl
}

// allow reports whether the request for key is within the limit, and
// increments its counter as a side effect. It also returns the remaining
// seconds until the current window resets, for use in a Retry-After header.
func (rl *rateLimiter) allow(key string) (bool, int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	v, ok := rl.visitors[key]
	if !ok || now.After(v.windowEnd) {
		v = &visitor{count: 0, windowEnd: now.Add(rl.window)}
		rl.visitors[key] = v
	}
	v.count++
	remaining := int(time.Until(v.windowEnd).Seconds())
	if remaining < 0 {
		remaining = 0
	}
	return v.count <= rl.limit, remaining
}

// reset clears the counter for key, used to forgive successful logins so a
// legitimate user isn't penalized by earlier typos.
func (rl *rateLimiter) reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.visitors, key)
}

func (rl *rateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for k, v := range rl.visitors {
			if now.After(v.windowEnd) {
				delete(rl.visitors, k)
			}
		}
		rl.mu.Unlock()
	}
}

// clientIP extracts the request's client IP, preferring a proxy-forwarded
// header only when running behind a trusted reverse proxy is expected; for
// simplicity and to avoid trivial spoofing of the rate-limit key we key on
// gin's own resolved ClientIP, which already understands X-Forwarded-For
// when gin's trusted-proxy list is configured (default: trust none, using
// RemoteAddr directly).
func clientIP(c *gin.Context) string {
	ip := c.ClientIP()
	if ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return c.Request.RemoteAddr
	}
	return host
}

// loginRateLimit throttles POST /api/login by client IP to slow down
// credential brute-forcing. On success, handleLogin resets the counter for
// the caller's key so legitimate users don't stay throttled after a typo.
func (s *Server) loginRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := "login:" + clientIP(c)
		ok, retryAfter := s.loginLimiter.allow(key)
		if !ok {
			c.Header("Retry-After", intToStr(retryAfter))
			abortError(c, http.StatusTooManyRequests, "too many login attempts, please try again later")
			return
		}
		c.Set("rateLimitKey", key)
		c.Next()
	}
}

// downloadRateLimit throttles the public download/share endpoints by client
// IP to reduce abuse (share-token guessing, scraping, or upstream-fetch
// amplification against configured subscription URLs).
func (s *Server) downloadRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := "download:" + clientIP(c)
		ok, retryAfter := s.downloadLimiter.allow(key)
		if !ok {
			c.Header("Retry-After", intToStr(retryAfter))
			abortError(c, http.StatusTooManyRequests, "too many requests, please try again later")
			return
		}
		c.Next()
	}
}

// securityHeaders sets a minimal, uncontroversial set of hardening headers
// on every response.
func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Next()
	}
}

func intToStr(n int) string {
	if n <= 0 {
		n = 1
	}
	return strconv.Itoa(n)
}
