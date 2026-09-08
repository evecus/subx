package server

import (
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"substore/internal/config"
	"substore/internal/share"
	"substore/internal/store"
	"substore/web"
)

// Server wires routes, middleware and handlers.
type Server struct {
	Cfg    *config.Config
	Store  *store.Store
	Share  *share.Resolver
	router *gin.Engine

	loginLimiter    *rateLimiter
	downloadLimiter *rateLimiter
}

// New builds a Server and its route tree.
func New(cfg *config.Config, st *store.Store) *Server {
	s := &Server{
		Cfg:   cfg,
		Store: st,
		Share: share.NewResolver(st),
		// 10 failed-or-otherwise login attempts per IP per 15 minutes.
		loginLimiter: newRateLimiter(10, 15*time.Minute),
		// 120 requests per IP per minute against the public
		// download/share endpoints.
		downloadLimiter: newRateLimiter(120, time.Minute),
	}
	s.router = s.buildRouter()
	return s
}

// Run starts the HTTP server.
func (s *Server) Run() error {
	addr := fmt.Sprintf("%s:%d", s.Cfg.Host, s.Cfg.Port)
	if s.Cfg.PathPrefix != "" {
		log.Printf("substore listening on %s (panel under %s%s/)", addr, addr, s.Cfg.PathPrefix)
	} else {
		log.Printf("substore listening on %s", addr)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *Server) buildRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(quietLogger(), gin.Recovery(), securityHeaders())
	r.MaxMultipartMemory = 8 << 20

	// When PathPrefix is set, every route lives under the prefix and the
	// bare root serves nothing (404), so the panel is only reachable at
	// host:port/<prefix>/.
	root := r.Group(s.Cfg.PathPrefix)
	if s.Cfg.PathPrefix != "" {
		// Redirect "host:port/<prefix>" to "host:port/<prefix>/" so the
		// frontend's relative asset URLs resolve correctly.
		r.GET(s.Cfg.PathPrefix, func(c *gin.Context) {
			target := s.Cfg.PathPrefix + "/"
			if qs := c.Request.URL.RawQuery; qs != "" {
				target += "?" + qs
			}
			c.Redirect(http.StatusPermanentRedirect, target)
		})
	}

	api := root.Group("/api")

	// auth
	api.POST("/login", s.loginRateLimit(), s.handleLogin)

	authed := api.Group("")
	authed.Use(s.authMiddleware())
	{
		authed.GET("/me", s.handleMe)

		// subscriptions
		authed.GET("/subs", s.handleListSubs)
		authed.POST("/subs", s.handleCreateSub)
		authed.GET("/sub/:name", s.handleGetSub)
		authed.PATCH("/sub/:name", s.handlePatchSub)
		authed.POST("/sub/:name/update", s.handleUpdateSub)
		authed.DELETE("/sub/:name", s.handleDeleteSub)

		// collections
		authed.GET("/collections", s.handleListCollections)
		authed.POST("/collections", s.handleCreateCollection)
		authed.GET("/col/:name", s.handleGetCollection)
		authed.PATCH("/col/:name", s.handlePatchCollection)
		authed.DELETE("/col/:name", s.handleDeleteCollection)

		// files
		authed.GET("/files", s.handleListFiles)
		authed.POST("/files", s.handleCreateFile)
		authed.GET("/file/:name", s.handleGetFile)
		authed.PATCH("/file/:name", s.handlePatchFile)
		authed.DELETE("/file/:name", s.handleDeleteFile)

		// preview
		authed.GET("/node-info/:name", s.handleNodeInfo)

		// tokens
		authed.GET("/tokens", s.handleListTokens)
		authed.POST("/token", s.handleCreateToken)
		authed.DELETE("/token/:token", s.handleDeleteToken)

		// targets
		authed.GET("/targets", s.handleTargets)

		// settings
		authed.GET("/settings", s.handleGetSettings)
		authed.PATCH("/settings", s.handlePatchSettings)
	}

	// shared endpoints
	root.GET("/download/:name", s.downloadRateLimit(), s.handleDownload)
	root.GET("/api/file/:name/raw", s.handleFileRaw)
	root.GET("/share/sub/:name", s.downloadRateLimit(), s.handleShareDownload)
	root.GET("/share/col/:name", s.downloadRateLimit(), s.handleShareDownload)
	root.GET("/share/file/:name", s.downloadRateLimit(), s.handleShareDownload)

	// static frontend
	s.mountFrontend(root, r)

	return r
}

// quietLogger only logs requests that fail (status >= 400), so normal
// traffic doesn't spam stdout the way gin.Logger() does.
func quietLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		c.Next()
		status := c.Writer.Status()
		if status >= http.StatusBadRequest {
			log.Printf("%d %s %s (%s)", status, c.Request.Method, path, time.Since(start).Round(time.Millisecond))
		}
	}
}

// mountFrontend serves the embedded web frontend under the group root
// (which is the configured PathPrefix, possibly empty).
func (s *Server) mountFrontend(root *gin.RouterGroup, r *gin.Engine) {
	var dist fs.FS
	if web.HasIndex() {
		dist = web.Dist()
	}
	if dist == nil {
		log.Printf("frontend not found (embedded dist is empty), API only")
		return
	}
	prefix := s.Cfg.PathPrefix
	fileServer := http.FileServer(http.FS(dist))
	// serveIndexHTML writes the embedded index.html directly instead of
	// delegating to http.FileServer, whose /index.html normalization
	// would issue a redirect on every SPA fallback.
	serveIndexHTML := func(c *gin.Context) {
		data, err := fs.ReadFile(dist, "index.html")
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	}
	if prefix != "" {
		// Without this, gin's trailing-slash redirect turns
		// "<prefix>/" into "<prefix>" which our own redirect turns
		// back into "<prefix>/" — an infinite loop.
		root.GET("/", serveIndexHTML)
	}
	// NoRoute is engine-wide; the handler itself enforces the prefix so
	// requests outside it (including the bare root) get a 404.
	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"message": "not found"})
			return
		}
		// Strip the configured prefix so the embedded dist (whose asset
		// URLs are relative, built with vite base './') can be served.
		if prefix != "" {
			if path == prefix+"/" {
				path = "/"
			} else if strings.HasPrefix(path, prefix+"/") {
				path = path[len(prefix):]
			} else {
				// Anything outside the prefix (including the bare root)
				// is intentionally not served when a prefix is set.
				c.Status(http.StatusNotFound)
				return
			}
		}
		rel := strings.TrimPrefix(path, "/")
		if rel == "" {
			rel = "index.html"
		}
		if f, err := fs.Stat(dist, rel); err == nil && !f.IsDir() {
			c.Request.URL.Path = path
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}
		if _, err := fs.Stat(dist, "index.html"); err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		// SPA fallback (only reachable for deep paths; the panel itself
		// uses hash routing).
		serveIndexHTML(c)
	})
}

// ---- auth helpers ----

// BootstrapAdmin logs a warning if the admin account is still using the
// default credentials. The admin account is never persisted to the
// database: username/password always come straight from Cfg (set via the
// `auth` environment variable, or "admin:admin" by default), so restarting
// with a different `auth` value takes effect immediately and old
// credentials never linger.
func (s *Server) BootstrapAdmin() error {
	if s.Cfg.AdminUsername == "admin" && s.Cfg.AdminPassword == "admin" {
		log.Printf("WARNING: admin account is using the default credentials \"admin:admin\" — set the `auth` environment variable (e.g. auth=myuser:mypassword) to a strong value before exposing this server to the network")
	}
	return nil
}

// ---- context helpers ----

func currentUser(c *gin.Context) string {
	if v, ok := c.Get("username"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func abortError(c *gin.Context, status int, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"message": msg})
}
