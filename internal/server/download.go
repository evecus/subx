package server

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"substore/internal/model"
	"substore/internal/pipeline"
	"substore/internal/processor"
	"substore/internal/share"
)

// lookupInstallOnce guards the one-time installation of the processor-layer
// subscription lookup used by the "Add Proxies From Subscription Operator".
var lookupInstallOnce sync.Once

// contentTypeFor maps a target to a response Content-Type.
func contentTypeFor(target string) string {
	switch strings.ToLower(target) {
	case "json":
		return "application/json; charset=utf-8"
	case "clash", "clash.meta", "clashmeta", "meta", "mihomo", "stash":
		return "text/yaml; charset=utf-8"
	case "sing-box", "singbox":
		return "application/json; charset=utf-8"
	default:
		// surge, surge-mac, surfboard, loon, qx, shadowrocket, egern,
		// v2ray, v2, uri — all text-based formats
		return "text/plain; charset=utf-8"
	}
}

// handleDownload serves /download/:name (subscription) with optional token or
// bearer auth.
func (s *Server) handleDownload(c *gin.Context) {
	name := c.Param("name")
	target := strings.TrimSpace(c.DefaultQuery("target", "mihomo"))
	if target == "" {
		target = "mihomo"
	}
	authorized := s.authorizeDownload(c, []string{"sub", "col"}, name)
	if !authorized {
		abortError(c, http.StatusUnauthorized, "unauthorized")
		return
	}
	s.ensureArtifactProxiesLookup()
	rec, err := s.Store.GetSub(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if rec != nil {
		s.downloadSub(c, rec, name, target)
		return
	}
	s.downloadCollection(c, name, target)
}

// handleShareDownload serves /share/sub/:name, /share/col/:name and
// /share/file/:name.
func (s *Server) handleShareDownload(c *gin.Context) {
	name := c.Param("name")
	target := strings.TrimSpace(c.Query("target"))
	token := strings.TrimSpace(c.Query("token"))
	if token == "" {
		abortError(c, http.StatusBadRequest, "missing token")
		return
	}
	kind := "sub"
	if strings.HasPrefix(c.FullPath(), "/share/col") {
		kind = "col"
	} else if strings.HasPrefix(c.FullPath(), "/share/file") {
		kind = "file"
	}
	rec, err := s.Share.Lookup(token)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if rec == nil {
		abortError(c, http.StatusUnauthorized, "invalid token")
		return
	}
	if getStr(rec, "type") != kind || getStr(rec, "name") != name {
		abortError(c, http.StatusUnauthorized, "token does not match target")
		return
	}
	if kind == "file" {
		s.shareDownloadFile(c, token, name)
		return
	}
	s.ensureArtifactProxiesLookup()
	// prefer the explicit query target, else the target chosen at token creation
	if target == "" {
		target = getStr(rec, "target")
	}
	if target == "" {
		target = "mihomo"
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()
	body, err := s.Share.Resolve(ctx, token, target)
	if err != nil {
		abortError(c, http.StatusBadRequest, err.Error())
		return
	}
	if c.Query("preview") == "1" {
		renderSharePreview(c, name+"."+fileExt(target), body)
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.%s"`, name, fileExt(target)))
	c.Header("Content-Type", contentTypeFor(target))
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, "%s", body)
}

// shareDownloadFile serves a shared plain-text file's raw content, bypassing
// the proxy pipeline entirely since files aren't subscriptions.
func (s *Server) shareDownloadFile(c *gin.Context, token, name string) {
	if err := s.Share.CheckAndConsume(token); err != nil {
		abortError(c, http.StatusBadRequest, err.Error())
		return
	}
	rec, err := s.Store.GetFile(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if rec == nil {
		abortError(c, http.StatusNotFound, "file not found")
		return
	}
	body := getStr(rec, "content")
	if c.Query("preview") == "1" {
		renderSharePreview(c, name, body)
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, "%s", body)
}

// renderSharePreview serves a pure raw-text preview of a share result, with
// no chrome: just the plain content, like a GitHub raw file view.
func renderSharePreview(c *gin.Context, title, body string) {
	html := `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + template.HTMLEscapeString(title) + `</title>
<style>
:root{color-scheme:light}
html,body{margin:0;padding:0;background:#ffffff}
pre{margin:0;padding:16px;white-space:pre-wrap;word-break:break-all;font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace;font-size:12px;line-height:1.5;color:#1f2328}
</style>
</head>
<body>
<pre>` + template.HTMLEscapeString(body) + `</pre>
</body>
</html>`
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, "%s", html)
}

// authorizeDownload accepts either a valid share token, a JWT bearer, or a
// JWT passed as ?token= (needed for opening /download in a new browser tab,
// where an Authorization header can't be attached). A share token only
// authorizes its own target — its type and name must match the requested
// resource, mirroring Sub-Store's matchesShareToken — so a token issued for
// one subscription can't be reused to download an arbitrary resource.
func (s *Server) authorizeDownload(c *gin.Context, kinds []string, name string) bool {
	header := c.GetHeader("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		_, err := s.validateToken(strings.TrimPrefix(header, "Bearer "))
		return err == nil
	}
	if token := strings.TrimSpace(c.Query("token")); token != "" {
		if _, err := s.validateToken(token); err == nil {
			return true
		}
		rec, err := s.Share.Lookup(token)
		if err != nil || rec == nil {
			return false
		}
		if name != "" && getStr(rec, "name") != name {
			return false
		}
		if len(kinds) > 0 {
			tk := getStr(rec, "type")
			matched := false
			for _, k := range kinds {
				if tk == k {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		return true
	}
	return false
}

func (s *Server) downloadSub(c *gin.Context, rec map[string]any, name, target string) {
	var sub model.Sub
	if err := share.Remarshal(rec, &sub); err != nil {
		abortError(c, http.StatusInternalServerError, "decode failed")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()
	raw, err := s.Share.FetchSub(ctx, sub)
	if err != nil {
		abortError(c, http.StatusBadGateway, "fetch failed: "+err.Error())
		return
	}
	req := pipeline.Request{
		Raw:            raw,
		Target:         target,
		IncludeProxies: true,
		Operators:      sub.Process,
		PrependLines:   decodeLines(rec["prependLines"]),
		AppendLines:    decodeLines(rec["appendLines"]),
		Useless:        false,
		SubName:        sub.Name,
		SubDisplayName: sub.DisplayName,
	}
	body, err := pipeline.Process(req)
	if err != nil {
		abortError(c, http.StatusBadRequest, err.Error())
		return
	}
	if c.Query("preview") == "1" {
		renderSharePreview(c, name+"."+fileExt(target), body)
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.%s"`, name, fileExt(target)))
	c.Header("Content-Type", contentTypeFor(target))
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, "%s", body)
}

func (s *Server) downloadCollection(c *gin.Context, name, target string) {
	rec, err := s.Store.GetCollection(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if rec == nil {
		abortError(c, http.StatusNotFound, "subscription or collection not found")
		return
	}
	var col model.Collection
	if err := share.Remarshal(rec, &col); err != nil {
		abortError(c, http.StatusInternalServerError, "decode failed")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 120*time.Second)
	defer cancel()
	// 原版 restful/sync.js：每个子订阅先 parse 各自原始文本（base64 逐块解码）
	// 并应用自身 process（646-674 行），再按原始顺序合并处理后的代理对象
	// （759-763 行），最后应用集合自身 process 并产出（771-805 行）。
	// 合并在代理对象上进行，避免旧实现的 JSON 序列化往返损耗。
	proxies, err := s.Share.CollectionProxies(ctx, col)
	if err != nil {
		abortError(c, http.StatusBadRequest, err.Error())
		return
	}
	if len(proxies) == 0 {
		abortError(c, http.StatusBadRequest, fmt.Sprintf("组合订阅 %s 中不含有效节点", name))
		return
	}
	body, err := share.ProcessProxies(
		proxies,
		target,
		nil,
		col.Process,
		decodeLines(rec["prependLines"]),
		decodeLines(rec["appendLines"]),
	)
	if err != nil {
		abortError(c, http.StatusBadRequest, err.Error())
		return
	}
	if c.Query("preview") == "1" {
		renderSharePreview(c, name+"."+fileExt(target), body)
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.%s"`, name, fileExt(target)))
	c.Header("Content-Type", contentTypeFor(target))
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, "%s", body)
}

// ensureArtifactProxiesLookup installs the processor-layer subscription
// lookup once, backed by this server's share resolver (store + downloader).
func (s *Server) ensureArtifactProxiesLookup() {
	lookupInstallOnce.Do(func() {
		processor.SetArtifactProxiesLookup(s.Share.LookupArtifactProxies)
	})
}

func decodeLines(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func fileExt(target string) string {
	switch strings.ToLower(target) {
	case "json", "sing-box", "singbox":
		return "json"
	case "clash", "clash.meta", "clashmeta", "meta", "mihomo", "stash":
		return "yaml"
	case "v2ray", "v2", "uri":
		return "txt"
	default:
		return "conf"
	}
}
