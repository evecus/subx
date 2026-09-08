package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"substore/internal/model"
	"substore/internal/scheduler"
	"substore/internal/share"
	"substore/internal/store"
)

func (s *Server) handleListSubs(c *gin.Context) {
	subs, err := s.Store.ListSubs()
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	c.JSON(http.StatusOK, subs)
}

func (s *Server) handleCreateSub(c *gin.Context) {
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		abortError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	name := strings.TrimSpace(getStr(body, "name"))
	if name == "" {
		abortError(c, http.StatusBadRequest, "name is required")
		return
	}
	if strings.Contains(name, "/") {
		abortError(c, http.StatusBadRequest, "name 不能包含 / 字符")
		return
	}
	if err := validateAndNormalizeSubBody(body); err != nil {
		abortError(c, http.StatusBadRequest, err.Error())
		return
	}
	existing, err := s.Store.GetSub(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if existing != nil {
		abortError(c, http.StatusConflict, "subscription already exists")
		return
	}
	position := getStr(body, "position")
	if position == "" {
		position = "bottom"
	}
	if err := s.Store.UpsertSub(name, body, position); err != nil {
		abortError(c, http.StatusInternalServerError, "save failed")
		return
	}
	// A freshly created remote subscription is fetched immediately and the
	// raw content is stored locally, so downloads/preview serve the cached
	// node list until the next manual update or cron refresh.
	resp := gin.H{"message": "success", "name": name}
	var sub model.Sub
	if err := share.Remarshal(body, &sub); err == nil && sub.Source == "remote" {
		if werr := s.refreshRemoteSubCache(sub, body); werr != nil {
			resp["warning"] = "订阅已保存，但拉取订阅链接失败：" + werr.Error()
		}
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Server) handleGetSub(c *gin.Context) {
	name := c.Param("name")
	sub, err := s.Store.GetSub(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if sub == nil {
		abortError(c, http.StatusNotFound, "subscription not found")
		return
	}
	c.JSON(http.StatusOK, sub)
}

func (s *Server) handlePatchSub(c *gin.Context) {
	name := c.Param("name")
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		abortError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	existing, err := s.Store.GetSub(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if existing == nil {
		abortError(c, http.StatusNotFound, "subscription not found")
		return
	}
	// rename support
	newName := name
	if n, ok := body["name"].(string); ok && n != "" && n != name {
		if strings.Contains(n, "/") {
			abortError(c, http.StatusBadRequest, "name 不能包含 / 字符")
			return
		}
		if dup, _ := s.Store.GetSub(n); dup != nil {
			abortError(c, http.StatusConflict, "name already taken")
			return
		}
		newName = n
	}
	// Capture the pre-merge source identity so we can tell whether the
	// remote endpoint (url/ua) actually changed after the merge below.
	oldURL := getStr(existing, "url")
	oldUA := getStr(existing, "ua")
	oldSource := getStr(existing, "source")
	for k, v := range body {
		if k == "name" {
			existing["name"] = v
			continue
		}
		existing[k] = v
	}
	// if the request explicitly switches source type, clear the fields that
	// belong to the other type so stale values (and any leftover cron
	// cache) can't linger and cause inconsistent behavior on the next fetch.
	if src, ok := body["source"].(string); ok {
		switch src {
		case "local":
			if _, urlSent := body["url"]; !urlSent {
				existing["url"] = ""
			}
			existing["updateCron"] = ""
			existing["cachedContent"] = ""
			existing["cachedAt"] = 0
		case "remote":
			if _, contentSent := body["content"]; !contentSent {
				existing["content"] = ""
			}
		}
	}
	if err := validateAndNormalizeSubBody(existing); err != nil {
		abortError(c, http.StatusBadRequest, err.Error())
		return
	}
	// When the URL or UA of a remote sub changes (or the source switches to
	// remote), the old cached snapshot no longer matches the link — drop it
	// before persisting so a failed refresh can never serve stale nodes.
	// The cache is re-populated right after the save.
	if getStr(existing, "source") == "remote" {
		identityChanged := getStr(existing, "url") != oldURL ||
			getStr(existing, "ua") != oldUA ||
			oldSource != "remote"
		if identityChanged {
			existing["cachedContent"] = ""
			existing["cachedAt"] = 0
		}
	}
	// When the subscription is renamed, keep its original position (like
	// Sub-Store's updateByName) and update every collection that references
	// the old name so the references don't silently break. Both steps run in
	// one transaction so a failure rolls the rename back.
	if newName != name {
		err := s.Store.WithTx(func(tx *sql.Tx) error {
			if err := store.RenameSubTx(tx, name, newName, existing); err != nil {
				return err
			}
			return s.updateCollectionsReferencingTx(tx, name, newName)
		})
		if errors.Is(err, store.ErrNameConflict) {
			abortError(c, http.StatusConflict, "name already taken")
			return
		}
		if err != nil {
			abortError(c, http.StatusInternalServerError, "save failed")
			return
		}
	} else {
		if err := s.Store.UpsertSub(name, existing, "bottom"); err != nil {
			abortError(c, http.StatusInternalServerError, "save failed")
			return
		}
	}
	// Editing a remote subscription re-fetches it immediately so the local
	// snapshot always reflects the current link/UA after a save.
	resp := gin.H{"message": "success", "name": newName}
	var sub model.Sub
	if err := share.Remarshal(existing, &sub); err == nil && sub.Source == "remote" {
		if werr := s.refreshRemoteSubCache(sub, existing); werr != nil {
			resp["warning"] = "订阅已保存，但拉取订阅链接失败：" + werr.Error()
		}
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Server) handleDeleteSub(c *gin.Context) {
	name := c.Param("name")
	existing, err := s.Store.GetSub(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if existing == nil {
		abortError(c, http.StatusNotFound, "subscription not found")
		return
	}
	// Sub-Store also removes the deleted subscription from every collection
	// that references it, so stale names don't linger in the merged output.
	// Both steps run in one transaction so the reference cleanup can't be
	// left half-done if a write fails.
	if err := s.Store.WithTx(func(tx *sql.Tx) error {
		if err := store.DeleteSubTx(tx, name); err != nil {
			return err
		}
		return s.removeSubscriptionFromCollectionsTx(tx, name)
	}); err != nil {
		abortError(c, http.StatusInternalServerError, "delete failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "success"})
}

// refreshRemoteSubCache performs a live fetch of the subscription with the
// sub's UA and stores the raw content as the local snapshot
// (cachedContent/cachedAt). rec is the persisted record map to update;
// pass the same map that was (or will be) saved so the cache write doesn't
// clobber concurrent field edits.
func (s *Server) refreshRemoteSubCache(sub model.Sub, rec map[string]any) error {
	if sub.URL == "" {
		return errors.New("订阅没有 URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	content, err := s.Share.FetchLive(ctx, sub)
	if err != nil {
		return err
	}
	rec["cachedContent"] = content
	rec["cachedAt"] = time.Now().UnixMilli()
	return s.Store.UpsertSub(sub.Name, rec, "bottom")
}

// handleUpdateSub manually refreshes a remote subscription: it always hits
// the remote URL (cache-bypassing) and overwrites the local snapshot.
func (s *Server) handleUpdateSub(c *gin.Context) {
	name := c.Param("name")
	rec, err := s.Store.GetSub(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if rec == nil {
		abortError(c, http.StatusNotFound, "subscription not found")
		return
	}
	var sub model.Sub
	if err := share.Remarshal(rec, &sub); err != nil {
		abortError(c, http.StatusInternalServerError, "decode failed")
		return
	}
	if sub.Source != "remote" || sub.URL == "" {
		abortError(c, http.StatusBadRequest, "本地订阅无需更新")
		return
	}
	if err := s.refreshRemoteSubCache(sub, rec); err != nil {
		abortError(c, http.StatusBadGateway, "更新失败："+err.Error())
		return
	}
	cachedAt, _ := rec["cachedAt"].(int64)
	c.JSON(http.StatusOK, gin.H{"message": "success", "cachedAt": cachedAt})
}

// handleNodeInfo returns a JSON preview of a subscription's parsed nodes.
func (s *Server) handleNodeInfo(c *gin.Context) {
	name := c.Param("name")
	rec, err := s.Store.GetSub(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if rec == nil {
		abortError(c, http.StatusNotFound, "subscription not found")
		return
	}
	var sub model.Sub
	if err := share.Remarshal(rec, &sub); err != nil {
		abortError(c, http.StatusInternalServerError, "decode failed")
		return
	}
	proxies, err := s.Share.PreviewSub(c, sub)
	if err != nil {
		abortError(c, http.StatusBadGateway, err.Error())
		return
	}
	c.JSON(http.StatusOK, proxies)
}

// updateCollectionsReferencingTx rewrites every collection that references
// oldName in its subscriptions array, replacing it with newName. Mirrors
// Sub-Store's updateSubscription behavior on rename. Runs inside tx so it is
// atomic with the rename itself.
func (s *Server) updateCollectionsReferencingTx(tx *sql.Tx, oldName, newName string) error {
	cols, err := store.ListCollectionsTx(tx)
	if err != nil {
		return err
	}
	for _, col := range cols {
		subs, ok := col["subscriptions"].([]any)
		if !ok {
			continue
		}
		changed := false
		for i, v := range subs {
			if name, ok := v.(string); ok && name == oldName {
				subs[i] = newName
				changed = true
			}
		}
		if changed {
			name, _ := col["name"].(string)
			if name != "" {
				if err := store.UpsertCollectionTx(tx, name, col, "bottom"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// removeSubscriptionFromCollectionsTx drops name from every collection's
// subscriptions array. Mirrors Sub-Store's deleteSubscriptionItem behavior.
// Runs inside tx so it is atomic with the deletion itself.
func (s *Server) removeSubscriptionFromCollectionsTx(tx *sql.Tx, name string) error {
	cols, err := store.ListCollectionsTx(tx)
	if err != nil {
		return err
	}
	for _, col := range cols {
		subs, ok := col["subscriptions"].([]any)
		if !ok {
			continue
		}
		filtered := make([]any, 0, len(subs))
		changed := false
		for _, v := range subs {
			if s, ok := v.(string); ok && s == name {
				changed = true
				continue
			}
			filtered = append(filtered, v)
		}
		if changed {
			col["subscriptions"] = filtered
			cname, _ := col["name"].(string)
			if cname != "" {
				if err := store.UpsertCollectionTx(tx, cname, col, "bottom"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func getStr(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// validateAndNormalizeSubBody checks source/url/content/updateCron
// consistency on a subscription body before it's persisted. It mutates body
// to clear fields that don't apply to the chosen source type.
func validateAndNormalizeSubBody(body map[string]any) error {
	src := getStr(body, "source")
	if src == "" {
		src = "remote"
		body["source"] = src
	}
	switch src {
	case "local":
		if strings.TrimSpace(getStr(body, "content")) == "" {
			return errors.New("本地订阅需要填写内容")
		}
		body["url"] = ""
		body["updateCron"] = ""
	case "remote":
		if strings.TrimSpace(getStr(body, "url")) == "" {
			return errors.New("远程订阅需要填写 URL")
		}
		body["content"] = ""
		cron := strings.TrimSpace(getStr(body, "updateCron"))
		if cron != "" {
			if _, err := scheduler.Parse(cron); err != nil {
				return errors.New("定时更新表达式无效，应为标准 5 段 cron 格式，例如 0 0 * * *")
			}
			body["updateCron"] = cron
		}
	default:
		return errors.New("source 必须是 local 或 remote")
	}
	return nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
