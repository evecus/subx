package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"substore/internal/store"
)

func (s *Server) handleListFiles(c *gin.Context) {
	files, err := s.Store.ListFiles()
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	c.JSON(http.StatusOK, files)
}

func (s *Server) handleCreateFile(c *gin.Context) {
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
	if err := validateFileBody(body); err != nil {
		abortError(c, http.StatusBadRequest, err.Error())
		return
	}
	existing, err := s.Store.GetFile(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if existing != nil {
		abortError(c, http.StatusConflict, "file already exists")
		return
	}
	position := getStr(body, "position")
	if position == "" {
		position = "bottom"
	}
	if err := s.Store.UpsertFile(name, body, position); err != nil {
		abortError(c, http.StatusInternalServerError, "save failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "success", "name": name})
}

func (s *Server) handleGetFile(c *gin.Context) {
	name := c.Param("name")
	file, err := s.Store.GetFile(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if file == nil {
		abortError(c, http.StatusNotFound, "file not found")
		return
	}
	c.JSON(http.StatusOK, file)
}

func (s *Server) handlePatchFile(c *gin.Context) {
	name := c.Param("name")
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		abortError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	existing, err := s.Store.GetFile(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if existing == nil {
		abortError(c, http.StatusNotFound, "file not found")
		return
	}
	newName := name
	if n, ok := body["name"].(string); ok && n != "" && n != name {
		if dup, _ := s.Store.GetFile(n); dup != nil {
			abortError(c, http.StatusConflict, "name already taken")
			return
		}
		newName = n
	}
	for k, v := range body {
		existing[k] = v
	}
	if err := validateFileBody(existing); err != nil {
		abortError(c, http.StatusBadRequest, err.Error())
		return
	}
	// keep the original position when renaming, like Sub-Store's updateByName
	if newName != name {
		if err := s.Store.RenameFile(name, newName, existing); err != nil {
			if errors.Is(err, store.ErrNameConflict) {
				abortError(c, http.StatusConflict, "name already taken")
				return
			}
			abortError(c, http.StatusInternalServerError, "save failed")
			return
		}
	} else {
		if err := s.Store.UpsertFile(name, existing, "bottom"); err != nil {
			abortError(c, http.StatusInternalServerError, "save failed")
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "success", "name": newName})
}

func (s *Server) handleDeleteFile(c *gin.Context) {
	name := c.Param("name")
	existing, err := s.Store.GetFile(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if existing == nil {
		abortError(c, http.StatusNotFound, "file not found")
		return
	}
	if err := s.Store.DeleteFile(name); err != nil {
		abortError(c, http.StatusInternalServerError, "delete failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "success"})
}

// handleFileRaw serves the raw text content of a file for preview, used by
// the "预览" button which opens a new browser tab (window.open), so it
// can't attach an Authorization header — it authorizes via ?token= instead,
// same pattern as /download/:name.
func (s *Server) handleFileRaw(c *gin.Context) {
	if !s.authorizeDownload(c, []string{"file"}, c.Param("name")) {
		abortError(c, http.StatusUnauthorized, "unauthorized")
		return
	}
	name := c.Param("name")
	rec, err := s.Store.GetFile(name)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if rec == nil {
		abortError(c, http.StatusNotFound, "file not found")
		return
	}
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, "%s", getStr(rec, "content"))
}

func validateFileBody(body map[string]any) error {
	if strings.TrimSpace(getStr(body, "name")) == "" {
		return errors.New("请输入文件名")
	}
	return nil
}
