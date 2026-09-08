package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"substore/internal/model"
	"substore/internal/producer"
	"substore/internal/share"
	"substore/internal/store"
)

func (s *Server) handleListTokens(c *gin.Context) {
	tokens, err := s.Store.ListTokens()
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	c.JSON(http.StatusOK, tokens)
}

func (s *Server) handleCreateToken(c *gin.Context) {
	var body struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		Mode      string `json:"mode"`
		Exp       int64  `json:"exp"`
		Seconds   int    `json:"seconds"`
		Permanent bool   `json:"permanent"`
		Count     int    `json:"count"`
		Target    string `json:"target"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		abortError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Type != "sub" && body.Type != "col" && body.Type != "file" {
		abortError(c, http.StatusBadRequest, "type must be sub, col or file")
		return
	}
	if body.Type != "file" {
		if body.Target == "" {
			body.Target = "mihomo"
		}
		if !producer.Known(body.Target) {
			abortError(c, http.StatusBadRequest, "unsupported target: "+body.Target)
			return
		}
	}
	// validate the target exists
	switch body.Type {
	case "sub":
		if sub, _ := s.Store.GetSub(body.Name); sub == nil {
			abortError(c, http.StatusNotFound, "subscription not found")
			return
		}
	case "col":
		if col, _ := s.Store.GetCollection(body.Name); col == nil {
			abortError(c, http.StatusNotFound, "collection not found")
			return
		}
	case "file":
		if file, _ := s.Store.GetFile(body.Name); file == nil {
			abortError(c, http.StatusNotFound, "file not found")
			return
		}
	}
	opts := map[string]any{
		"mode":      body.Mode,
		"seconds":   body.Seconds,
		"permanent": body.Permanent,
		"exp":       body.Exp,
		"count":     body.Count,
		"target":    body.Target,
	}
	token, err := share.BuildTokenPayload(body.Type, body.Name, opts)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "token generation failed")
		return
	}
	payload := tokenPayloadMap(token)
	if err := s.Store.InsertToken(payload); err != nil {
		if errors.Is(err, store.ErrNameConflict) {
			abortError(c, http.StatusConflict, "token already exists")
			return
		}
		abortError(c, http.StatusInternalServerError, "save token failed")
		return
	}
	c.JSON(http.StatusOK, payload)
}

// handleTargets lists the supported output target formats with labels.
func (s *Server) handleTargets(c *gin.Context) {
	c.JSON(http.StatusOK, producer.Targets())
}

func (s *Server) handleDeleteToken(c *gin.Context) {
	token := c.Param("token")
	if err := s.Store.DeleteToken(token); err != nil {
		abortError(c, http.StatusInternalServerError, "delete failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "success"})
}

func tokenPayloadMap(t model.Token) map[string]any {
	b, err := json.Marshal(t)
	if err != nil {
		return map[string]any{"token": t.Token, "type": t.Type, "name": t.Name}
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}
