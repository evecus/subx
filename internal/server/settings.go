package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) handleGetSettings(c *gin.Context) {
	settings, err := s.Store.GetSettings()
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if settings == nil {
		settings = map[string]any{}
	}
	c.JSON(http.StatusOK, settings)
}

func (s *Server) handlePatchSettings(c *gin.Context) {
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		abortError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	existing, err := s.Store.GetSettings()
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	if existing == nil {
		existing = map[string]any{}
	}
	for k, v := range body {
		existing[k] = v
	}
	if err := s.Store.SaveSettings(existing); err != nil {
		abortError(c, http.StatusInternalServerError, "save failed")
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "success"})
}
