package api

import (
	"net/http"
)

func (server *Server) handleAdminAccountBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	bootstrap := server.deps.Bootstrap
	if bootstrap == nil {
		writeOpenAIError(w, http.StatusInternalServerError, "bootstrap not configured")
		return
	}

	// Try OAuth first, fall back to WebSocket
	sess, err := bootstrap.StartOAuth()
	if err != nil {
		sess, err = bootstrap.StartWS()
		if err != nil {
			writeOpenAIError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, sess)
}

func (server *Server) handleAdminAccountBootstrapStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	bootstrap := server.deps.Bootstrap
	if bootstrap == nil {
		writeOpenAIError(w, http.StatusInternalServerError, "bootstrap not configured")
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		writeOpenAIError(w, http.StatusBadRequest, "missing id parameter")
		return
	}

	sess := bootstrap.GetStatus(id)
	if sess == nil {
		writeOpenAIError(w, http.StatusNotFound, "session not found")
		return
	}

	writeJSON(w, http.StatusOK, sess)
}
