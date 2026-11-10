package server

import (
	"io"
	"net/http"
)

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeHealth(w, http.StatusOK, `{"status":"ok"}`)
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	if !s.Ready() {
		writeHealth(w, http.StatusServiceUnavailable, `{"status":"not_ready"}`)
		return
	}
	writeHealth(w, http.StatusOK, `{"status":"ready"}`)
}

func writeHealth(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body+"\n")
}
