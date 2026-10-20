package common

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

// StatsHandler serves the current statistics as JSON on GET /stats (and HEAD). snapshot is called for every request, so the numbers are live.
// If token is not empty, requests need the header "Authorization: Bearer <token>".
func StatsHandler(snapshot func() Snapshot, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if token != "" && !validBearer(r.Header.Get("Authorization"), token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="stats"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := json.MarshalIndent(snapshot(), "", "  ")
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodGet {
			w.Write(append(body, '\n'))
		}
	})
	return mux
}

func validBearer(header, token string) bool {
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(header[len(prefix):])), []byte(token)) == 1
}

// ServeStats listens on addr and serves h in the background. Listening happens before it returns, so a bad or busy address is reported to the caller. The returned server can be closed to stop it.
func ServeStats(addr string, h http.Handler) (*http.Server, net.Addr, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go srv.Serve(ln)
	return srv, ln.Addr(), nil
}
