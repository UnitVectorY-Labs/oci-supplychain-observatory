// Package web provides the HTTP UI for OCI supply-chain inspection.
package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/config"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/inspect"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/reference"
)

//go:embed static/*
var staticFS embed.FS

//go:embed templates/*
var templateFS embed.FS

type Server struct {
	cfg        config.Config
	inspector  *inspect.Service
	templates  *template.Template
	httpServer *http.Server
	logger     *slog.Logger
	jobs       *jobStore
}

func New(cfg config.Config, inspector *inspect.Service, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	assetVersions, err := buildAssetVersions(staticFS, versionedAssetPaths)
	if err != nil {
		return nil, err
	}
	funcs := template.FuncMap{
		"assetURL": func(path string) string { return assetURL(path, assetVersions) },
		"join":     strings.Join,
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &Server{cfg: cfg, inspector: inspector, templates: tmpl, logger: logger, jobs: newJobStore()}, nil
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return err
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("POST /inspect", s.wrapWithOriginCheck(s.handleInspect))
	mux.HandleFunc("GET /inspect/jobs/{id}", s.handleInspectJob)
	mux.HandleFunc("GET /artifacts/{id}/download", s.handleArtifactDownload)
	mux.HandleFunc("GET /healthz", textHandler("ok"))
	mux.HandleFunc("GET /readyz", textHandler("ready"))

	s.httpServer = &http.Server{
		Addr:         s.cfg.HTTPAddr,
		Handler:      s.securityHeaders(mux),
		ReadTimeout:  s.cfg.ReadTimeout,
		WriteTimeout: s.cfg.WriteTimeout,
		IdleTimeout:  s.cfg.IdleTimeout,
	}
	s.logger.Info("starting web server", "addr", s.cfg.HTTPAddr)
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

type IndexData struct {
	Allowed []string
}

type ResultData struct {
	Report  *inspect.Report
	Error   *ErrorData
	Loading *LoadingData
	Job     *inspectionJob
}

type ErrorData struct {
	Title   string
	Message string
}

type LoadingData struct {
	JobID string
	Input string
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.render(w, http.StatusOK, "index.html", IndexData{Allowed: s.cfg.AllowedList})
}

func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderResultError(w, r, "Invalid request", "Could not parse the form data.", http.StatusBadRequest)
		return
	}
	input := strings.TrimSpace(r.FormValue("image"))
	if _, err := reference.Parse(input, reference.Config{AllowedRegistry: s.cfg.AllowedRegistry}); err != nil {
		s.renderResultError(w, r, "Inspection failed", err.Error(), http.StatusBadRequest)
		return
	}
	job := s.jobs.create(input)
	go s.runInspectionJob(job.ID, input)
	if strings.EqualFold(r.Header.Get("HX-Request"), "true") {
		s.render(w, http.StatusOK, "results.html", ResultData{Loading: &LoadingData{JobID: job.ID, Input: input}})
		return
	}
	s.render(w, http.StatusOK, "page-results.html", ResultData{Loading: &LoadingData{JobID: job.ID, Input: input}})
}

func (s *Server) runInspectionJob(id, input string) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.RequestTimeout)
	defer cancel()
	report, err := s.inspector.Inspect(ctx, input)
	if err != nil && !errors.Is(err, reference.ErrInvalidInput) && !errors.Is(err, reference.ErrRegistryNotAllowed) {
		s.logger.Warn("inspection failed", "job", id, "error", err)
	}
	s.jobs.finish(id, report, err)
}

func (s *Server) handleInspectJob(w http.ResponseWriter, r *http.Request) {
	job, ok := s.jobs.get(r.PathValue("id"))
	if !ok {
		s.render(w, http.StatusNotFound, "result-panel.html", ResultData{Error: &ErrorData{Title: "Inspection expired", Message: "Start a new inspection."}})
		return
	}
	if !job.Done {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if job.Err != nil {
		message := "The registry request could not be completed."
		if errors.Is(job.Err, reference.ErrInvalidInput) || errors.Is(job.Err, reference.ErrRegistryNotAllowed) {
			message = job.Err.Error()
		}
		s.render(w, http.StatusOK, "result-panel.html", ResultData{Error: &ErrorData{Title: "Inspection failed", Message: message}})
		return
	}
	s.render(w, http.StatusOK, "result-panel.html", ResultData{Report: job.Report})
}

func (s *Server) renderResultError(w http.ResponseWriter, r *http.Request, title, message string, status int) {
	data := ResultData{Error: &ErrorData{Title: title, Message: message}}
	if strings.EqualFold(r.Header.Get("HX-Request"), "true") {
		status = http.StatusOK
	}
	s.render(w, status, "results.html", data)
}

func (s *Server) handleArtifactDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	artifact, ok := s.inspector.Artifact(id)
	if !ok || artifact == nil || !artifact.Downloadable {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", safeFilename(artifact.Type+"-"+artifact.ID+".json")))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(artifact.Raw)
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		s.logger.Error("failed to render template", "template", name, "error", err)
	}
}

func (s *Server) wrapWithOriginCheck(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secFetchSite := r.Header.Get("Sec-Fetch-Site")
		if secFetchSite != "" && secFetchSite != "same-origin" && secFetchSite != "same-site" && secFetchSite != "none" {
			http.Error(w, "Cross-site requests are not allowed", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			host := r.Host
			if host == "" {
				host = r.URL.Host
			}
			if origin != "http://"+host && origin != "https://"+host {
				http.Error(w, "Cross-origin requests are not allowed", http.StatusForbidden)
				return
			}
		}
		handler(w, r)
	}
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		next.ServeHTTP(w, r)
	})
}

func textHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(body + "\n"))
	}
}

func safeFilename(name string) string {
	name = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, name)
	return strings.Trim(name, ".-")
}

type inspectionJob struct {
	ID     string
	Input  string
	Done   bool
	Report *inspect.Report
	Err    error
}

type jobStore struct {
	mu   sync.Mutex
	jobs map[string]*inspectionJob
}

func newJobStore() *jobStore {
	return &jobStore{jobs: map[string]*inspectionJob{}}
}

func (s *jobStore) create(input string) *inspectionJob {
	job := &inspectionJob{ID: randomID(), Input: input}
	s.mu.Lock()
	s.jobs[job.ID] = job
	s.mu.Unlock()
	return job
}

func (s *jobStore) finish(id string, report *inspect.Report, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job := s.jobs[id]; job != nil {
		job.Done = true
		job.Report = report
		job.Err = err
	}
}

func (s *jobStore) get(id string) (*inspectionJob, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		return nil, false
	}
	clone := *job
	return &clone, true
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprintf("%p", &b)))
	}
	return hex.EncodeToString(b[:])
}
