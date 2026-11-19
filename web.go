package main

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"time"
)

const MaxSecretSize = 1 << 16

func (a *App) render(w io.Writer, page string, template string, data map[string]any) error {
	t, err := a.BaseTemplate.Clone()
	if err != nil {
		return err
	}
	_, err = t.ParseFS(templates, "templates/pages/"+page+".html")
	if err != nil {
		return err
	}

	if data == nil {
		data = make(map[string]any)
	}
	data["Version"] = Version
	data["Commit"] = Commit

	if template == "" {
		template = "base"
	}

	return t.ExecuteTemplate(w, template, data)
}

func (a *App) HandleAddSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxSecretSize)
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			a.renderIndexError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("That secret is too large. The limit is %d KiB.", MaxSecretSize>>10), "")
		} else {
			a.renderIndexError(w, http.StatusBadRequest, "The form submission was malformed. Please try again.", "")
		}
		return
	}
	secret := r.FormValue("secret")
	sharedSecret, err := a.AddSecret(r.Context(), secret, 1)
	if err != nil {
		slog.Error("failed to add secret", "error", err)
		// Hand the secret back so the user doesn't have to retype it
		a.renderIndexError(w, http.StatusServiceUnavailable,
			"Your secret couldn't be stored right now. Please try again in a little while.", secret)
		return
	}
	urlToken := base64.URLEncoding.EncodeToString(sharedSecret)
	err = a.render(w, "add", "", map[string]any{
		"URL": fmt.Sprintf("%s://%s/s/%s", scheme(r), r.Host, urlToken),
	})
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}
}

// scheme returns the scheme the client used: the proxy's X-Forwarded-Proto
// if there is one, otherwise whatever this server is speaking.
func scheme(r *http.Request) string {
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "http" || proto == "https" {
		return proto
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// renderIndexError re-renders the front page with an error message, keeping
// whatever the user had typed.
func (a *App) renderIndexError(w http.ResponseWriter, status int, msg, secret string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	err := a.render(w, "index", "", map[string]any{
		"Error":  msg,
		"Secret": secret,
	})
	if err != nil {
		slog.Error("failed to render index error", "error", err)
	}
}

func (a *App) HandleShowSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := r.PathValue("token")
	if token == "" {
		http.Error(w, "missing parameters", http.StatusBadRequest)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")

	// Only check the secret exists: link previewers fetch this page too, so
	// it must never consume or decrypt anything.
	status := http.StatusOK
	data := map[string]any{"Token": token}
	tbytes, err := base64.URLEncoding.DecodeString(token)
	if err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		err = a.CheckSecret(ctx, string(tbytes))
		cancel()
	} else {
		err = fmt.Errorf("%w: %w", errSecretNotFound, err)
	}
	switch {
	case errors.Is(err, errSecretNotFound):
		slog.Debug("secret not found", "error", err)
		status = http.StatusNotFound
		data["Error"] = "Secret not found. It may already have been read, or it has expired."
	case err != nil:
		slog.Error("failed to check secret", "error", err)
		status = http.StatusServiceUnavailable
		data["Error"] = "This secret can't be checked right now. It hasn't been touched, so please reload the page in a little while."
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := a.render(w, "show", "", data); err != nil {
		slog.Error("failed to render show page", "error", err)
	}
}

func (a *App) HandlePopSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.render(w, "show", "secret", map[string]any{
			"Error": "method not allowed",
		})
		return
	}
	if err := r.ParseForm(); err != nil {
		a.render(w, "show", "secret", map[string]any{
			"Error": "bad request",
		})
		return
	}
	token := r.Form.Get("token")
	if token == "" {
		a.render(w, "show", "secret", map[string]any{
			"Error": "missing parameters",
		})
		return
	}
	tbytes, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		a.render(w, "show", "secret", map[string]any{
			"Error": "bad token",
		})
		return
	}
	secret, err := a.PopSecret(r.Context(), string(tbytes))
	if err != nil {
		// These responses stay 200 because htmx doesn't swap error responses
		if errors.Is(err, errSecretNotFound) {
			slog.Debug("secret not found", "error", err)
			a.render(w, "show", "secret", map[string]any{
				"Error": "Secret not found. It may already have been read, or it has expired.",
			})
		} else {
			slog.Error("failed to pop secret", "error", err)
			a.render(w, "show", "secret", map[string]any{
				"Token": token,
				"Error": "The secret couldn't be fetched right now. It hasn't been deleted, so please try again in a little while.",
			})
		}
		return
	}

	// w.Header().Set("HX-Trigger", "secretPopped")
	w.Header().Set("Cache-Control", "no-store")
	err = a.render(w, "show", "secret", map[string]any{
		"Secret": secret,
		"Token":  token,
	})
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}
}

func (a *App) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ok"}`)
}

func (a *App) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !a.Ready.Load() {
		slog.Debug("not ready in readyz")
		w.WriteHeader(http.StatusServiceUnavailable)
		err := json.NewEncoder(w).Encode(map[string]any{
			"status": "error",
			"error":  "startup has not completed",
		})
		if err != nil {
			slog.Error("failed to write ping error response", "error", err)
		}
		return
	}
	timeout := 2 * time.Second
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	if err := a.DB.Ping(ctx); err != nil {
		slog.Error("database ping failed", "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		err = json.NewEncoder(w).Encode(map[string]any{
			"status": "error",
			"error":  err.Error(),
		})
		if err != nil {
			slog.Error("failed to write ping error response", "error", err)
		}
		return
	}
	fmt.Fprint(w, `{"status":"ok"}`)
}

//go:embed templates/*
var templates embed.FS

//go:embed public/assets/*
var assets embed.FS

func (a *App) Serve(ctx context.Context) error {
	a.BaseTemplate = template.Must(template.ParseFS(templates, "templates/base.html"))
	mux := http.NewServeMux()
	subfs, err := fs.Sub(assets, "public/assets")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /assets/", http.StripPrefix("/assets", http.FileServer(http.FS(subfs))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		a.render(w, "index", "", nil)
	})
	mux.HandleFunc("POST /add", a.HandleAddSecret)
	mux.HandleFunc("GET /s/{token}", a.HandleShowSecret)
	mux.HandleFunc("POST /pop", a.HandlePopSecret)
	mux.HandleFunc("/healthz", a.HandleHealthz)
	mux.HandleFunc("/readyz", a.HandleReadyz)

	return runServer(ctx, &http.Server{Addr: ":8080", Handler: mux})
}

// runServer serves until ctx is cancelled, then shuts down gracefully.
func runServer(ctx context.Context, server *http.Server) error {
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}
