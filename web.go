package main

import (
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
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
		http.Error(w, "Request too large or malformed", http.StatusRequestEntityTooLarge)
		return
	}
	secret := r.FormValue("secret")
	sharedSecret, err := a.AddSecret(r.Context(), secret, 1)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	urlToken := base64.URLEncoding.EncodeToString(sharedSecret)
	err = a.render(w, "add", "", map[string]any{
		// TODO This won't work if the server isn't behind a proxy
		"URL": fmt.Sprintf("https://%s/s/%s", r.Host, urlToken),
	})
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
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
	err := a.render(w, "show", "", map[string]any{
		"Token": token,
	})
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}
}

func (a *App) HandlePopSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token := r.Form.Get("token")
	if token == "" {
		http.Error(w, "missing parameters", http.StatusBadRequest)
		return
	}
	tbytes, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		http.Error(w, "Bad token", http.StatusBadRequest)
		return
	}
	secret, err := a.PopSecret(r.Context(), string(tbytes))
	if err != nil {
		switch err.Error() {
		// Return 404 if the secret is not found or if the key is wrong
		case "no rows in result set", "ERROR: Wrong key or corrupt data (SQLSTATE 39000)":
			http.Error(w, "Not found", http.StatusNotFound)
		default:
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			slog.Error(err.Error())
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

//go:embed templates/*
var templates embed.FS

//go:embed public/assets/*
var assets embed.FS

func (a *App) Serve() {
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
	http.ListenAndServe(":8080", mux)
}
