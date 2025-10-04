package main

import (
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
)

//go:embed templates/*
var templates embed.FS

const MaxSecretSize = 1 << 16

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
	id, sharedSecret, err := a.AddSecret(r.Context(), secret, 1)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = a.TemplateHandler.ExecuteTemplate(w, "add.html", struct {
		ID  int
		URL string
	}{
		ID: id,
		// TODO This won't work if the server isn't behind a proxy
		URL: fmt.Sprintf("https://%s/pop?i=%d&s=%s", r.Host, id, sharedSecret),
	})
	if err != nil {
		w.Write([]byte(fmt.Sprintf("Error: %s", err)))
	}
}

func (a *App) HandlePopSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sharedSecret := r.FormValue("s")
	idstring := r.FormValue("i")
	if sharedSecret == "" || idstring == "" {
		http.Error(w, "missing parameters", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(idstring)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	secret, err := a.PopSecret(r.Context(), id, sharedSecret)
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
	err = a.TemplateHandler.ExecuteTemplate(w, "show.html", struct {
		ID     int
		Secret string
	}{
		ID:     id,
		Secret: secret,
	})
	if err != nil {
		w.Write([]byte(fmt.Sprintf("Error: %s", err)))
	}
}

func (a *App) Serve() {
	a.TemplateHandler = template.Must(template.ParseFS(templates, "templates/*.html"))
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		a.TemplateHandler.ExecuteTemplate(w, "index.html", nil)
	})
	mux.HandleFunc("POST /add", a.HandleAddSecret)
	mux.HandleFunc("GET /pop/{token}", a.HandlePopSecret)
	http.ListenAndServe(":8080", mux)
}
