package main

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
)

//go:embed templates/*
var templates embed.FS

func (a *App) HandleAddSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	secret := r.FormValue("secret")
	id, sharedSecret, err := a.AddSecret(r.Context(), secret)
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
		if err.Error() == "no rows in result set" {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		a.TemplateHandler.ExecuteTemplate(w, "index.html", nil)
	})
	http.HandleFunc("/add", a.HandleAddSecret)
	http.HandleFunc("/pop", a.HandlePopSecret)
	http.ListenAndServe(":8080", nil)
}
