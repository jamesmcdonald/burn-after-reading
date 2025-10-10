package main

import (
	"cmp"
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type App struct {
	DB           *pgxpool.Pool
	BaseTemplate *template.Template
}

//go:generate go run genversion.go

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	pgOwnerUser := cmp.Or(os.Getenv("PGOWNERUSER"), os.Getenv("PGUSER"), os.Getenv("PGDATABASE")+"_owner_user")
	pgWriterUser := cmp.Or(os.Getenv("PGWRITERUSER"), os.Getenv("PGUSER"), os.Getenv("PGDATABASE")+"_writer_user")

	pgOwnerPassword := cmp.Or(os.Getenv("PGOWNERPASSWORD"), os.Getenv("PGPASSWORD"))
	pgWriterPassword := cmp.Or(os.Getenv("PGWRITERPASSWORD"), os.Getenv("PGPASSWORD"))

	ctx := context.Background()
	conn, err := pgxpool.New(ctx, fmt.Sprintf("application_name=burn-after-reading user=%s password=%s", pgOwnerUser, pgOwnerPassword))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}

	app := App{
		DB: conn,
	}

	err = app.Create(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create database: %v\n", err)
		os.Exit(1)
	}
	conn.Close()

	conn, err = pgxpool.New(ctx, fmt.Sprintf("application_name=burn-after-reading user=%s password=%s", pgWriterUser, pgWriterPassword))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	app.DB = conn

	app.StartPruner(ctx, 1*time.Hour)
	app.Serve()
}
