package main

import (
	"cmp"
	"context"
	"fmt"
	"html/template"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

type App struct {
	DB              *pgxpool.Pool
	TemplateHandler *template.Template
}

func main() {
	pgOwnerUser := cmp.Or(os.Getenv("PGOWNERUSER"), os.Getenv("PGUSER"), os.Getenv("PGDATABASE")+"_owner_user")
	pgWriterUser := cmp.Or(os.Getenv("PGWRITERUSER"), os.Getenv("PGUSER"), os.Getenv("PGDATABASE")+"_writer_user")

	pgOwnerPassword := cmp.Or(os.Getenv("PGOWNERPASSWORD"), os.Getenv("PGPASSWORD"))
	pgWriterPassword := cmp.Or(os.Getenv("PGWRITERPASSWORD"), os.Getenv("PGPASSWORD"))

	ctx := context.Background()
	conn, err := pgxpool.New(ctx, fmt.Sprintf("user=%s password=%s", pgOwnerUser, pgOwnerPassword))
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

	conn, err = pgxpool.New(ctx, fmt.Sprintf("user=%s password=%s", pgWriterUser, pgWriterPassword))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	app.DB = conn

	app.Serve()
}
