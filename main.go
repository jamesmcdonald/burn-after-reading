package main

import (
	"cmp"
	"context"
	"flag"
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

	defaultUser := cmp.Or(os.Getenv("PGUSER"), "")
	defaultPassword := os.Getenv("PGPASSWORD")

	user := flag.String("user", defaultUser, "Database user (env: PGUSER)")
	password := flag.String("password", defaultPassword, "Database password (env: PGPASSWORD)")
	migrationUser := flag.String("migration-user", "", "Database user for migrations, defaults to -user (env: PGMIGRATIONUSER)")
	migrationPassword := flag.String("migration-password", "", "Database migration password, defaults to -password (env: PGMIGRATIONPASSWORD)")
	flag.Parse()

	// Apply env fallbacks for migration credentials after flag parsing
	if *migrationUser == "" {
		*migrationUser = cmp.Or(os.Getenv("PGMIGRATIONUSER"), *user)
	}
	if *migrationPassword == "" {
		*migrationPassword = cmp.Or(os.Getenv("PGMIGRATIONPASSWORD"), *password)
	}

	ctx := context.Background()

	if *migrationUser != *user {
		conn, err := pgxpool.New(ctx, fmt.Sprintf("application_name=burn-after-reading user=%s password=%s", *migrationUser, *migrationPassword))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to connect to database for migration: %v\n", err)
			os.Exit(1)
		}
		app := App{DB: conn}
		if err = app.Migrate(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to migrate database: %v\n", err)
			os.Exit(1)
		}
		conn.Close()
	}

	conn, err := pgxpool.New(ctx, fmt.Sprintf("application_name=burn-after-reading user=%s password=%s", *user, *password))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	app := App{DB: conn}

	if *migrationUser == *user {
		if err = app.Migrate(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to migrate database: %v\n", err)
			os.Exit(1)
		}
	}

	app.StartPruner(ctx, 1*time.Hour)
	app.Serve()
}
