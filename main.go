package main

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"html/template"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sync/atomic"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type App struct {
	DB           *pgxpool.Pool
	BaseTemplate *template.Template
	Ready        atomic.Bool
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

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()

	conf, err := pgxpool.ParseConfig("application_name=burn-after-reading")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse database config: %v\n", err)
		os.Exit(1)
	}
	conf.ConnConfig.User = *user
	conf.ConnConfig.Password = *password
	conn, err := pgxpool.NewWithConfig(ctx, conf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	app := App{DB: conn}

	serveErr := make(chan error, 1)
	go func() { serveErr <- app.Serve(ctx) }()

	// Migration
	if err = retry(ctx, "startup", func(ctx context.Context) error {
		conf, err := pgx.ParseConfig("application_name=burn-after-reading")
		if err != nil {
			return fmt.Errorf("unable to parse migration config: %w", err)
		}
		conf.User = *migrationUser
		conf.Password = *migrationPassword
		conn, err := pgx.ConnectConfig(ctx, conf)
		if err != nil {
			return fmt.Errorf("unable to connect to database for migration: %w", err)
		}
		defer conn.Close(ctx)
		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("unable to connect to start migration transaction: %w", err)
		}
		defer tx.Rollback(ctx)
		if err = migrate(ctx, tx); err != nil {
			return fmt.Errorf("unable to migrate database: %w", err)
		}
		return nil
	}); err == nil {
		app.Ready.Store(true)
		app.StartPruner(ctx, 1*time.Hour)
	}
	if err = <-serveErr; err != nil {
		fmt.Fprintf(os.Stdout, "serve error: %v", err)
		os.Exit(1)
	}
}
