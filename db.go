package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// errSecretNotFound covers every way a token can fail to match a stored
// secret: unknown locator, wrong key or a malformed token. They are
// deliberately indistinguishable to the user.
var errSecretNotFound = errors.New("secret not found")

// notFoundOr wraps errors that mean "this token doesn't match a secret" in
// errSecretNotFound and passes everything else through unchanged.
func notFoundOr(err error) error {
	var pgErr *pgconn.PgError
	// 39000 is pgcrypto's "Wrong key or corrupt data"
	if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == "39000") {
		return fmt.Errorf("%w: %w", errSecretNotFound, err)
	}
	return err
}

func migrate(ctx context.Context, tx pgx.Tx) error {
	defer tx.Rollback(ctx)

	_, err := tx.Exec(ctx, `create extension if not exists pgcrypto`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `create table if not exists secret (
		id serial not null primary key,
		locator bytea not null unique,
		data bytea not null,
		expires_at timestamp with time zone default now() + interval '1 day'
	)`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `create index if not exists secret_expires_at on secret (expires_at)`)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

func (a *App) Prune(ctx context.Context) (int64, error) {
	res, err := a.DB.Exec(ctx, `delete from secret where expires_at < now()`)
	if err != nil {
		return 0, err
	}
	count := res.RowsAffected()
	return count, nil
}

func (a *App) StartPruner(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.Tick(interval)
		for {
			pruneCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			count, err := a.Prune(pruneCtx)
			cancel()
			switch {
			case ctx.Err() != nil:
				return // shutting down
			case err != nil:
				slog.Error("Failed to prune", "error", err)
			default:
				slog.Debug("Pruned expired secrets", "count", count, "interval", interval)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker:
			}
		}
	}()
}

func (a *App) AddSecret(ctx context.Context, secret string, alg byte) ([]byte, error) {
	switch alg {
	case algPGPAES:
		query := `with pw as (
			select encode(gen_random_bytes(32), 'hex') as pw
			)
		insert into secret(locator, data)
		values (gen_random_bytes(16), pgp_sym_encrypt($1, (select pw from pw), 'cipher-algo=aes256'))
		returning locator, (select pw from pw)`

		result := a.DB.QueryRow(ctx, query, secret)
		var locator []byte
		var sharedSecret []byte
		err := result.Scan(&locator, &sharedSecret)
		if err != nil {
			return nil, err
		}
		t := token{
			version: versionByte,
			alg:     alg,
		}
		t.locator = locator
		t.key = sharedSecret
		return t.pack(), nil
	default:
		t, err := newToken(alg)
		if err != nil {
			return nil, err
		}
		encrypted, err := t.encrypt([]byte(secret))
		if err != nil {
			return nil, err
		}
		query := `insert into secret(locator, data) values ($1, $2)`
		_, err = a.DB.Exec(ctx, query, t.locator, encrypted)
		if err != nil {
			return nil, err
		}
		tokenBytes := t.pack()
		return tokenBytes, nil
	}
}

// CheckSecret returns nil if a secret is stored for the token,
// errSecretNotFound if not, or the underlying error if it couldn't tell. It
// doesn't decrypt or consume the secret.
func (a *App) CheckSecret(ctx context.Context, token string) error {
	t, err := parseToken([]byte(token))
	if err != nil {
		return fmt.Errorf("%w: %w", errSecretNotFound, err)
	}
	var exists bool
	err = a.DB.QueryRow(ctx, `select exists(select 1 from secret where locator = $1)`, t.locator).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return errSecretNotFound
	}
	return nil
}

func (a *App) PopSecret(ctx context.Context, token string) (string, error) {
	t, err := parseToken([]byte(token))
	if err != nil {
		return "", fmt.Errorf("%w: %w", errSecretNotFound, err)
	}
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	switch t.alg {
	case algPGPAES:
		query := `select id, pgp_sym_decrypt(data, $1) from secret where locator=$2 for update`
		result := tx.QueryRow(ctx, query, t.key, t.locator)
		var id int
		var secret string
		err = result.Scan(&id, &secret)
		if err != nil {
			return "", notFoundOr(err)
		}
		_, err = tx.Exec(ctx, `delete from secret where id = $1`, id)
		if err != nil {
			return "", err
		}
		if err := tx.Commit(ctx); err != nil {
			return "", err
		}
		return secret, nil
	default:
		query := `select id, data from secret where locator=$1 for update`
		result := tx.QueryRow(ctx, query, t.locator)
		var id int
		var data []byte
		err = result.Scan(&id, &data)
		if err != nil {
			return "", notFoundOr(err)
		}
		secret, err := t.decrypt(data)
		if err != nil {
			// A wrong key fails authentication
			return "", fmt.Errorf("%w: %w", errSecretNotFound, err)
		}
		_, err = tx.Exec(ctx, `delete from secret where id = $1`, id)
		if err != nil {
			return "", err
		}
		if err := tx.Commit(ctx); err != nil {
			return "", err
		}
		return string(secret), nil
	}
}
