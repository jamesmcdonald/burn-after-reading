package main

import (
	"context"
	"log/slog"
	"time"
)

func (a *App) Migrate(ctx context.Context) error {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `create extension if not exists pgcrypto`)
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
			count, err := a.Prune(ctx)
			if err != nil {
				slog.Error("Failed to prune", "error", err)
			}
			slog.Debug("Pruned expired secrets", "count", count, "interval", interval)
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

func (a *App) PopSecret(ctx context.Context, token string) (string, error) {
	t, err := parseToken([]byte(token))
	if err != nil {
		return "", err
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
			return "", err
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
			return "", err
		}
		secret, err := t.decrypt(data)
		if err != nil {
			return "", err
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
