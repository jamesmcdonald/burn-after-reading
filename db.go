package main

import (
	"context"
	"log/slog"
	"time"
)

func (a *App) Create(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, `create extension if not exists pgcrypto`)
	if err != nil {
		return err
	}
	_, err = a.DB.Exec(ctx, `create table if not exists secret (
		id serial not null primary key,
		data bytea not null,
		expires_at timestamp with time zone default now() + interval '1 day'
	)`)
	if err != nil {
		return err
	}
	_, err = a.DB.Exec(ctx, `create index if not exists secret_expires_at on secret (expires_at)`)
	if err != nil {
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
		for {
			count, err := a.Prune(ctx)
			if err != nil {
				slog.Error("Failed to prune", "error", err)
			}
			slog.Debug("Pruned expired secrets", "count", count, "interval", interval)
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
			}
		}
	}()
}

func (a *App) AddSecret(ctx context.Context, secret string) (int, string, error) {
	query := `with pw as (
		select encode(digest(gen_random_bytes(1024), 'sha-256'), 'hex') as pw
	)
	insert into secret(data)
    values (pgp_sym_encrypt($1, (select pw from pw), 'cipher-algo=aes256'))
	returning id, (select pw from pw)`

	result := a.DB.QueryRow(ctx, query, secret)
	var id int
	var sharedSecret string
	err := result.Scan(&id, &sharedSecret)
	if err != nil {
		return 0, "", err
	}
	return id, sharedSecret, nil
}

func (a *App) PopSecret(ctx context.Context, id int, sharedSecret string) (string, error) {
	query := `select pgp_sym_decrypt(data, $1) from secret where id=$2`
	result := a.DB.QueryRow(ctx, query, sharedSecret, id)
	var secret string
	err := result.Scan(&secret)
	if err != nil {
		return "", err
	}
	_, err = a.DB.Exec(ctx, `delete from secret where id = $1`, id)
	if err != nil {
		return "", err
	}
	return secret, nil
}
