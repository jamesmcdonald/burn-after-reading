package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	versionByte byte = 1
	algPGPAES   byte = 0
	algXChaCha  byte = 1
)

func (a *App) Create(ctx context.Context) error {
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
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			count, err := a.Prune(ctx)
			if err != nil {
				slog.Error("Failed to prune", "error", err)
			}
			slog.Debug("Pruned expired secrets", "count", count, "interval", interval)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (a *App) AddSecretNew(ctx context.Context, secret string, alg byte) (int, string, error) {
	switch alg {
	case algXChaCha:
		locator := make([]byte, 16)
		if _, err := rand.Read(locator); err != nil {
			return 0, "", err
		}
		key := make([]byte, chacha20poly1305.KeySize)
		if _, err := rand.Read(key); err != nil {
			return 0, "", err
		}
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			return 0, "", err
		}
		nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(secret)+aead.Overhead())
		if _, err := rand.Read(nonce); err != nil {
			return 0, "", err
		}
		encrypted := aead.Seal(nonce, nonce, []byte(secret), locator)
		var id int
		query := `insert into secret(locator, data) values ($1, $2) returning id`
		err = a.DB.QueryRow(ctx, query, locator, encrypted).Scan(&id)
		if err != nil {
			return 0, "", err
		}
		raw := make([]byte, 0, 1+1+16+aead.NonceSize()+chacha20poly1305.KeySize)
		raw = append(raw, versionByte)
		raw = append(raw, alg)
		raw = append(raw, locator...)
		raw = append(raw, nonce...)
		raw = append(raw, key...)
		return id, string(raw), nil
	default:
		return 0, "", fmt.Errorf("unsupported algorithm")
	}
}

func (a *App) AddSecret(ctx context.Context, secret string, alg byte) (int, string, error) {
	if alg != algPGPAES {
		return a.AddSecretNew(ctx, secret, alg)
	}
	query := `with pw as (
		select encode(gen_random_bytes(32), 'hex') as pw
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
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return "", err
	}
	query := `select pgp_sym_decrypt(data, $1) from secret where id=$2`
	result := tx.QueryRow(ctx, query, sharedSecret, id)
	var secret string
	err = result.Scan(&secret)
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
}
