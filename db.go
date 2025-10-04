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

type token struct {
	version byte
	alg     byte
	locator []byte
	nonce   []byte
	key     []byte
}

func (t token) pack() []byte {
	raw := make([]byte, 0, 1+1+len(t.locator)+len(t.nonce)+len(t.key))
	raw = append(raw, versionByte)
	raw = append(raw, t.alg)
	raw = append(raw, t.locator...)
	raw = append(raw, t.nonce...)
	raw = append(raw, t.key...)
	return raw
}

func parseToken(tokenBytes []byte) (token, error) {
	var t token
	if len(tokenBytes) < 2 {
		return t, fmt.Errorf("short token")
	}
	t.version = tokenBytes[0]
	if t.version != versionByte {
		return token{}, fmt.Errorf("unsupported version %d", t.version)
	}
	t.alg = tokenBytes[1]
	var nonceLen int
	switch t.alg {
	case algXChaCha:
		nonceLen = chacha20poly1305.NonceSizeX
	case algPGPAES:
		nonceLen = 0
	default:
		return t, fmt.Errorf("unknown algorithm %d", t.alg)
	}

	if len(tokenBytes) < 1+1+16+nonceLen+1 {
		return t, fmt.Errorf("short token")
	}
	t.locator = tokenBytes[2:18]
	t.nonce = tokenBytes[18 : 18+nonceLen]
	t.key = tokenBytes[18+nonceLen:]
	fmt.Printf("%x %x %x %x %x\n", t.version, t.alg, t.locator, t.nonce, t.key)
	return t, nil
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
	case algXChaCha:
		t := token{
			version: versionByte,
			alg:     alg,
		}
		t.locator = make([]byte, 16)
		if _, err := rand.Read(t.locator); err != nil {
			return nil, err
		}
		t.key = make([]byte, chacha20poly1305.KeySize)
		if _, err := rand.Read(t.key); err != nil {
			return nil, err
		}
		aead, err := chacha20poly1305.NewX(t.key)
		if err != nil {
			return nil, err
		}
		t.nonce = make([]byte, aead.NonceSize(), aead.NonceSize()+len(secret)+aead.Overhead())
		if _, err := rand.Read(t.nonce); err != nil {
			return nil, err
		}
		encrypted := aead.Seal(t.nonce, t.nonce, []byte(secret), t.locator)
		query := `insert into secret(locator, data) values ($1, $2)`
		_, err = a.DB.Exec(ctx, query, t.locator, encrypted)
		if err != nil {
			return nil, err
		}
		tokenBytes := t.pack()
		return tokenBytes, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm")
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
	case algXChaCha:
		query := `select id, data from secret where locator=$1 for update`
		result := tx.QueryRow(ctx, query, t.locator)
		var id int
		var data []byte
		err = result.Scan(&id, &data)
		if err != nil {
			return "", err
		}
		aead, err := chacha20poly1305.NewX(t.key)
		if err != nil {
			return "", err
		}
		fmt.Printf("%x\n", data)
		secret, err := aead.Open(nil, t.nonce, data, t.locator)
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
	default:
		return "", fmt.Errorf("unknown algorithm %d", t.alg)
	}
}
