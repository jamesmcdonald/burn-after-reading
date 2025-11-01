package main

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	versionByte byte = 1
	algPGPAES   byte = 0
	algXChaCha  byte = 1
)

type token struct {
	version byte
	alg     byte
	locator []byte
	key     []byte
}

func newToken(alg byte) (token, error) {
	locator := make([]byte, 16)
	if _, err := rand.Read(locator); err != nil {
		return token{}, err
	}
	return token{
		version: versionByte,
		alg:     alg,
		locator: locator,
	}, nil
}

func (t token) pack() []byte {
	raw := make([]byte, 0, 1+1+len(t.locator)+len(t.key))
	raw = append(raw, versionByte)
	raw = append(raw, t.alg)
	raw = append(raw, t.locator...)
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

	if len(tokenBytes) < 1+1+16+1 {
		return t, fmt.Errorf("short token")
	}
	t.locator = tokenBytes[2:18]
	t.key = tokenBytes[18:]
	return t, nil
}

func (t *token) encrypt(secret []byte) ([]byte, error) {
	switch t.alg {
	case algXChaCha:
		// Generate a key if the token doesn't have one
		if t.key == nil || len(t.key) == 0 {
			t.key = make([]byte, chacha20poly1305.KeySize)
			if _, err := rand.Read(t.key); err != nil {
				return nil, err
			}
		}
		aead, err := chacha20poly1305.NewX(t.key)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(secret)+aead.Overhead())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		encrypted := aead.Seal(nonce, nonce, []byte(secret), t.locator)
		return encrypted, nil
	default:
		return nil, fmt.Errorf("unknown algorithm %d", t.alg)
	}
}

func (t token) decrypt(data []byte) (string, error) {
	switch t.alg {
	case algXChaCha:
		aead, err := chacha20poly1305.NewX(t.key)
		if err != nil {
			return "", err
		}
		nonce := data[0:aead.NonceSize()]
		ciphertext := data[aead.NonceSize():]
		secret, err := aead.Open(nil, nonce, ciphertext, t.locator)
		return string(secret), err
	default:
		return "", fmt.Errorf("unknown algorithm %d", t.alg)
	}
}
