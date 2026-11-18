package main

import (
	"context"
	"log/slog"
	"math/rand"
	"time"
)

func retry(ctx context.Context, what string, fn func(context.Context) error) error {
	delay, maxDelay := time.Second, 30*time.Second
	for attempt := 1; ; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := fn(attemptCtx)
		cancel()
		if err == nil {
			return nil
		}
		sleep := delay/2 + time.Duration(rand.Int63n(int64(delay)))
		slog.Warn("retrying", "op", what, "attempt", attempt, "in", sleep, "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}
		delay = min(delay*2, maxDelay)
	}
}
