package database

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/unclaim/monolith-backend.git/internal/shared/config"
)

// NewRedisClient создает и возвращает новый клиент Redis.
func NewRedisClient(cfg *config.Config, log *slog.Logger) (*redis.Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
		PoolSize: cfg.Redis.PoolSize,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к Redis: %w", err)
	}

	log.Info("Успешно подключено к Redis", "хост", cfg.Redis.Host, "порт", cfg.Redis.Port)
	return rdb, nil
}
