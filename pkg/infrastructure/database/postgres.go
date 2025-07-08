package database

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/unclaim/monolith-backend.git/internal/shared/config"
)

// NewPostgreSQLConnectionPool создает и возвращает пул соединений PostgreSQL.
func NewPostgreSQLConnectionPool(cfg *config.Config, log *slog.Logger) (*pgxpool.Pool, error) {
	connStr := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=%s",
		cfg.Postgres.User,
		cfg.Postgres.Password,
		cfg.Postgres.Host,
		cfg.Postgres.Port,
		cfg.Postgres.DBName,
		cfg.Postgres.SSLMode,
	)

	pgxCfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("не удалось разобрать строку подключения PostgreSQL: %w", err)
	}

	pgxCfg.MaxConns = int32(cfg.Postgres.MaxConnections)
	pgxCfg.MinConns = int32(cfg.Postgres.MaxIdleConns) // Используем MaxIdleConns как MinConns
	pgxCfg.MaxConnLifetime = cfg.Postgres.ConnMaxLifetime
	pgxCfg.MaxConnIdleTime = cfg.Postgres.ConnMaxLifetime // Также как MaxConnLifetime

	pool, err := pgxpool.NewWithConfig(context.Background(), pgxCfg)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать пул соединений PostgreSQL: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = pool.Ping(ctx)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("не удалось подключиться к PostgreSQL: %w", err)
	}

	log.Info("Успешно подключено к PostgreSQL", "база", cfg.Postgres.DBName, "хост", cfg.Postgres.Host)
	return pool, nil
}
