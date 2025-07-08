# internal/auth/infra/repository.go - Рабочий для Домика "Авторизация" (База Данных PostgreSQL)
Этот файл — наш "рабочий", который умеет общаться с базой данных PostgreSQL. Он берет запросы от AuthServiceImplementation и превращает их в команды, которые понимает база данных.
```go
package infra

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5" // Драйвер PostgreSQL
	"github.com/jackc/pgx/v5/pgxpool" // Пул соединений для PostgreSQL

	"your-app-name/internal/auth/domain"       // Наш домен "Auth"
	"your-app-name/internal/shared/common_errors" // Наши общие ошибки
)

// AuthRepositoryPostgres — это наш "рабочий", который умеет общаться с PostgreSQL.
type AuthRepositoryPostgres struct {
	db *pgxpool.Pool // Наш бассейн соединений с базой данных
}

// NewAuthRepositoryPostgres создает нового "рабочего" для PostgreSQL.
func NewAuthRepositoryPostgres(db *pgxpool.Pool) *AuthRepositoryPostgres {
	return &AuthRepositoryPostgres{db: db}
}

// SaveUser - это то, как "рабочий" сохраняет пользователя в PostgreSQL.
func (r *AuthRepositoryPostgres) SaveUser(ctx context.Context, user domain.User) error {
	query := `INSERT INTO users (id, email, password_hash, username, name, surname, status, email_verification_code, created_at, updated_at)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := r.db.Exec(ctx, query,
		user.ID,
		user.Email,
		user.PasswordHash,
		user.Username,
		user.Name,
		user.Surname,
		user.Status,
		user.EmailVerificationCode,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("не удалось сохранить пользователя в PostgreSQL: %w", err)
	}
	return nil
}

// GetUserByEmail - то, как "рабочий" находит пользователя по email в PostgreSQL.
func (r *AuthRepositoryPostgres) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	var user domain.User
	query := `SELECT id, email, password_hash, username, name, surname, status, email_verification_code, created_at, updated_at
              FROM users WHERE email = $1`
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Username,
		&user.Name,
		&user.Surname,
		&user.Status,
		&user.EmailVerificationCode,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, common_errors.ErrNotFound // Если не нашли, говорим, что не найдено
		}
		return domain.User{}, fmt.Errorf("не удалось получить пользователя по email из PostgreSQL: %w", err)
	}
	return user, nil
}

// Другие методы (GetUserByUsername, SaveSession и т.д.) будут выглядеть похожим образом.
// ...

```
