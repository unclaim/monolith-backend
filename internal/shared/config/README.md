# Конфигурация (internal/shared/config/config.go)
```go
package config

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/joho/godotenv"
)

// Config содержит все настройки приложения, загруженные из переменных окружения.
type Config struct {
	Env            string `env:"APP_ENV,required"`
	Port           string `env:"APP_PORT,required"`
	SecretKey      string `env:"APP_SECRET_KEY,required"`
	CSRFSecret     string `env:"APP_CSRF_SECRET,required"`

	Postgres struct {
		Host            string `env:"POSTGRES_HOST,required"`
		Port            string `env:"POSTGRES_PORT,required"`
		User            string `env:"POSTGRES_USER,required"`
		Password        string `env:"POSTGRES_PASSWORD,required"`
		DBName          string `env:"POSTGRES_DB,required"`
		SSLMode         string `env:"POSTGRES_SSLMODE,required"`
		MaxConnections  int    `env:"POSTGRES_MAX_CONN,default=10"`
		MaxIdleConns    int    `env:"POSTGRES_MAX_IDLE_CONN,default=5"`
		ConnMaxLifetime time.Duration `env:"POSTGRES_CONN_MAX_LIFETIME,default=5m"`
	}

	Redis struct {
		Host     string `env:"REDIS_HOST,required"`
		Port     string `env:"REDIS_PORT,required"`
		Password string `env:"REDIS_PASSWORD"`
		DB       int    `env:"REDIS_DB,default=0"`
		PoolSize int    `env:"REDIS_POOL_SIZE,default=10"`
	}

	MongoDB struct {
		URI    string `env:"MONGO_URI,required"`
		DBName string `env:"MONGO_DB_NAME,required"`
	}

	Email struct {
		SenderName    string `env:"EMAIL_SENDER_NAME,required"`
		SenderAddress string `env:"EMAIL_SENDER_ADDRESS,required"`
		SMTPHost      string `env:"EMAIL_SMTP_HOST,required"`
		SMTPPort      int    `env:"EMAIL_SMTP_PORT,required"`
		SMTPUsername  string `env:"EMAIL_SMTP_USERNAME,required"`
		SMTPPassword  string `env:"EMAIL_SMTP_PASSWORD,required"`
	}
}

// LoadConfig загружает конфигурацию приложения из переменных окружения.
// Использует пакет godotenv для чтения переменных из файла .env в режиме разработки.
func LoadConfig(log *slog.Logger) (*Config, error) {
	// Загружаем .env файл только если он существует и мы не в продакшене
	if _, err := os.Stat(".env"); err == nil && os.Getenv("APP_ENV") != "production" {
		err := godotenv.Load()
		if err != nil {
			log.Warn("Не удалось загрузить файл .env", "ошибка", err)
		}
	}

	cfg := &Config{}
	
	// Общие настройки
	cfg.Env = getEnv("APP_ENV", "development")
	cfg.Port = getEnv("APP_PORT", "8080")
	cfg.SecretKey = getEnv("APP_SECRET_KEY", "")
	cfg.CSRFSecret = getEnv("APP_CSRF_SECRET", "")

	// Настройки PostgreSQL
	cfg.Postgres.Host = getEnv("POSTGRES_HOST", "localhost")
	cfg.Postgres.Port = getEnv("POSTGRES_PORT", "5432")
	cfg.Postgres.User = getEnv("POSTGRES_USER", "user")
	cfg.Postgres.Password = getEnv("POSTGRES_PASSWORD", "password")
	cfg.Postgres.DBName = getEnv("POSTGRES_DB", "youdo_clone_db")
	cfg.Postgres.SSLMode = getEnv("POSTGRES_SSLMODE", "disable")
	cfg.Postgres.MaxConnections = getEnvAsInt("POSTGRES_MAX_CONN", 10)
	cfg.Postgres.MaxIdleConns = getEnvAsInt("POSTGRES_MAX_IDLE_CONN", 5)
	cfg.Postgres.ConnMaxLifetime = getEnvAsDuration("POSTGRES_CONN_MAX_LIFETIME", 5*time.Minute)

	// Настройки Redis
	cfg.Redis.Host = getEnv("REDIS_HOST", "localhost")
	cfg.Redis.Port = getEnv("REDIS_PORT", "6379")
	cfg.Redis.Password = getEnv("REDIS_PASSWORD", "")
	cfg.Redis.DB = getEnvAsInt("REDIS_DB", 0)
	cfg.Redis.PoolSize = getEnvAsInt("REDIS_POOL_SIZE", 10)

	// Настройки MongoDB
	cfg.MongoDB.URI = getEnv("MONGO_URI", "mongodb://localhost:27017")
	cfg.MongoDB.DBName = getEnv("MONGO_DB_NAME", "youdo_clone_chat")

	// Настройки Email
	cfg.Email.SenderName = getEnv("EMAIL_SENDER_NAME", "")
	cfg.Email.SenderAddress = getEnv("EMAIL_SENDER_ADDRESS", "")
	cfg.Email.SMTPHost = getEnv("EMAIL_SMTP_HOST", "")
	cfg.Email.SMTPPort = getEnvAsInt("EMAIL_SMTP_PORT", 587)
	cfg.Email.SMTPUsername = getEnv("EMAIL_SMTP_USERNAME", "")
	cfg.Email.SMTPPassword = getEnv("EMAIL_SMTP_PASSWORD", "")

	// Проверяем обязательные параметры, которые не имеют значений по умолчанию
	if cfg.SecretKey == "" {
		return nil, fmt.Errorf("переменная окружения APP_SECRET_KEY не установлена")
	}
	if cfg.CSRFSecret == "" {
		return nil, fmt.Errorf("переменная окружения APP_CSRF_SECRET не установлена")
	}

	log.Info("Конфигурация успешно загружена", "окружение", cfg.Env)
	return cfg, nil
}

// Вспомогательные функции для получения переменных окружения
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsInt(name string, defaultVal int) int {
    valueStr := getEnv(name, "")
    if valueStr == "" {
        return defaultVal
    }
    var value int
    _, err := fmt.Sscanf(valueStr, "%d", &value)
    if err != nil {
        slog.Default().Warn("Некорректное значение переменной окружения", "переменная", name, "значение", valueStr, "ошибка", err, "используется_по_умолчанию", defaultVal)
        return defaultVal
    }
    return value
}

func getEnvAsDuration(name string, defaultVal time.Duration) time.Duration {
    valueStr := getEnv(name, "")
    if valueStr == "" {
        return defaultVal
    }
    duration, err := time.ParseDuration(valueStr)
    if err != nil {
        slog.Default().Warn("Некорректное значение переменной окружения", "переменная", name, "значение", valueStr, "ошибка", err, "используется_по_умолчанию", defaultVal)
        return defaultVal
    }
    return duration
}
```

Добавь зависимость: В корне проекта выполни: go get github.com/joho/godotenv
# Пояснение:
Используем пакет github.com/joho/godotenv для удобной загрузки переменных окружения из файла .env в режиме разработки.
Структура Config содержит все необходимые настройки, разбитые по категориям (общие, PostgreSQL, Redis, MongoDB, Email).
Функция LoadConfig загружает значения из окружения, предоставляя значения по умолчанию, если переменная не установлена. Это делает наше приложение более гибким.
Мы проверяем наличие критически важных секретов, чтобы приложение не запустилось без них.
