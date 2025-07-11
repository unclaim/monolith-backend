package logger

import (
	"log/slog"
	"os"
)

// SetupLogger инициализирует и возвращает новый *slog.Logger.
// Логгер настроен для вывода структурированных логов в стандартный вывод.
// Уровень логирования по умолчанию - INFO, но может быть переопределен.
func SetupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case "development":
		log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: true, // Добавляем информацию о файле и строке
		}))
	case "production":
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	default: // По умолчанию для staging, testing и т.д.
		log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	}

	slog.SetDefault(log) // Устанавливаем наш логгер как дефолтный
	return log
}
