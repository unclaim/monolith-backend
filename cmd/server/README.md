# cmd/server/main.go - Наш Главный Выключатель
Этот файл — точка входа в приложение. Он очень прост: загружает настройки, настраивает, как мы будем записывать важные события (логи), и запускает нашу главную "фабрику" (app_bootstrap), которая собирает все части приложения вместе.
```go
package main

import (
	"context"
	"log/slog" // Для записи логов
	"net/http"  // Для работы с HTTP-сервером
	"os"        // Для работы с файлами и окружением

	// Здесь мы импортируем наш собственный код.
	// Замените "your-app-name" на имя вашего Go-модуля (из go.mod)
	"your-app-name/internal"
	"your-app-name/pkg/infrastructure/logger" // Наш логгер
)

// @title YouDo-Клон API
// @version 1.0
// @description Документация по API для платформы "YouDo-клон".
// @host localhost:8080
// @BasePath /api/v1
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
func main() {
	// 1. Настраиваем, куда будем записывать логи.
	// Это как дать ручку и блокнот, чтобы записывать все, что происходит.
	// Мы записываем в консоль (os.Stdout)
	slogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug, // Записываем все сообщения, даже отладочные
	}))
	slog.SetDefault(slogger) // Устанавливаем его как логгер по умолчанию

	// 2. Инициализируем наш логгер (это наш pkg/infrastructure/logger)
	// Мы передаем стандартный slog, чтобы наш логгер умел записывать
	appLogger := logger.New(slogger)

	// 3. Создаем главный HTTP-маршрутизатор. Это как главный указатель дорог.
	router := http.NewServeMux()

	// 4. Запускаем "сборку мебели" (app_bootstrap).
	// Он связывает все домики и их части вместе, настраивает их.
	// Здесь мы передаем логгер и маршрутизатор, чтобы они могли быть использованы внутри.
	// Context.Background() - это как общий фон для всех операций.
	err := internal.BootstrapApplication(context.Background(), router, appLogger)
	if err != nil {
		appLogger.Error("Ошибка при запуске приложения", "error", err)
		os.Exit(1) // Если что-то пошло не так, выходим
	}

	appLogger.Info("Сервер запускается...", "адрес", ":8080")

	// 5. Запускаем HTTP-сервер. Это как открыть двери нашего дома,
	// чтобы люди могли заходить по дорогам, которые мы настроили.
	err = http.ListenAndServe(":8080", router)
	if err != nil {
		appLogger.Error("Ошибка при запуске HTTP-сервера", "error", err)
		os.Exit(1)
	}
}
```