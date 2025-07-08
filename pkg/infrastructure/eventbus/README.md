# pkg/infrastructure/eventbus/eventbus.go - Наша Шина Новостей (In-Memory)
Это наша шина новостей. Она позволяет разным частям приложения "публиковать" (отправлять) новости и "подписываться" (слушать) на них. Эта версия очень простая и работает только пока приложение запущено (in-memory).

```go
package eventbus

import (
	"context"
	"log/slog" // Для записи логов
	"sync"      // Для безопасной работы с данными одновременно
)

// Event - это то, что мы отправляем по шине новостей. У каждой новости есть тип.
type Event interface {
	EventType() string // Тип новости (например, "UserRegistered")
}

// EventHandler - это тот, кто умеет слушать и обрабатывать новости.
type EventHandler func(ctx context.Context, event Event) error

// EventBus - это наша шина новостей. Это обещание (интерфейс), как она должна работать.
type EventBus interface {
	Publish(ctx context.Context, event Event) error          // Опубликовать новость
	Subscribe(eventType string, handler EventHandler) error  // Подписаться на новости определенного типа
}

// InMemoryEventBus - это простая версия шины новостей, которая работает в памяти.
type InMemoryEventBus struct {
	// Это как блокнот, где для каждого типа новости (ключа) записаны все, кто на нее подписан (значение).
	handlers map[string][]EventHandler
	mu       sync.RWMutex // Замок, чтобы никто не мешал друг другу записывать или читать
	logger   *slog.Logger // Наш логгер для записи происходящего
}

// NewInMemoryEventBus создает новую шину новостей.
func NewInMemoryEventBus(logger *slog.Logger) *InMemoryEventBus {
	return &InMemoryEventBus{
		handlers: make(map[string][]EventHandler),
		logger:   logger,
	}
}

// Publish - метод для публикации новости.
func (eb *InMemoryEventBus) Publish(ctx context.Context, event Event) error {
	eb.mu.RLock()         // Берем замок для чтения (мы не меняем список подписчиков)
	defer eb.mu.RUnlock() // Отпускаем замок, когда закончим

	eventType := event.EventType()
	handlers, ok := eb.handlers[eventType]
	if !ok {
		eb.logger.Debug("Нет подписчиков для события", "тип", eventType)
		return nil // Никто не слушает эту новость, это нормально
	}

	// Отправляем новость всем, кто на нее подписан.
	for _, handler := range handlers {
		// Запускаем обработчик в отдельной "нитью" (горутине), чтобы он не блокировал
		// отправку других новостей.
		go func(h EventHandler) {
			if err := h(ctx, event); err != nil {
				eb.logger.Error("Ошибка обработки события", "тип", eventType, "error", err)
			}
		}(handler)
	}
	return nil
}

// Subscribe - метод для подписки на новости.
func (eb *InMemoryEventBus) Subscribe(eventType string, handler EventHandler) error {
	eb.mu.Lock()          // Берем замок для записи (мы меняем список подписчиков)
	defer eb.mu.Unlock()  // Отпускаем замок, когда закончим

	eb.handlers[eventType] = append(eb.handlers[eventType], handler)
	eb.logger.Info("Подписан новый обработчик", "тип_события", eventType)
	return nil
}


```