# Шина событий (pkg/infrastructure/eventbus/eventbus.go)
```go
package eventbus

import (
	"log/slog"
	"sync"
)

// Event представляет собой интерфейс для любого события, которое может быть опубликовано.
type Event interface {
	EventType() string
}

// EventHandler представляет собой функцию-обработчик для конкретного типа события.
type EventHandler func(event Event)

// EventBus определяет интерфейс шины событий.
type EventBus interface {
	Publish(event Event)
	Subscribe(eventType string, handler EventHandler)
}

// InMemoryEventBus implements EventBus for in-memory event dispatching.
type InMemoryEventBus struct {
	handlers map[string][]EventHandler
	mu       sync.RWMutex
	log      *slog.Logger
}

// NewInMemoryEventBus создает новый экземпляр InMemoryEventBus.
func NewInMemoryEventBus(log *slog.Logger) *InMemoryEventBus {
	return &InMemoryEventBus{
		handlers: make(map[string][]EventHandler),
		log:      log,
	}
}

// Publish отправляет событие всем подписанным обработчикам.
func (eb *InMemoryEventBus) Publish(event Event) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	eventType := event.EventType()
	if handlers, ok := eb.handlers[eventType]; ok {
		eb.log.Debug("Публикация события", "тип", eventType)
		// Запускаем каждый обработчик в отдельной горутине, чтобы не блокировать публикатора.
		// Важно: обработчики должны быть идемпотентны и не зависеть от порядка выполнения,
		// так как нет гарантий порядка при параллельной обработке.
		for _, handler := range handlers {
			go func(h EventHandler, e Event) {
				defer func() {
					if r := recover(); r != nil {
						eb.log.Error("Паника в обработчике события", "тип", eventType, "recover", r)
					}
				}()
				h(e)
			}(handler, event)
		}
	} else {
		eb.log.Debug("Нет обработчиков для события", "тип", eventType)
	}
}

// Subscribe подписывает обработчик на определенный тип события.
func (eb *InMemoryEventBus) Subscribe(eventType string, handler EventHandler) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	eb.handlers[eventType] = append(eb.handlers[eventType], handler)
	eb.log.Info("Обработчик успешно подписан на событие", "тип", eventType)
}

```
# Пояснение:
Event и EventHandler определяют интерфейсы для событий и их обработчиков.
InMemoryEventBus — простая реализация шины событий, которая хранит обработчики в памяти.
Publish отправляет событие. Каждый обработчик запускается в отдельной горутине, чтобы публикатор не ждал завершения всех обработчиков.
Subscribe позволяет зарегистрировать обработчик для определенного типа события.
