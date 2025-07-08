# Общие ошибки (internal/shared/common_errors/errors.go)
```go
package common_errors

import (
	"fmt"
	"net/http"
)

// ErrorResponse представляет собой стандартизированную структуру для HTTP-ответов об ошибках.
type ErrorResponse struct {
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

// BaseError представляет базовый интерфейс для всех доменных ошибок.
type BaseError interface {
	Error() string // Реализация интерфейса error
	HTTPStatus() int // Возвращает соответствующий HTTP-статус
	ErrorCode() string // Возвращает код ошибки (например, "AUTH_INVALID_CREDENTIALS")
	Details() map[string]string // Возвращает дополнительные детали ошибки
}

// AppError является общей реализацией BaseError для ошибок приложения.
type AppError struct {
	Msg      string
	Status   int
	Code     string
	ErrDetails map[string]string
	InternalErr error // Внутренняя ошибка, которую не следует раскрывать клиенту
}

// NewAppError создает новый экземпляр AppError.
func NewAppError(status int, code, msg string, details ...map[string]string) *AppError {
	errDetails := make(map[string]string)
	if len(details) > 0 {
		errDetails = details[0]
	}
	return &AppError{
		Msg:      msg,
		Status:   status,
		Code:     code,
		ErrDetails: errDetails,
	}
}

// WrapAppError оборачивает существующую ошибку в AppError, добавляя внутреннюю ошибку.
func WrapAppError(internalErr error, status int, code, msg string, details ...map[string]string) *AppError {
	errDetails := make(map[string]string)
	if len(details) > 0 {
		errDetails = details[0]
	}
	return &AppError{
		Msg:      msg,
		Status:   status,
		Code:     code,
		ErrDetails: errDetails,
		InternalErr: internalErr,
	}
}


// Error реализует интерфейс error.
func (e *AppError) Error() string {
	if e.InternalErr != nil {
		return fmt.Sprintf("%s: %v", e.Msg, e.InternalErr)
	}
	return e.Msg
}

// HTTPStatus возвращает HTTP-статус для этой ошибки.
func (e *AppError) HTTPStatus() int {
	return e.Status
}

// ErrorCode возвращает код ошибки.
func (e *AppError) ErrorCode() string {
	return e.Code
}

// Details возвращает дополнительные детали ошибки.
func (e *AppError) Details() map[string]string {
	return e.ErrDetails
}


// Предопределенные стандартные ошибки приложения
var (
	ErrInternalServer = NewAppError(http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Произошла внутренняя ошибка сервера.")
	ErrNotFound       = NewAppError(http.StatusNotFound, "NOT_FOUND", "Запрошенный ресурс не найден.")
	ErrInvalidInput   = NewAppError(http.StatusBadRequest, "INVALID_INPUT", "Неверные или отсутствующие входные данные.")
	ErrUnauthorized   = NewAppError(http.StatusUnauthorized, "UNAUTHORIZED", "Для доступа к этому ресурсу требуется аутентификация.")
	ErrForbidden      = NewAppError(http.StatusForbidden, "FORBIDDEN", "У вас нет прав для доступа к этому ресурсу.")
	ErrConflict       = NewAppError(http.StatusConflict, "CONFLICT", "Конфликт данных, ресурс с такими параметрами уже существует.")
)
```

# Пояснение:
Мы определяем стандартную структуру ErrorResponse для единообразных ответов об ошибках клиенту.
BaseError: Это интерфейс, который должны реализовать все доменные ошибки. Это позволяет нам централизованно обрабатывать ошибки в HTTP-слое, определяя HTTP-статус, код ошибки и детали.
AppError: Базовая реализация BaseError. Она позволяет обернуть внутренние ошибки (которые мы не хотим показывать клиенту) и предоставляет поля для сообщения, HTTP-статуса и кода ошибки.
Предопределенные ошибки, такие как ErrInternalServer, ErrNotFound, упрощают создание типичных ответов.
