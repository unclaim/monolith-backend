# internal/auth/api/handlers.go - Двери в Домик "Авторизация" 🚪
Эта папка — как двери, через которые люди стучатся в наш домик "Авторизация". Когда кто-то хочет зарегистрироваться или войти, он отправляет запрос именно сюда. Эти двери принимают запрос, проверяют его, а затем просят "главного работника" (сервис) выполнить нужную задачу. После этого они красиво упаковывают ответ и отправляют его обратно.
Где это: your-ultra-scalable-monolith/internal/auth/api/handlers.go
Что здесь:
Обработка запросов: Здесь код "слушает", что говорят люди (получает HTTP-запросы).
Проверка данных: Он смотрит, правильно ли написаны данные в запросе (например, правильный ли формат email или пароля). Если что-то не так, он сразу говорит об ошибке.
Передача задачи сервису: Если все хорошо, он передает "главному работнику" (нашему domain/service.go) команду выполнить то, что хочет пользователь (например, "зарегистрируй этого пользователя").
Формирование ответа: Получив результат от "главного работника", он создает красивый ответ для пользователя (например, "Вы успешно зарегистрированы!" или "Что-то пошло не так").
Пример:

```go
package api

import (
	"encoding/json" // Для работы с JSON-данными
	"net/http"      // Для работы с HTTP-запросами и ответами
	"log/slog"      // Для записи логов

	"your-app-name/internal/auth/domain"         // Наш домен "Auth"
	"your-app-name/internal/shared/common_errors" // Общие ошибки
	"your-app-name/internal/shared/validator"    // Наш валидатор для проверки данных
)

// Handlers содержит наши HTTP-обработчики для домена авторизации.
// Он "знает" о сервисе, который выполняет основную работу.
type Handlers struct {
	authService domain.AuthService // Это наш "главный работник" домика Auth
	logger      *slog.Logger       // Наш логгер
}

// NewHandlers создает новые двери для домика Auth.
func NewHandlers(authService domain.AuthService, logger *slog.Logger) *Handlers {
	return &Handlers{
		authService: authService,
		logger:      logger,
	}
}

// RegisterRequest - это как "форма", которую заполняет пользователь для регистрации.
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`      // Почта, обязательно и должен быть формат email
	Password string `json:"password" validate:"required,min=8"`   // Пароль, обязательно и минимум 8 символов
}

// @Summary Зарегистрировать нового пользователя
// @Description Регистрирует нового пользователя в системе, отправляет код подтверждения на email.
// @Tags auth
// @Accept json
// @Produce json
// @Param user_data body RegisterRequest true "Данные для регистрации пользователя"
// @Success 202 {object} map[string]string "Сообщение о том, что код подтверждения отправлен"
// @Failure 400 {object} common_errors.ErrorResponse "Неверные входные данные или пользователь с таким email уже существует"
// @Failure 500 {object} common_errors.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/register [post]
// Register - это функция, которая обрабатывает запрос на регистрацию.
func (h *Handlers) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	// 1. Пытаемся прочитать данные из запроса (как заполненную форму).
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Не удалось разобрать запрос регистрации", "error", err)
		common_errors.SendJSONError(w, common_errors.NewBadRequestError("Неверный формат запроса"), http.StatusBadRequest)
		return
	}

	// 2. Проверяем данные (правильно ли заполнена форма).
	if err := validator.ValidateStruct(req); err != nil {
		h.logger.Warn("Неверные входные данные при регистрации", "error", err)
		common_errors.SendJSONError(w, common_errors.NewBadRequestError(err.Error()), http.StatusBadRequest)
		return
	}

	// 3. Передаем задачу "главному работнику" (сервису).
	_, err := h.authService.RegisterUser(r.Context(), req.Email, req.Password)
	if err != nil {
		h.logger.Error("Ошибка регистрации пользователя", "email", req.Email, "error", err)
		// Превращаем ошибку сервиса в HTTP-ответ
		common_errors.SendJSONError(w, err, common_errors.HTTPStatusFromError(err))
		return
	}

	// 4. Отправляем успешный ответ.
	w.WriteHeader(http.StatusAccepted) // Принято, но еще не завершено (ждет подтверждения email)
	json.NewEncoder(w).Encode(map[string]string{"message": "Код подтверждения отправлен на вашу почту"})
}

// ... Другие обработчики: Login, VerifyEmail, CompleteRegistration и т.д.


```