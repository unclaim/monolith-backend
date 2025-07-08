package user

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"sync"
)

// CheckUserRequest - структура для проверки пользователя по полю username
// @Description Данные для проверки пользователя
// @Title CheckUserRequest
type CheckUserRequest struct {
	Username *string `json:"username" example:"test_user"`
}

// LoginRequest - структура запроса для входа пользователя
// @Description Структура данных для авторизации пользователя
// @Title LoginRequest
type LoginRequest struct {
	Username     *string `json:"username,omitzero"`
	PasswordHash string  `json:"password_hash,omitzero"`
}

// GetByLoginOrEmail retrieves a user from the database by either username or email.
// It returns the User object if found, or nil if no user is found matching the criteria.
// In case of a database or parsing error, it returns an error.
// Params:
//   - ctx: context.Context for managing request-scoped values and cancellation.
//   - username: the username to search for.
//   - email: the email to search for.
// Returns:
//   - *User: the retrieved User object, or nil if not found.
//   - error: any error encountered during query execution or parsing.

func (repository *UserRepository) GetByLoginOrEmail(ctx context.Context, username string, email string) (*User, error) {
	const SQL_READ_LOGIN_OR_EMAIL = `
		SELECT id, username, email, password_hash /* добавьте остальные поля */
		FROM users
		WHERE username = $1 OR email = $2
		LIMIT 1
	`

	row := repository.db.QueryRow(ctx, SQL_READ_LOGIN_OR_EMAIL, username, email)

	user, err := parseRowToUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Пользователь не найден
			return nil, nil // или возвращайте специальную ошибку
		}
		// Другие ошибки парсинга или выполнения запроса
		return nil, fmt.Errorf("ошибка при парсинге строки пользователя: %w", err)
	}

	return user, nil
}

var (
	ErrMessageTooLong = errors.New("содержимое сообщения слишком длинное")
	ErrDatabaseError  = errors.New("ошибка базы данных")
)

// getUserProfileData - вспомогательный метод для получения данных профиля пользователя.
func (repository *UserRepository) getUserProfileData(profileID, currentUserId int64) (Response, error) {
	// Получаем профиль пользователя и число подписок
	profile, subscriptionsCount, err := repository.GetUserProfile(profileID, currentUserId)
	if err != nil {
		return Response{}, fmt.Errorf("не удалось получить профиль пользователя: %v", err)
	}

	// Получаем новые сообщения для текущего пользователя
	messages, err := repository.GetNewMessages(currentUserId)
	if err != nil {
		return Response{}, fmt.Errorf("не удалось получить новые сообщения: %v", err)
	}

	// Проверяем, заблокирован ли текущий пользователь
	isBlocked, err := repository.isBlocked(currentUserId, profileID)
	if err != nil {
		return Response{}, fmt.Errorf("не удалось проверить статус блокировки: %v", err)
	}

	// Проверяем, подписан ли текущий пользователь
	isFollowing, err := repository.isFollowing(currentUserId, profileID)
	if err != nil {
		return Response{}, fmt.Errorf("не удалось проверить статус подписки: %v", err)
	}

	// Формируем и возвращаем ответ
	response := Response{
		StatusCode: http.StatusOK,
		Body: struct {
			Profile            User      `json:"profile"`
			Messages           []Message `json:"messages"`
			SubscriptionsCount int64     `json:"subscriptions_count"`
			IsBlocked          bool      `json:"is_blocked"`
			IsFollowing        bool      `json:"is_following"`
		}{
			Profile:            profile,
			Messages:           messages,
			SubscriptionsCount: subscriptionsCount,
			IsBlocked:          isBlocked,
			IsFollowing:        isFollowing,
		},
	}
	return response, nil
}

// parseSignupRequest парсит тело запроса и возвращает объект SignUpRequest.
// @Summary Парсинг запроса на регистрацию
// @Description Парсит тело запроса и возвращает объект SignUpRequest.
// @Tags users
// @Param request body SignUpRequest true "Данные для регистрации"
// @Success 200 {object} SignUpRequest "Успешный парсинг данных"
// @Failure 400 {object} ErrorResponse "Ошибка парсинга данных"
func parseSignupRequest(r *http.Request) (SignUpRequest, error) {
	var signupRequest SignUpRequest
	if err := json.NewDecoder(r.Body).Decode(&signupRequest); err != nil {
		return signupRequest, fmt.Errorf("неверный формат JSON: %v", err)
	}

	if err := validateSignupRequest(signupRequest); err != nil {
		return signupRequest, fmt.Errorf("ошибка валидации данных: %v", err)
	}

	return signupRequest, nil
}

// validateSignupRequest проверяет корректность данных для регистрации пользователя.
// @Summary Валидация данных для регистрации
// @Description Проверяет корректность данных для регистрации пользователя.
// @Tags users
// @Param req body SignUpRequest true "Данные для регистрации"
// @Success 200 {string} string "Данные валидны"
// @Failure 400 {object} ErrorResponse "Ошибка валидации данных"
func validateSignupRequest(req SignUpRequest) error {
	if req.FirstName == "" || req.LastName == "" || req.Username == "" || req.Email == "" || req.Password == "" {
		return errors.New("все поля обязательны для заполнения")
	}
	return nil
}

// userLinksCache - кэш для хранения ссылок пользователей
var userLinksCache sync.Map

// handleVerificationAndSession обрабатывает создание кода верификации и сессии для нового пользователя.
// @Summary Обработка верификации и сессии
// @Description Создает код верификации и сессию для нового пользователя.
// @Tags users
// @Param userId path string true "ID пользователя"
// @Success 200 {string} string "Успешно обработано"
// @Failure 500 {object} ErrorResponse "Ошибка сервера"
// func (uh *UserHandler) handleVerificationAndSession(ctx context.Context, w http.ResponseWriter, user *User, r *http.Request) error {
// 	code, err := generateRandomCode(6)
// 	if err != nil {
// 		return fmt.Errorf("ошибка генерации кода: %v", err)
// 	}

// 	// codeStr := fmt.Sprintf("%d", code)
// 	// Преобразование кода в int64
// 	codeInt64 := int64(code)
// 	if err := images.Directories(user.ID); err != nil {
// 		return fmt.Errorf("ошибка создания директорий для пользователя: %v", err)
// 	}

// 	if err := uh.UsersRepo.CreateAccountVerificationsCode(ctx, user.Email, codeInt64); err != nil {
// 		return fmt.Errorf("ошибка сохранения кода верификации: %v", err)
// 	}

// 	// if err := uh.SendVerificationEmail(user.Email, codeStr); err != nil {
// 	// 	return fmt.Errorf("ошибка отправки email: %v", err)
// 	// }
// 	// slog.Info("Код верификации успешно отправлен на почту", "userEmail", user.Email)

// 	userInterface, ok := interface{}(user).(session.UserInterface) // Приведение типа
// 	if !ok {
// 		return errors.New("пользователь не реализует интерфейс session.UserInterface")
// 	}

// 	if err := uh.Sessions.Create(ctx, w, userInterface, r); err != nil {
// 		return fmt.Errorf("ошибка создания сессии: %v", err)
// 	}

// 	return nil
// }

// SendVerificationEmail отправляет код верификации на указанный адрес электронной почты.
// @Summary Отправка кода верификации по электронной почте
// @Description Отправляет код верификации на указанный адрес электронной почты.
// @Tags users
// @Param to query string true "Адрес электронной почты"
// @Param code query string true "Код верификации"
// @Success 200 {string} string "Код успешно отправлен"
// @Failure 500 {object} ErrorResponse "Ошибка при отправке email"
func (uh *UserHandler) SendVerificationEmail(to string, code string) error {
	from := "duginea@mail.ru"
	password := "L9BtgetNuRcPkWUvN9wz" // Замените на ваш пароль

	subject := "Код верификации"
	body := fmt.Sprintf("Ваш код верификации: %s\nПожалуйста, используйте его для подтверждения вашей регистрации.", code)

	msg := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s",
		from,
		to,
		subject,
		body,
	)

	smtpServer := "smtp.mail.ru:587"
	auth := smtp.PlainAuth("", from, password, "smtp.mail.ru")

	err := smtp.SendMail(smtpServer, auth, from, []string{to}, []byte(msg))
	if err != nil {

		return fmt.Errorf("не удалось отправить email: %w", err)
	}

	return nil
}

// createUser создает нового пользователя в репозитории пользователей.
// @Summary Создание нового пользователя
// @Description Создает нового пользователя в репозитории пользователей.
// @Tags users
// @Param signupRequest body SignUpRequest true "Данные для регистрации"
// @Success 201 {object} User "Пользователь успешно создан"
// @Failure 500 {object} ErrorResponse "Ошибка при создании пользователя"
func (uh *UserHandler) createUser(ctx context.Context, signupRequest SignUpRequest) (*User, error) {
	// Создание нового пользователя
	user, err := uh.UsersRepo.CreateUser(ctx,
		signupRequest.FirstName,
		signupRequest.LastName,
		signupRequest.Username,
		signupRequest.Email,
		signupRequest.Password,
	)

	if err != nil {
		return nil, fmt.Errorf("ошибка при создании пользователя: %w", err)
	}

	return user, nil
}

// UpdateUserSkills обновляет навыки пользователя.
// userID - идентификатор пользователя
// skills - список навыков пользователя
// Возвращает ошибку, если обновление не удалось
func (uh *UserHandler) UpdateUserSkills(userID int64, skills []int) error {
	// Проверяем входные данные
	if len(skills) == 0 {
		return fmt.Errorf("список навыков пуст")
	}

	// Проверяем корректность значений навыков
	for _, skill := range skills {
		if skill < 0 {
			return fmt.Errorf("некорректный индекс навыка: %d", skill)
		}
	}

	// Обращаемся к репозиторию для обновления навыков
	err := uh.UsersRepo.UpdateUserSkills(userID, skills)
	if err != nil {
		return fmt.Errorf("ошибка при обновлении навыков пользователя с ID %d: %w", userID, err)
	}

	return nil
}
