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
package user

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"

	"log/slog"
)

// Режим отладки
const debugMode = true

// Основная функция обработки ошибок
func handleError(w http.ResponseWriter, req *http.Request, err error, statusCode int) {
	// Дополнительные атрибуты: метод, путь, IP-адрес
	ipAddress := getClientIP(req)

	// Прямо передаем все атрибуты без группировок
	slog.Error(
		"API Error occurred",
		slog.String("error", err.Error()),
		slog.String("method", req.Method),
		slog.String("path", req.URL.Path),
		slog.String("remote_ip", ipAddress),
	)
	var trace []byte
	if debugMode {
		trace = debug.Stack()
	}

	errorResp := &ErrorResponse{
		ErrorMessage: fmt.Sprintf("%s", err),
		ErrorType:    determineErrorType(statusCode),
		StackTrace:   formatStackTrace(trace), // Красиво оформляем стектрейс
	}

	response := &Response{
		StatusCode: statusCode,
		Body:       errorResp,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		return
	}
}

// Функция для получения IP-адреса клиента
func getClientIP(r *http.Request) string {
	// Сначала пробуем из X-Real-IP
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Затем проверяем X-Forwarded-For
	forwardIP := r.Header.Get("X-Forwarded-For")
	if forwardIP != "" {
		return forwardIP
	}

	// Иначе берем RemoteAddr
	addrParts := strings.Split(r.RemoteAddr, ":")
	if len(addrParts) > 0 {
		return addrParts[0]
	}

	return "unknown"
}

// Функция для красивого оформления стектрейса
func formatStackTrace(trace []byte) []string {
	if len(trace) == 0 {
		return nil
	}

	// Деление стектрейса на строки
	lines := bytes.Split(trace, []byte("\n"))

	// Количество выводимых строк стектрейса
	maxLines := 10
	if len(lines) > maxLines {
		lines = lines[:maxLines]
	}

	// Начнём с фильтрацией ненужных кадров
	filteredLines := filterRelevantLines(lines)

	// Возвращаем чистые строки стектрейса
	return filteredLines
}

// Фильтруем только нужные строки стектрейса
func filterRelevantLines(lines [][]byte) []string {
	result := make([]string, 0)

	for _, line := range lines {
		// Конвертируем строку
		str := string(line)

		// Проверяем, содержится ли важная информация
		if containsImportant(str) {
			// Преобразуем строку в удобную форму
			formatted := formatStackFrame(str)
			result = append(result, formatted)
		}
	}

	return result
}

// Проверяем, важна ли данная строка стектрейса
func containsImportant(line string) bool {
	// Игнорируем некоторые известные несущественные записи
	if strings.HasPrefix(line, "goroutine ") || strings.HasSuffix(line, "+0x5e") {
		return false
	}

	// Если видим знак TAB (\t), значит это потенциальная важная запись
	return strings.Contains(line, "\t")
}

// Форматируем каждый кадр стектрейса
func formatStackFrame(frame string) string {
	parts := strings.Split(frame, "\t")
	if len(parts) < 2 {
		return frame
	}

	// Первый элемент — функциональная информация
	functionInfo := strings.TrimSpace(parts[0])

	// Второй элемент — информация о файле и строке
	locationInfo := strings.TrimSpace(parts[1])

	// Чистим путь файла
	cleanLocation := cleanFilePath(locationInfo)

	// Объединяем обратно
	return functionInfo + " (" + cleanLocation + ")"
}

// Очищаем путь файла
func cleanFilePath(path string) string {
	const projectBase = "the_server_part/git/pkg/"

	if index := strings.Index(path, projectBase); index >= 0 {
		// Берём только имя пакета и файл
		return path[index+len(projectBase):]
	}

	return path
}

// Определяем тип ошибки по HTTP-коду
func determineErrorType(statusCode int) string {
	switch statusCode {
	case http.StatusNotFound:
		return "NotFound"
	case http.StatusBadRequest:
		return "BadRequest"
	case http.StatusUnauthorized:
		return "Unauthorized"
	case http.StatusForbidden:
		return "Forbidden"
	case http.StatusConflict:
		return "Conflict"
	case http.StatusGone:
		return "Gone"
	case http.StatusPreconditionFailed:
		return "PreconditionFailed"
	case http.StatusUnprocessableEntity:
		return "UnprocessableEntity"
	case http.StatusLocked:
		return "Locked"
	case http.StatusTooManyRequests:
		return "TooManyRequests"
	case http.StatusServiceUnavailable:
		return "ServiceUnavailable"
	case http.StatusGatewayTimeout:
		return "GatewayTimeout"
	case http.StatusMethodNotAllowed:
		return "MethodNotAllowed"
	case http.StatusInternalServerError:
		fallthrough
	case http.StatusBadGateway:
		fallthrough
	case http.StatusHTTPVersionNotSupported:
		return "InternalServerError"
	default:
		return "UnknownError"
	}
}
package user

import (
	"archive/zip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jackc/pgx"
	"github.com/unclaim/the_server_part.git/pkg/session"
	"github.com/unclaim/the_server_part.git/pkg/templates"
)

// HandleAccountVerification проверяет статус верификации аккаунта пользователя.
// Обработчик отображает соответствующую страницу для пользователей с не подтвержденными аккаунтами,
// либо возвращает ошибку, если возникают проблемы с аутентификацией или доступом к данным пользователя.
//
// @Summary      Проверка статуса верификации аккаунта
// @Description  Отображает страницу для не верифицированных пользователей или возвращает сообщение об ошибке
// @Tags         Пользователи
// @Accept json
// @Produce      json
// @Param        Authorization header string true "Авторизационный токен"
// @Success      200 {object} User
// @Failure      401 {string} string "Ошибка при проверке авторизации: %s"
// @Failure      500 {string} string "Ошибка при доступе к данным пользователя: %s"
// @Router       /account/unverified [post]
func (uh *UserHandler) HandleAccountVerification(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить данные сессии: %v", err), http.StatusUnauthorized)
		return
	}

	// Получение информации об аккаунте пользователя.
	account, err := uh.UsersRepo.GetByID(ctx, sess.UserID)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось загрузить информацию об аккаунте: %v", err), http.StatusInternalServerError)
		return
	}

	// Проверяем, является ли метод запроса POST. Для GET-метода возвращаем шаблон страницы.
	if r.Method != http.MethodPost {
		http.Error(w, "Метод должен быть POST", http.StatusMethodNotAllowed)
		return
	}

	// Отправляем информацию об аккаунте в виде JSON-кода.
	if err := json.NewEncoder(w).Encode(account); err != nil {
		handleError(w, r, fmt.Errorf("не удалось отправить ответ: %v", err), http.StatusInternalServerError)
		return
	}
}

// HandleAccountUpdateEmail обрабатывает обновление адреса электронной почты пользователя.
// @Summary Обновление адреса электронной почты пользователя
// @Description Этот метод получает новый email, проверяет его валидность и обновляет информацию в базе данных.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param user_email body string true "Новый адрес электронной почты"
// @Success 302 {object} string "Перезагрузка на страницу подтверждения аккаунта"
// @Failure 400 {object} string "Ошибка: недопустимый email или пустое поле"
// @Failure 401 {object} string "Ошибка: требуется вход в аккаунт"
// @Failure 500 {object} string "Ошибка: не удалось обновить email"
// @Router /account/update-email [post]
func (uh *UserHandler) HandleAccountUpdateEmail(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить данные сессии: %v", err), http.StatusUnauthorized)
		return
	}

	// Проверяем метод запроса
	if r.Method != http.MethodPost {
		handleError(w, r, fmt.Errorf("запрашиваемый метод (%s) не поддерживается", r.Method), http.StatusMethodNotAllowed)
		return
	}

	// Получаем адрес электронной почты из тела запроса.
	var updateRequest struct {
		UserEmail string `json:"user_email"`
	}
	err = json.NewDecoder(r.Body).Decode(&updateRequest)
	if err != nil || updateRequest.UserEmail == "" {
		handleError(w, r, fmt.Errorf("неверный или пустой email: %v", err), http.StatusBadRequest)
		return
	}
	// Устанавливаем deferred закрытие тела ответа с проверкой ошибки
	defer func() {
		if err := r.Body.Close(); err != nil {
			handleError(w, r, fmt.Errorf("ошибка при закрытии тела запроса: %v", err), http.StatusInternalServerError)
			return
		}
	}()

	// Проверяем допустимость адреса электронной почты.
	if err := validateEmail(updateRequest.UserEmail); err != nil {
		handleError(w, r, fmt.Errorf("адрес электронной почты некорректен: %v", err), http.StatusBadRequest)
		return
	}

	// Пытаемся обновить адрес электронной почты пользователя.
	if err := uh.UsersRepo.UpdateEmail(ctx, sess.UserID, updateRequest.UserEmail); err != nil {
		handleError(w, r, fmt.Errorf("не удалось обновить адрес электронной почты: %v", err), http.StatusInternalServerError)
		return
	}

	// После успешного обновления перенаправляем на страницу с не подтвержденным аккаунтом.
	http.Redirect(w, r, "/account/unverified", http.StatusFound)
}

// HandleAccountVerification обрабатывает процесс верификации аккаунта пользователя.
// Метод проверяет предоставленный код верификации и обновляет состояние аккаунта в базе данных.
// Если верификация проходит успешно, пользователь перенаправляется на свою учетную запись.
//
// @Summary Подтверждение аккаунта пользователя
// @Description Проверяет введенный код верификации и активирует учетную запись.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param vercode formData string true "Введенный код верификации"
// @Success 302 {object} string "Учетная запись успешно подтверждена, переходите на страницу профиля."
// @Failure 400 {object} string "Неверный или отсутствующий код верификации"
// @Failure 401 {object} string "Необходимо пройти аутентификацию перед попыткой верификации"
// @Failure 500 {object} string "Ошибка при попытке подтвердить аккаунт"
// @Router /account/verify [post]
func (uh *UserHandler) AccountVerifications(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить данные сессии: %v", err), http.StatusUnauthorized)
		return
	}

	// Проверяем, завершена ли ранее верификация пользователя.
	verified, err := uh.UsersRepo.checkVerifiedByUserID(ctx, int64(sess.UserID))
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось проверить статус верификации: %v", err), http.StatusInternalServerError)
		return
	}

	// Если аккаунт уже верифицирован, перенаправляем на профиль пользователя.
	if verified {
		http.Redirect(w, r, "/user/profile", http.StatusFound)
		return
	}

	// Получаем информацию об аккаунте.
	account, err := uh.UsersRepo.GetByID(ctx, int64(sess.UserID))
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить информацию об аккаунте: %v", err), http.StatusInternalServerError)
		return
	}

	email := account.Email

	// Если метод не POST, показываем форму ввода кода верификации.
	if r.Method != http.MethodPost {
		http.Error(w, "Этот метод доступен только методом POST.", http.StatusMethodNotAllowed)
		return
	}

	// Парсим форму и получаем код верификации.
	if err := r.ParseForm(); err != nil {
		handleError(w, r, fmt.Errorf("не удалось обработать форму: %v", err), http.StatusInternalServerError)
		return
	}

	// Получаем и конвертируем код верификации.
	codeString := r.FormValue("vercode")
	codeInt, err := strconv.Atoi(codeString)
	if err != nil {
		handleError(w, r, fmt.Errorf("некорректный формат кода верификации: %v", err), http.StatusBadRequest)
		return
	}
	code := int64(codeInt)

	// Читаем правильный код верификации из базы данных.
	result, err := uh.UsersRepo.ReadVerificationCode(ctx, email)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось прочитать код верификации: %v", err), http.StatusInternalServerError)
		return
	}

	// Проверяем совпадение введенного кода с ожидаемым.
	if code != result.Code {
		handleError(w, r, fmt.Errorf("код верификации неверный: %v", err), http.StatusBadRequest)
		return
	}

	// Если коды совпадают, устанавливаем флаг верификации.
	if err := uh.UsersRepo.Verified(email); err != nil {
		handleError(w, r, fmt.Errorf("не удалось установить статус верификации: %v", err), http.StatusInternalServerError)
		return
	}

	// Перенаправляем пользователя на страницу профиля после успешной верификации.
	http.Redirect(w, r, "/user/profile", http.StatusFound)
}

// HandleGetAccountInfo обрабатывает запросы на получение информации о текущем пользователе.
// Метод создает CSRF-токен, устанавливает его в куки и отправляет данные пользователя в формате JSON.
//
// @Summary Получение информации о пользователе
// @Description Обрабатывает запросы для получения данных текущего пользователя вместе с созданием CSRF-токена.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} UserResponse "Информация о пользователе"
// @Failure 401 {object} string "Ошибка: не удалось получить сессию"
// @Failure 500 {object} string "Ошибка: не удалось получить данные пользователя"
// @Router /account [get]
func (uh *UserHandler) HandleGetAccountInfo(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить сессионные данные: %v", err), http.StatusUnauthorized)
		return
	}

	// Создаем CSRF-токен, действительный в течение суток
	expirationTime := time.Now().Add(24 * time.Hour)
	CSRFToken, err := uh.Tokens.Create(sess, expirationTime.Unix())
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось создать CSRF-токен: %v", err), http.StatusInternalServerError)
		return
	}

	// Устанавливаем заголовок CSRF-токена
	w.Header().Set("X-CSRF-Token", CSRFToken)

	// Сохраняем CSRF-токен в куки браузера
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    CSRFToken,
		Path:     "/",
		HttpOnly: true,                 // Ограничивает доступ к кукам только серверу
		SameSite: http.SameSiteLaxMode, // Улучшаем безопасность путем ограничения использования токенов
		MaxAge:   86400,                // Токен действует сутки
	})

	// Извлекаем идентификатор пользователя из сессии
	userID := sess.UserID

	// Получаем данные пользователя из репозитория
	user, err := uh.UsersRepo.GetByID(ctx, userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить данные пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	// Формируем ответ
	response := user

	// Ответ с информацией о пользователе
	respondWithJSON(w, http.StatusOK, response)
}

// AdminRemoveUserType обрабатывает запрос на удаление пользователя по его идентификатору.
// @Summary Удаление пользователя
// @Description Метод удаляет пользователя из базы данных по заданному идентификатору.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param user_id path integer true "Идентификатор пользователя"
// @Success 204 {object} string "Пользователь успешно удалён"
// @Failure 400 {object} string "Ошибка: неправильно указанный идентификатор пользователя"
// @Failure 404 {object} string "Ошибка: пользователь не найден"
// @Failure 500 {object} string "Ошибка: произошла проблема при выполнении запроса"
// @Router /users/{user_id} [delete]
func (uh *UserHandler) AdminRemoveUserType(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Получаем ID пользователя из URL
	userID := r.PathValue("user_id")
	if userID == "" {
		handleError(w, r, fmt.Errorf("не указан идентификатор пользователя"), http.StatusBadRequest)
		return
	}
	// Формулируем SQL-запрос для удаления пользователя
	query := ` DELETE FROM users WHERE id = $1; `

	// Выполняем запрос к базе данных
	result, err := uh.UsersRepo.db.Exec(r.Context(), query, userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при удалении пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	// Проверяем количество строк, затронутых операцией удаления
	rowsAffected := result.RowsAffected()

	// Если ни одна строка не была удалена, значит такой пользователь не существует
	if rowsAffected == 0 {
		handleError(w, r, fmt.Errorf("пользователь с указанным идентификатором не найден: %v", err), http.StatusNotFound)
		return
	}

	// Возвращаем успешный ответ (HTTP 204 No Content)
	w.WriteHeader(http.StatusNoContent)
}

// AdminFetchUserTypes обрабатывает запрос на получение списка пользователей с типом USER.
// @Summary Получение списка пользователей
// @Description Возвращает список зарегистрированных пользователей, имеющих тип 'USER' из базы данных.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Success 200 {array} User "Массив объектов пользователей"
// @Failure 500 {object} string "Ошибка: внутренний сервер"
// @Router /users [get]
func (uh *UserHandler) AdminFetchUserTypes(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Запрос для выборки пользователей с типом USER
	query := ` SELECT id, first_name, last_name, username, email, created_at FROM users WHERE type = 'USER'; `

	// Выполняем запрос к базе данных
	rows, err := uh.UsersRepo.db.Query(r.Context(), query)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось выполнить запрос: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Инициализируем срез для хранения пользователей
	var users []User

	// Проходим по результатам запроса и добавляем каждого пользователя в срез
	for rows.Next() {
		var user User
		if err := rows.Scan(
			&user.ID,
			&user.FirstName,
			&user.LastName,
			&user.Username,
			&user.Email,
			&user.CreatedAt,
		); err != nil {
			handleError(w, r, fmt.Errorf("не удалось считать данные пользователя: %v", err), http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	// Проверяем наличие ошибок после сканирования всех строк
	if err := rows.Err(); err != nil {
		handleError(w, r, fmt.Errorf("ошибка при итерации по строкам: %v", err), http.StatusInternalServerError)
		return
	}

	// Кодируем ответ в JSON и отправляем клиентам
	if err := json.NewEncoder(w).Encode(users); err != nil {
		handleError(w, r, fmt.Errorf("не удалось закодировать ответ: %v", err), http.StatusInternalServerError)
		return
	}
}

// AdminListUserTypes обрабатывает запрос на получение статистики количества пользователей по типам.
// @Summary Получение статистики количества пользователей по типам
// @Description Возвращает статистику числа пользователей, сгруппированную по их типам, а также общее количество пользователей.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Success 200 {object} UserResponse "Объект статистики пользователей"
// @Failure 500 {object} string "Ошибка: внутренний сервер"
// @Router /users/stats [get]
func (uh *UserHandler) AdminListUserTypes(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Подготовленные структуры для хранения результатов
	var userCounts []UserCount
	var totalCount int64

	// SQL-запрос для подсчета количества пользователей по каждому типу
	query := ` SELECT type, COUNT(*) AS count FROM users GROUP BY type ORDER BY type ASC; `

	// Выполняем запрос к базе данных
	rows, err := uh.UsersRepo.db.Query(r.Context(), query)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось выполнить запрос: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Обрабатываем полученные результаты
	for rows.Next() {
		var userCount UserCount
		if err := rows.Scan(&userCount.Type, &userCount.Count); err != nil {
			handleError(w, r, fmt.Errorf("не удалось считать данные: %v", err), http.StatusInternalServerError)
			return
		}
		userCounts = append(userCounts, userCount)
	}

	// Завершаем проверку ошибок
	if err := rows.Err(); err != nil {
		handleError(w, r, fmt.Errorf("ошибка при считывании данных: %v", err), http.StatusInternalServerError)
		return
	}

	// Определяем общий счётчик пользователей
	err = uh.UsersRepo.db.QueryRow(r.Context(), "SELECT COUNT(*) FROM users").Scan(&totalCount)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить общее количество пользователей: %v", err), http.StatusInternalServerError)
		return
	}

	// Формирование конечного ответа
	response := UserResponse{
		UserCounts:     userCounts,
		TotalUserCount: TotalUserCount{Total: totalCount},
	}

	// Кодируем ответ в JSON и отправляем клиенту
	if err := json.NewEncoder(w).Encode(response); err != nil {
		handleError(w, r, fmt.Errorf("не удалось сформировать ответ: %v", err), http.StatusInternalServerError)
		return
	}
}

// HandleBlockUser обрабатывает запрос на блокировку пользователя.
// @Summary Блокировка пользователя
// @Description Позволяет администратору или другому пользователю заблокировать другого пользователя по его идентификатору.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param id path integer true "Идентификатор пользователя для блокировки"
// @Success 200 {object} Response "Пользователь успешно заблокирован"
// @Failure 400 {object} string "Ошибка: неправильный формат ID"
// @Failure 401 {object} string "Ошибка: требуется авторизация"
// @Failure 404 {object} string "Ошибка: пользователь не найден"
// @Failure 500 {object} string "Ошибка: произошел внутренний сбой"
// @Router /users/{id}/block [post]
func (uh *UserHandler) HandleBlockUser(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить сессию: %v", err), http.StatusUnauthorized)
		return
	}
	// Извлекаем идентификатор пользователя из пути
	userId := r.PathValue("id")
	userIdInt, err := strconv.Atoi(userId)
	if err != nil {
		handleError(w, r, fmt.Errorf("неправильный формат идентификатора пользователя: %v", err), http.StatusBadRequest)
		return
	}

	blockerID := sess.UserID
	blockedID := int64(userIdInt)

	// Проверяем существование пользователя, которого хотим заблокировать
	exists, err := uh.UsersRepo.UserExists(ctx, blockedID)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось проверить существование пользователя: %v", err), http.StatusInternalServerError)
		return
	}
	if !exists {
		handleError(w, r, fmt.Errorf("пользователь с указанным идентификатором не найден: %v", err), http.StatusNotFound)
		return
	}

	// Пытаемся заблокировать пользователя
	err = uh.UsersRepo.blockUser(blockerID, blockedID)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось заблокировать пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	response := "Пользователь успешно заблокирован"

	respondWithJSON(w, http.StatusOK, response)
}

// HandleCompanyInfo выводит информацию о компании на веб-странице.
// @Summary Показ информации о компании
// @Description Возвращает веб-страницу с информацией о компании, полученной из базы данных.
// @Tags         Пользователи
// @Prodocue html
// @Success 200 {html} string "HTML страница с информацией о компании"
// @Failure 500 {object} string "Ошибка: внутренний сервер"
// @Router /company-info [get]
func (uh *UserHandler) HandleCompanyInfo(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Получаем информацию о компании из базы данных
	company, err := uh.UsersRepo.getCompanyInfo()
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить информацию о компании: %v", err), http.StatusInternalServerError)
		return
	}

	// Загружаем и выполняем HTML-шаблоны
	tmpl := template.Must(template.ParseFiles("templates/layout.html", "templates/company_info.html"))

	// Рендерим страницу с данными о компании
	if err := tmpl.Execute(w, company); err != nil {
		handleError(w, r, fmt.Errorf("ошибка при рендеринге шаблона: %v", err), http.StatusInternalServerError)
		return
	}
}

// DeleteAccountHandler обрабатывает запросы на удаление учетной записи пользователя.
// @Summary Удаление учетной записи пользователя
// @Description Данный метод позволяет пользователю удалить свою учетную запись и связанные файлы.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Success 200 {object} Response "Успешное удаление учетной записи"
// @Failure 401 {object} map[string]interface{} "Ошибка: неавторизован"
// @Failure 500 {object} map[string]interface{} "Ошибка: не удалось удалить учетную запись или файлы"
// @Router /account/delete [delete]
func (uh *UserHandler) DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить сессию: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID

	// Удаление пользователя из базы данных
	if err = uh.UsersRepo.deleteUserByID(userID); err != nil {
		handleError(w, r, fmt.Errorf("не удалось удалить пользователя из базы данных: %v", err), http.StatusInternalServerError)
		return
	}

	// Удаление связанных файлов (если они существуют на файловой системе)
	if err = uh.UsersRepo.deleteUserFiles(userID); err != nil {
		handleError(w, r, fmt.Errorf("не удалось удалить файлы пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "Ваш аккаунт был успешно удален.",
	}

	respondWithJSON(w, http.StatusOK, response)
}

// DeleteAvatarHandler обрабатывает DELETE-запросы для удаления аватара пользователя.
// @Summary Удаление аватара пользователя
// @Description Данный метод позволяет пользователю удалить свой аватар из системы.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Success 200 {string} string "Аватар успешно удален"
// @Failure 401 {object} map[string]interface{} "Ошибка: неавторизован"
// @Failure 500 {object} map[string]interface{} "Ошибка: не удалось удалить аватар"
// @Router /avatar/delete [delete]
func (uh *UserHandler) DeleteAvatarHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить сессию: %v", err), http.StatusUnauthorized)
		return
	}

	// Извлекаем идентификатор пользователя из сессии
	userID := sess.UserID

	// Пытаемся удалить аватар пользователя
	if err := uh.deleteAvatar(userID); err != nil {
		handleError(w, r, fmt.Errorf("не удалось удалить аватар: %v", err), http.StatusInternalServerError)
		return
	}

	// Формируем успешный ответ
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"message": "Аватар успешно удален"}`))
}

// DeleteConfirmationHandler обрабатывает запросы на отображение результата удаления учетной записи пользователя.
// @Summary Подтверждение удаления аккаунта пользователя
// @Description Данный метод отображает результат удаления учетной записи пользователя в зависимости от статуса.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param status query string true "Статус операции удаления (success или error)"
// @Success 200 {object} Response "Успешное получение результата удаления"
// @Router /account/delete/confirmation [get]
func (uh UserHandler) DeleteConfirmationHandler(w http.ResponseWriter, r http.Request) {
	// Включаем CORS
	enableCors(&w)

	status := r.URL.Query().Get("status")
	var message string

	if status == "success" {
		message = "Ваш аккаунт был успешно удален."
	} else {
		message = "Произошла ошибка при удалении вашего аккаунта."
	}

	response := map[string]interface{}{
		"status":  "info",
		"message": message,
	}

	respondWithJSON(w, http.StatusOK, response)
}

// HandleDownloadExportDate обрабатывает запросы на скачивание JSON-файла с данными пользователя.
// @Summary Скачивание данных пользователя в формате JSON
// @Description Позволяет пользователю скачать свои личные данные в формате JSON. Сначала проверяется сессия пользователя, затем получаются данные, обновляется дата последнего экспорта и создается файл для скачивания.
// @Tags         Пользователи
// @Accept json
// @Produce application/json
// @Success 200 {file} string "Файл с данными пользователя в формате JSON"
// @Failure 401 {object} map[string]interface{} "Ошибка: неавторизован"
// @Failure 500 {object} map[string]interface{} "Ошибка: проблемы с сервером"
// @Router /user/download [get]
func (uh *UserHandler) HandleDownloadExportDate(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить сессию: %v", err), http.StatusUnauthorized)
		return
	}

	// Получаем идентификатор пользователя из сессии
	userID := sess.UserID

	// Получаем данные пользователя из репозитория
	user, err := uh.UsersRepo.getUserData(ctx, userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить данные пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	// Обновляем дату последнего экспорта данных пользователя
	if err := uh.UsersRepo.updateExportDate(ctx, userID); err != nil {
		handleError(w, r, fmt.Errorf("не удалось обновить дату экспорта: %v", err), http.StatusInternalServerError)
		return
	}

	// Генерируем временный файл с именем test.json
	filename := "test.json"

	// Сохраняем данные пользователя в JSON-файл
	if err := saveToJSON(user, filename); err != nil {
		handleError(w, r, fmt.Errorf("не удалось сохранить данные в файл: %v", err), http.StatusInternalServerError)
		return
	}

	// Настройка заголовков для скачивания файла
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	// Открываем файл и начинаем передачу клиенту
	file, err := os.Open(filename)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось открыть файл: %v", err), http.StatusInternalServerError)
		return
	}
	// Используем defer для автоматического закрытия файла после выхода из функции
	defer func() {
		// Пробуем закрыть файл и проверяем возвращаемую ошибку
		if err := file.Close(); err != nil {
			handleError(w, r, fmt.Errorf("ошибка при закрытии файла: %v", err), http.StatusBadRequest)
			return
		}
	}()

	// Передача файла клиенту
	if _, err := io.Copy(w, file); err != nil {
		handleError(w, r, fmt.Errorf("не удалось передать файл клиенту: %v", err), http.StatusInternalServerError)
		return
	}

	// Удаляем временный файл после загрузки
	if err := os.Remove(filename); err != nil {
		handleError(w, r, fmt.Errorf("не удалось удалить временный файл: %v", err), http.StatusInternalServerError)
		return
	}
}

// HandleExportDate обрабатывает запросы на экспорт данных пользователя.
// @Summary Экспорт данных пользователя
// @Description Предоставляет пользователю возможность получить свои персональные данные, такие как email и дату последнего экспорта.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Success 200 {object} User "Данные пользователя успешно получены"
// @Failure 401 {object} map[string]string "Ошибка: неавторизован"
// @Failure 500 {object} map[string]string "Ошибка: внутренние проблемы с сервером"
// @Router /user/export [get]
func (uh *UserHandler) HandleExportDate(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить сессию: %v", err), http.StatusUnauthorized)
		return
	}

	// Получаем идентификатор пользователя из сессии
	userID := sess.UserID

	// Получаем электронную почту пользователя
	email, err := uh.UsersRepo.getEmailByUserID(ctx, userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить email пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	// Получаем дату последнего экспорта данных
	exportDate, err := uh.UsersRepo.getExportDate(ctx, userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить дату последнего экспорта: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"Email":      email,
		"ExportDate": exportDate,
	}

	respondWithJSON(w, http.StatusOK, response)
}

// HandleGetAvatar обрабатывает запросы на получение URL аватара пользователя.
// @Summary Получение URL аватара пользователя
// @Description Возвращает URL аватара пользователя по его идентификатору.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Success 200 {object} User "Адрес аватара пользователя"
// @Failure 401 {object} map[string]string "Ошибка: неавторизован"
// @Failure 500 {object} map[string]string "Ошибка: возникли проблемы с сервером"
// @Router /user/avatar [get]
func (uh *UserHandler) HandleGetAvatar(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось получить сессию: %v", err), http.StatusUnauthorized)
		return
	}

	// Получаем идентификатор пользователя из сессии
	userID := sess.UserID

	// Выполняем запрос к базе данных для получения URL аватара
	var avatarURL string
	row := uh.UsersRepo.db.QueryRow(ctx, "SELECT avatar_url FROM users WHERE id = $1", userID)
	err = row.Scan(&avatarURL)
	if err != nil && err != sql.ErrNoRows {
		handleError(w, r, fmt.Errorf("не удалось получить URL аватара: %v", err), http.StatusInternalServerError)
		return
	}

	// Если аватар не установлен, вернем ошибку 404
	if avatarURL == "" {
		handleError(w, r, fmt.Errorf("аватар не найден: %v", err), http.StatusNotFound)
		return
	}

	response := struct {
		StatusCode int    `json:"statusCode"`
		Body       string `json:"body"`
	}{
		StatusCode: http.StatusOK,
		Body:       avatarURL,
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		handleError(w, r, fmt.Errorf("ошибка: %v", err), http.StatusInternalServerError)
		return
	}
}

// HandleGetBots обрабатывает запрос на получение всех пользователей с типом "BOT".
// @Summary Получение списка ботов
// @Description Возвращает список всех пользователей, у которых тип равен BOT.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Success 200 {array} User "Список пользователей с типом BOT"
// @Failure 500 {object} map[string]string "Ошибка: проблема с базой данных"
// @Router /bots [get]
func (uh *UserHandler) HandleGetBots(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Выполняем запрос к базе данных для получения всех ботов
	rows, err := uh.UsersRepo.db.Query(ctx, ` SELECT id, version, blacklisted, sex, followers_count, verified, no_ads, can_upload_shot, pro, type, first_name, last_name, middle_name, username, password_hash, bdate, phone, email, html_url, avatar_url, bio, location, created_at, updated_at FROM users WHERE type = $1`,
		"BOT",
	)
	if err != nil {
		handleError(w, r, fmt.Errorf("не удалось выполнить запрос: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Создаем срез для хранения результатов
	var users []User

	// Складываем данные из результата запроса в объекты User
	for rows.Next() {
		var user User
		if err := rows.Scan(
			&user.ID, &user.Version, &user.Blacklisted, &user.Sex, &user.FollowersCount,
			&user.Verified, &user.NoAds, &user.CanUploadShot, &user.Pro, &user.Type,
			&user.FirstName, &user.LastName, &user.MiddleName, &user.Username,
			&user.PasswordHash, &user.Bdate, &user.Phone, &user.Email, &user.HTMLURL,
			&user.AvatarURL, &user.Bio, &user.Location, &user.CreatedAt, &user.UpdatedAt,
		); err != nil {
			handleError(w, r, fmt.Errorf("не удалось просканировать данные: %v", err), http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	// Проверяем ошибки после итерации
	if err := rows.Err(); err != nil {
		handleError(w, r, fmt.Errorf("не удалось завершить обработку: %v", err), http.StatusInternalServerError)
		return
	}

	// Формируем ответ
	response := users
	respondWithJSON(w, http.StatusOK, response)
}

// HandleGettingOrderExecutors обрабатывает запрос на получение исполнителей заказов.
// @Summary Получение исполнителей заказов
// @Description Возвращает список пользователей-исполнителей заказов с возможностью фильтрации по различным параметрам.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param limit query integer false "Количество элементов на странице (опционально)"
// @Param offset query integer false "Смещение для пагинации (опционально)"
// @Param pro query boolean false "Фильтрация по наличию Pro-аккаунта (true|false)"
// @Param online query boolean false "Фильтрация по онлайн-статусу (true|false)"
// @Param categories query string false "Категории пользователей (через запятую)"
// @Param location query string false "Местоположение исполнителя"
// @Success 200 {object} User "Список исполнителей заказов"
// @Failure 400 {object} ErrorResponse "Некорректные параметры запроса"
// @Failure 500 {object} ErrorResponse "Проблемы с сервером"
// @Router /order/executors [get]
func (uh *UserHandler) HandleGettingOrderExecutors(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Проверяем метод запроса
	if r.Method != http.MethodGet {
		handleError(w, r, fmt.Errorf("метод не поддерживается"), http.StatusMethodNotAllowed)
		return
	}

	// Получаем параметры из запроса
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	proStr := r.URL.Query().Get("pro")
	onlineStr := r.URL.Query().Get("online")
	categories := r.URL.Query().Get("categories")
	location := r.URL.Query().Get("location")

	// По умолчанию значения для лимитов
	limit, offset := 3, 0
	var err error

	// Преобразуем limit и offset в целые числа
	if limitStr != "" {
		limit, err = strconv.Atoi(limitStr)
		if err != nil {
			handleError(w, r, fmt.Errorf("некорректный параметр limit: %v", err), http.StatusBadRequest)
			return
		}
	}

	if offsetStr != "" {
		offset, err = strconv.Atoi(offsetStr)
		if err != nil {
			handleError(w, r, fmt.Errorf("некорректный параметр offset: %v", err), http.StatusBadRequest)
			return
		}
	}

	// Получаем список пользователей с фильтрацией и пагинацией
	users, count, err := uh.UsersRepo.fetchUsers(limit, offset, proStr, onlineStr, categories, location)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при извлечении пользователей: %v", err), http.StatusInternalServerError)
		return
	}
	// Формирование ответа с массивом пользователей и общим количеством
	response := struct {
		StatusCode int    `json:"statusCode"`
		Body       []User `json:"body"`
		TotalCount int    `json:"totalCount"`
	}{
		StatusCode: http.StatusOK,
		Body:       users,
		TotalCount: count,
	}

	w.WriteHeader(http.StatusOK)
	// Кодируем данные в JSON-формат и проверяем ошибку
	if err := json.NewEncoder(w).Encode(response); err != nil {
		handleError(w, r, fmt.Errorf("ошибка: %v", err), http.StatusInternalServerError)
		return
	}
}

// HandleGetUserByQuery обрабатывает запросы для получения информации о пользователе по ID из query-параметра.
// @Summary Получение информации о пользователе по query-параметру id
// @Description Возвращает полную информацию о пользователе по переданному в query параметре id.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param id query string true "ID пользователя"
// @Success 200 {object} User "Информация о пользователе"
// @Failure 400 {string} string "Некорректный или отсутствующий ID"
// @Failure 404 {string} string "Пользователь не найден"
// @Failure 500 {string} string "Внутренняя ошибка сервера"
// @Router /user [get]
func (uh *UserHandler) HandleGetUserByQuery(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем значение query-параметра "id"
	userIDStr := r.PathValue("id")
	if userIDStr == "" {
		handleError(w, r, fmt.Errorf("отсутствует обязательный параметр id"), http.StatusBadRequest)
		return
	}

	// Преобразовываем строку в целое число
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		handleError(w, r, fmt.Errorf("неверный формат id: %v", err), http.StatusBadRequest)
		return
	}

	// Получаем информацию о пользователе из репозитория
	user, err := uh.UsersRepo.GetByID(ctx, userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при поиске пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	// Проверяем, существует ли пользователь
	if user == nil {
		handleError(w, r, fmt.Errorf("пользователь с указанным id не найден: %v", err), http.StatusNotFound)
		return
	}

	// Готовим ответ
	response := user

	respondWithJSON(w, http.StatusOK, response)
}

// @Summary Получить категории пользователя
// @Description Метод возвращает список категорий, связанных с указанным пользователем.
// @Tags Пользователи
// @Accept json
// @Produce json
// @Param id path string true "ID пользователя"
// @Success 200 {object} CategoryResponse "Успешное получение списка категорий"
// @Failure 400 {string} string "Ошибка формата входных данных"
// @Failure 500 {string} string "Ошибка сервера"
// @Router /users/{id}/categories [GET]
func (uh *UserHandler) GetUserCategories(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	if r.Method != http.MethodGet {
		handleError(w, r, fmt.Errorf("метод запроса некорректен"), http.StatusMethodNotAllowed)
		return
	}

	// Получаем ID пользователя из URL
	userId := r.PathValue("id") // Предполагается использование библиотеки Chi

	// Преобразуем ID пользователя из строки в int
	userIdInt, err := strconv.Atoi(userId)
	if err != nil || userIdInt <= 0 {
		handleError(w, r, fmt.Errorf("некорректный идентификатор пользователя: %v", err), http.StatusBadRequest)
		return
	}

	// Используем метод репозитория для получения категорий
	categories, err := uh.UsersRepo.GetUserCategories(userIdInt)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка базы данных: %v", err), http.StatusInternalServerError)
		return
	}

	// Формируем ответ
	response := categories

	// Отправляем JSON-ответ с результатом
	respondWithJSON(w, http.StatusOK, response)
}

// @Summary Обработчик GET-запросов для профиля пользователя
// @Description Запрашивает профиль текущего авторизованного пользователя и рендерит страницу профиля.
// @Tags Пользователи
// @Accept html
// @Produce html
// @Param Authorization header string true "Авторизационный токен JWT"
// @Success 200 {html} string "HTML-код страницы профиля пользователя"
// @Failure 401 {string} string "Ошибка аутентификации"
// @Failure 500 {string} string "Ошибка загрузки данных пользователя"
// @Router /profile [GET]
// @Security ApiKeyAuth
func (uh *UserHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаём новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID

	// Загружаем информацию о пользователе
	var user User
	if err := uh.UsersRepo.db.QueryRow(ctx, `
        SELECT id, ver, blacklisted, sex, followers_count, verified, no_ads, can_upload_shot, pro, type, first_name, last_name, middle_name, username, bdate, phone, email, avatar_url, bio, location, created_at, updated_at, links 
        FROM users 
        WHERE id = $1
    `, userID).Scan(
		&user.ID, &user.Version, &user.Blacklisted, &user.Sex, &user.FollowersCount, &user.Verified, &user.NoAds, &user.CanUploadShot, &user.Pro, &user.Type, &user.FirstName, &user.LastName, &user.MiddleName, &user.Username, &user.Bdate, &user.Phone, &user.Email, &user.AvatarURL, &user.Bio, &user.Location, &user.CreatedAt, &user.UpdatedAt, &user.Links,
	); err != nil {
		handleError(w, r, fmt.Errorf("ошибка загрузки данных пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	// Рендерим шаблоны
	templates.NewTemplates(
		ctx,
		w,
		"../website/base.html",
		"../website/social_profiles.html",
		"root",
		map[string]interface{}{
			"user": user,
		},
	)
}

// @Summary Обработчик POST-запросов для сохранения социальных ссылок пользователя
// @Description Сохраняет социальные ссылки пользователя (VK, Telegram, WhatsApp, Web, Twitter) и сохраняет их в базу данных.
// @Tags Пользователи
// @Accept json
// @Produce json
// @Param Authorization header string true "Авторизационный токен JWT"
// @Param vk formData string false "Ссылка VK"
// @Param telegram formData string false "Ссылка Telegram"
// @Param whatsapp formData string false "Ссылка WhatsApp"
// @Param web formData string false "Ссылка веб-сайта"
// @Param twitter formData string false "Ссылка Twitter"
// @Success 204 {string} string ""
// @Failure 401 {string} string "Ошибка аутентификации"
// @Failure 500 {string} string "Ошибка сохранения данных"
// @Router /update-social-links [POST]
// @Security ApiKeyAuth
func (uh *UserHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	// Ограничение размера тела запроса
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // Ограничение в 1MB

	userID := sess.UserID

	// Извлечение ссылок из формы
	vk := r.FormValue("vk")
	telegram := r.FormValue("telegram")
	whatsapp := r.FormValue("whatsapp")
	web := r.FormValue("web")         // Дополнительные поля
	twitter := r.FormValue("twitter") // Дополнительные поля

	// Обновляем ссылки пользователя
	if err := uh.UsersRepo.updateUserLinks(ctx, userID, vk, telegram, whatsapp, web, twitter); err != nil {
		handleError(w, r, fmt.Errorf("ошибка сохранения данных: %v", err), http.StatusInternalServerError)
		return
	}

	// Отправляем пустой успех-ответ 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

// @Summary Отмечает сообщение как прочитанное
// @Description Обработчик принимает ID сообщения и помечает его как прочитанное в базе данных.
// @Tags         Пользователи
// @Accept json
// @Produce plain
// @Param request body MessageReq true "Объект запроса с ID сообщения"
// @Success 204 {string} string ""
// @Failure 400 {string} string "Неверный формат запроса"
// @Failure 500 {string} string "Ошибка баз данных"
// @Router /mark-message-as-read [PUT]
func (uh *UserHandler) MarkMessagesAsRead(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	var request MessageReq

	// Декодируем тело запроса в структуру MessageRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		handleError(w, r, fmt.Errorf("неверный формат запроса: %v", err), http.StatusBadRequest)
		return
	}

	// Убедимся, что ID сообщения валиден
	messageID := request.ID

	if messageID <= 0 {
		handleError(w, r, fmt.Errorf("недопустимый ID сообщения"), http.StatusBadRequest)
		return
	}

	// Выполняем SQL запрос для отметки сообщения как прочитанного
	_, err := uh.UsersRepo.db.Exec(context.Background(), `UPDATE messages SET is_read = TRUE WHERE id = $1`, messageID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка базы данных: %v", err), http.StatusInternalServerError)
		return
	}

	// Возвращаем статус 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

// @Summary Получение архивированных сообщений пользователя
// @Description Возвращает список всех архивированных сообщений конкретного пользователя.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param Authorization header string true "Авторизационный токен JWT"
// @Success 200 {array} Message "Список архивированных сообщений"
// @Failure 401 {string} string "Ошибка аутентификации"
// @Failure 500 {string} string "Ошибка загрузки архивированных сообщений"
// @Router /messages-archive [GET]
// @Security ApiKeyAuth
func (uh *UserHandler) GetArchivedMessages(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID

	// Получаем архивированные сообщения пользователя
	messages, err := uh.UsersRepo.GetArchiveMessages(userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка загрузки архивированных сообщений: %v", err), http.StatusInternalServerError)
		return
	}

	// Формируем ответ
	response := messages

	// Отправляем JSON-ответ с результатом
	respondWithJSON(w, http.StatusOK, response)
}

// @Summary Получение новых сообщений пользователя
// @Description Возвращает список последних непрочитанных сообщений для указанного пользователя.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param Authorization header string true "Авторизационный токен JWT"
// @Success 200 {array} Message "Массив объектов сообщений"
// @Failure 401 {string} string "Ошибка аутентификации"
// @Failure 500 {string} string "Ошибка загрузки сообщений"
// @Router /new-messages [GET]
// @Security ApiKeyAuth
func (uh *UserHandler) GetInboxMessages(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID

	// Получаем новые сообщения пользователя
	messages, err := uh.UsersRepo.GetNewMessages(userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка загрузки сообщений: %v", err), http.StatusInternalServerError)
		return
	}

	// Формирование ответа
	response := messages

	// Отправляем JSON-ответ с результатами
	respondWithJSON(w, http.StatusOK, response)
}

// @Summary Обработчик запросов для управления заказами
// @Description Данный обработчик предназначен для обработки запросов на получение существующих заказов (GET) и создание новых заказов (POST).
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param Authorization header string true "Авторизационный токен JWT"
// @Param order body Order false "Заказ для создания (только для POST)"
// @Success 200 {array} Order "Список заказов (для GET)"
// @Success 201 {object} Order "Созданный заказ (для POST)"
// @Failure 401 {string} string "Ошибка аутентификации"
// @Failure 500 {string} string "Ошибка обработки запроса"
// @Router /orders [GET]
// @Security ApiKeyAuth
func (uh *UserHandler) OrdersHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Обрабатываем метод запроса
	switch r.Method {
	case http.MethodGet:
		// Пример получения заказов (вы можете заменить это на реальные данные)
		orders := []Order{
			{ID: 1, Item: "Товар 1", Amount: 2},
			{ID: 2, Item: "Товар 2", Amount: 5},
		}

		// Возвращаем данные в формате JSON
		if err := json.NewEncoder(w).Encode(orders); err != nil {
			handleError(w, r, fmt.Errorf("ошибка сериализации данных: %v", err), http.StatusInternalServerError)
			return
		}

	case http.MethodPost:
		var newOrder Order
		// Декодируем JSON из тела запроса
		if err := json.NewDecoder(r.Body).Decode(&newOrder); err != nil {
			handleError(w, r, fmt.Errorf("ошибка декодирования данных: %v", err), http.StatusBadRequest)
			return
		}

		// Здесь должна происходить реальная логика добавления заказа в систему
		// Например, запись в базу данных или другой сервис

		// Возвращаем подтверждение создания заказа
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(newOrder); err != nil {
			handleError(w, r, fmt.Errorf("ошибка сериализации данных: %v", err), http.StatusInternalServerError)
			return
		}

	default:
		handleError(w, r, fmt.Errorf("неподдерживаемый метод запроса"), http.StatusMethodNotAllowed)
		return
	}
}

// @Summary Изменение пароля пользователя
// @Description Обработчик меняет пароль пользователя, предварительно проверяя старый пароль и совпадение нового пароля с повтором.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param Authorization header string true "Авторизационный токен JWT"
// @Param password_request body PasswordRequest true "Параметры запроса для смены пароля"
// @Success 200 {object} Response "Информация о результате изменения пароля"
// @Failure 401 {string} string "Ошибка аутентификации"
// @Failure 400 {string} string "Новый пароль не задан или не совпал с подтверждением"
// @Failure 500 {string} string "Ошибка изменения пароля"
// @Router /change-password [POST]
// @Security ApiKeyAuth
func (uh *UserHandler) PasswordHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	// Проверяем метод запроса
	if r.Method != http.MethodPost {
		handleError(w, r, fmt.Errorf("метод не разрешён: %v", err), http.StatusMethodNotAllowed)
		return
	}

	// Декодируем JSON из тела запроса в структуру PasswordRequest
	var request PasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		handleError(w, r, fmt.Errorf("ошибка декодирования данных: %v", err), http.StatusBadRequest)
		return
	}

	// Проверяем, что новый пароль задан и совпадает с подтверждением
	if request.NewPassword1 == "" || request.NewPassword1 != request.NewPassword2 {
		handleError(w, r, fmt.Errorf("новый пароль не задан или не совпал с подтверждением: %v", err), http.StatusBadRequest)
		return
	}

	// Проверяем старый пароль
	user, err := uh.UsersRepo.checkPasswordByUserID(ctx, sess.UserID, request.OldPassword)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка проверки старого пароля: %v", err), http.StatusInternalServerError)
		return
	}

	// Обновляем пароль пользователя
	// if err := uh.UsersRepo.UpdatePassword(strconv.FormatInt(user.ID, 10), request.NewPassword1); err != nil {
	// 	handleError(w, r, fmt.Errorf("ошибка обновления пароля: %v", err), http.StatusInternalServerError)
	// 	return
	// }

	if err := uh.UsersRepo.UpdateThePasswordInTheSettings(ctx, user.ID, request.NewPassword1); err != nil {
		handleError(w, r, fmt.Errorf("ошибка обновления пароля: %v", err), http.StatusInternalServerError)
		return
	}

	// Инкрементируем версию пользователя
	user.Version++

	// Удаляем старые сессии
	if err := uh.Sessions.DestroyAll(ctx, w, user); err != nil {
		handleError(w, r, fmt.Errorf("ошибка удаления старых сессий: %v", err), http.StatusInternalServerError)
		return
	}

	// Создаем новую сессию
	if err := uh.Sessions.Create(ctx, w, user, r); err != nil {
		handleError(w, r, fmt.Errorf("ошибка создания новой сессии: %v", err), http.StatusInternalServerError)
		return
	}

	// Готовим ответ
	response := map[string]string{
		"message": "Пароль успешно изменен",
	}

	// Возвращаем успешный ответ
	respondWithJSON(w, http.StatusOK, response)
}

// @Summary Страница подтверждения сброса пароля
// @Description Отображение HTML-шаблона страницы подтверждения сброса пароля.
// @Tags         Пользователи
// @Accept html
// @Produce html
// @Success 200 {html} string "Шаблон страницы подтверждения сброса пароля"
// @Failure 500 {string} string "Ошибка рендеринга страницы"
// @Router /password-reset-confirmation [GET]
func (uh *UserHandler) ConfirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Загружаем шаблон страницы подтверждения
	t, err := template.ParseFiles("../website/password_reset_confirmation.html")
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка загрузки шаблона страницы: %v", err), http.StatusInternalServerError)
		return
	}

	// Отображаем шаблон
	if err := t.Execute(w, nil); err != nil {
		handleError(w, r, fmt.Errorf("ошибка рендеринга страницы: %v", err), http.StatusInternalServerError)
		return
	}
}

// @Summary Страница запроса сброса пароля
// @Description Представляет форму для запроса сброса пароля, куда пользователь вводит свою электронную почту.
// @Tags         Пользователи
// @Accept html
// @Produce html
// @Success 200 {html} string "Шаблон страницы запроса сброса пароля"
// @Failure 500 {string} string "Ошибка рендеринга страницы"
// @Router /password-reset-request [GET]
func (uh *UserHandler) PasswordResetPage(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Парсим HTML-шаблон страницы
	t, err := template.ParseFiles("../website/password_reset.html")
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка загрузки шаблона страницы: %v", err), http.StatusInternalServerError)
		return
	}

	// Отображаем шаблон страницы
	if err := t.Execute(w, nil); err != nil {
		handleError(w, r, fmt.Errorf("ошибка рендеринга страницы: %v", err), http.StatusInternalServerError)
		return
	}
}

// @Summary Обработчик GET-запросов для получения информации о профиле пользователя
// @Description Предоставляет доступ к личной информации зарегистрированного пользователя (имя, фамилия, местоположение и другие детали).
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param Authorization header string true "Авторизационный токен JWT"
// @Success 200 {object} User "Пользовательская информация"
// @Failure 401 {string} string "Ошибка аутентификации"
// @Failure 500 {string} string "Ошибка получения данных пользователя"
// @Router /profile [GET]
// @Security ApiKeyAuth
func (uh *UserHandler) ProfileGetHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID

	// Получаем пользователя по его ID
	u, err := uh.UsersRepo.GetByID(ctx, userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка получения данных пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	// Подготавливаем профиль для возврата
	response := User{
		FirstName:  u.FirstName,
		LastName:   u.LastName,
		MiddleName: u.MiddleName,
		Location:   u.Location,
		Bio:        u.Bio,
		NoAds:      u.NoAds,
	}

	// Устанавливаем правильный заголовок и возвращаем JSON-ответ
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		handleError(w, r, fmt.Errorf("ошибка сериализации данных: %v", err), http.StatusInternalServerError)
		return
	}
}

// @Summary Обработчик POST-запросов для обновления профиля пользователя
// @Description Обновляет личные данные пользователя, такие как имя, фамилию, биографию и настройки.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param Authorization header string true "Авторизационный токен JWT"
// @Param profile_update body User true "Новые данные профиля"
// @Success 204 {string} string ""
// @Failure 401 {string} string "Ошибка аутентификации"
// @Failure 400 {string} string "Неполные или некорректные данные"
// @Failure 500 {string} string "Ошибка обновления профиля"
// @Router /profile/update [POST]
// @Security ApiKeyAuth
func (uh *UserHandler) ProfilePostHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID // Предположительно userID - это int64 из сессии

	var update User
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		handleError(w, r, fmt.Errorf("ошибка десериализации данных: %v", err), http.StatusBadRequest)
		return
	}

	// Освобождаем ресурсы после завершения работы с телом запроса
	defer func() {
		if err := r.Body.Close(); err != nil {
			handleError(w, r, fmt.Errorf("ошибка закрытия тела запроса: %v", err), http.StatusInternalServerError)
			return
		}
	}()

	// Валидация обязательных полей
	if update.FirstName == nil || update.LastName == nil {
		handleError(w, r, fmt.Errorf("обязательно заполнить имя и фамилию: %v", err), http.StatusBadRequest)
		return
	}

	// Обновляем профиль пользователя
	if err := uh.updateProfileData(userID, update); err != nil {
		handleError(w, r, fmt.Errorf("ошибка обновления профиля: %v", err), http.StatusInternalServerError)
		return
	}

	// Ответ успешен, возвращаем 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

// @Summary Получение информации о профиле пользователя по имени
// @Description Обработчик получает информацию о профиле пользователя на основании имени пользователя (username).
// Если пользователь залогинен, дополнительно проверяются права доступа и выдается персонализированная информация.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param username path string true "Имя пользователя"
// @Param Authorization header string false "Авторизационный токен JWT (необязателен)"
// @Success 200 {object} User "Пользователи"
// @Failure 404 {string} string "Пользователь не найден"
// @Failure 500 {string} string "Ошибка обработки запроса"
// @Router /profile/{username} [GET]
func (uh *UserHandler) ProfileUsername(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем имя пользователя из URL
	username := r.PathValue("username")

	// Получаем пользователя по имени
	getUser, err := uh.UsersRepo.GetByName(ctx, username)
	if err != nil || getUser == nil {
		handleError(w, r, fmt.Errorf("пользователь не найден: %v", err), http.StatusNotFound)
		return
	}

	// Получаем ID пользователя
	IDX := getUser.ID

	// Ищем информацию о текущей сессии пользователя
	sessionCookie, _ := r.Cookie("session_id")
	currentUserId := int64(-1) // Значение по умолчанию, если cookie нет

	// Проверяем наличие cookie с сессией
	if sessionCookie != nil {
		sess := &session.Session{}
		row := uh.UsersRepo.db.QueryRow(ctx, `SELECT user_id FROM sessions WHERE id = $1`, sessionCookie.Value)
		err = row.Scan(&sess.UserID)

		if err == pgx.ErrNoRows {
			// Если сессия не найдена, удаляем cookie
			http.SetCookie(w, &http.Cookie{
				Name:   "session_id",
				Value:  "",
				Path:   "/",
				MaxAge: -1, // Удаление cookie
			})
		} else if err != nil {
			handleError(w, r, fmt.Errorf("ошибка обработки сессии: %v", err), http.StatusInternalServerError)
			return
		} else {
			// Устанавливаем ID текущего пользователя из сессии
			currentUserId = sess.UserID
		}
	}

	// Получаем данные профиля пользователя и связанные с ним данные
	response, err := uh.UsersRepo.getUserProfileData(IDX, currentUserId)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка получения данных профиля: %v", err), http.StatusInternalServerError)
		return
	}

	// Устанавливаем статус ответа и кодируем объект в JSON
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		handleError(w, r, fmt.Errorf("ошибка сериализации данных: %v", err), http.StatusInternalServerError)
		return
	}
}

// @Summary Обработчик запроса на получение профиля пользователя
// @Description Возвращает полный профиль пользователя, включая новые сообщения и статистику подписок.
// Принимает ID пользователя в URL и проверяет текущий сеанс пользователя.
// Возвращает либо JSON с полным профилем, либо ошибку в формате JSON.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param id path string true "Идентификатор пользователя"
// @Param Authorization header string true "Авторизационный токен JWT"
// @Success 200 {object} User "Полный профиль пользователя"
// @Failure 401 {string} string "Ошибка аутентификации"
// @Failure 500 {string} string "Ошибка получения данных профиля"
// @Router /profile/{id} [GET]
// @Security ApiKeyAuth
func (uh *UserHandler) Profile(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	// Получаем ID пользователя из URL
	userIdStr := r.PathValue("id")

	// Преобразуем ID пользователя из строки в int
	userIdInt, err := strconv.Atoi(userIdStr)
	if err != nil {
		handleError(w, r, fmt.Errorf("неправильный формат ID пользователя: %v", err), http.StatusBadRequest)
		return
	}

	// Получаем ID текущего пользователя из сессии
	currentUserId := sess.UserID

	// Получаем профиль пользователя
	profile, subscriptionsCount, err := uh.UsersRepo.GetUserProfile(int64(userIdInt), currentUserId)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка получения профиля пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	// Получаем новые сообщения для текущего пользователя
	messages, err := uh.UsersRepo.GetNewMessages(currentUserId)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка получения новых сообщений: %v", err), http.StatusInternalServerError)
		return
	}

	// Проверяем, заблокировал ли текущий пользователь запрашиваемого пользователя
	isBlocked, err := uh.UsersRepo.isBlocked(currentUserId, int64(userIdInt))
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка проверки блокировки: %v", err), http.StatusInternalServerError)
		return
	}

	// Проверяем, подписан ли текущий пользователь на запрашиваемого пользователя
	isFollowing, err := uh.UsersRepo.isFollowing(currentUserId, int64(userIdInt))
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка проверки подписки: %v", err), http.StatusInternalServerError)
		return
	}

	// Формируем успешный ответ с данными профиля пользователя
	response := struct {
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
	}

	// Возвращаем JSON-ответ с данными
	respondWithJSON(w, http.StatusOK, response)
}

// @Summary Экспорт данных пользователя
// @Description Осуществляет сбор персональных данных пользователя и отправляет их на указанный email в формате архива.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param Authorization header string true "Авторизационный токен JWT"
// @Success 200 {object} Response "Информация о завершении экспорта"
// @Failure 401 {string} string "Ошибка аутентификации"
// @Failure 500 {string} string "Ошибка сбора или отправки данных"
// @Router /export-data [POST]
// @Security ApiKeyAuth
func (uh *UserHandler) RequestExportHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID
	email, err := uh.UsersRepo.getEmailByUserID(ctx, userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка получения email пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	// Собираем JSON с данными профиля
	profileData := map[string]interface{}{
		"email": email,
	}

	jsondata, err := json.Marshal(profileData)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка преобразования данных в JSON: %v", err), http.StatusInternalServerError)
		return
	}

	// Генерируем временный ZIP-файл
	zipFileName := "data.zip"
	zipFile, err := os.Create(zipFileName)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка создания временного ZIP-файла: %v", err), http.StatusInternalServerError)
		return
	}
	defer func() {
		if err := os.Remove(zipFileName); err != nil {
			handleError(w, r, fmt.Errorf("ошибка удаления временного ZIP-файла: %v", err), http.StatusInternalServerError)
			return
		}
	}()

	zipWriter := zip.NewWriter(zipFile)
	defer func() {
		if err := zipWriter.Close(); err != nil {
			handleError(w, r, fmt.Errorf("ошибка закрытия ZIP-писателя: %v", err), http.StatusInternalServerError)
			return
		}
	}()

	// Добавляем JSON-файл в ZIP
	jsonFileName := "email.json"
	jsonFile, err := zipWriter.Create(jsonFileName)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка создания JSON-файла внутри ZIP: %v", err), http.StatusInternalServerError)
		return
	}
	if _, err := jsonFile.Write(jsondata); err != nil {
		handleError(w, r, fmt.Errorf("ошибка записи данных в ZIP-файл: %v", err), http.StatusInternalServerError)
		return
	}

	// Отправляем ZIP-файл на email пользователя
	if err := sendEmail(email, zipFileName); err != nil {
		handleError(w, r, fmt.Errorf("ошибка отправки ZIP-файла на email: %v", err), http.StatusInternalServerError)
		return
	}

	// Готовим успешный ответ
	response := map[string]string{
		"message": "Запрос на экспорт данных отправлен на ваш email.",
	}

	respondWithJSON(w, http.StatusOK, response)
}

// @Summary Сброс пароля пользователя
// @Description Позволяет сбросить пароль пользователя, используя валидный токен восстановления.
// Токен передаётся вместе с новым паролем и адресом электронной почты.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param request body ResetPasswordRequest true "Запрос на восстановление пароля"
// @Success 200 {string} string "Пароль успешно обновлён"
// @Failure 400 {string} string "Неверный формат запроса"
// @Failure 401 {string} string "Истёкший или недействительный токен"
// @Failure 500 {string} string "Ошибка обновления пароля"
// @Router /reset-password [POST]
func (uh *UserHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	var req ResetPasswordRequest
	// Читаем тело запроса
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		handleError(w, r, fmt.Errorf("неверный формат запроса: %v", err), http.StatusBadRequest)
		return
	}

	// Извлечение значений из структуры
	token := req.Token
	email := req.Email
	newPassword := req.NewPassword

	claims := &jwt.StandardClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil || claims.ExpiresAt < time.Now().Unix() || claims.Subject != email {
		handleError(w, r, fmt.Errorf("истёкший или недействительный токен: %v", err), http.StatusUnauthorized)
		return
	}

	err = uh.UsersRepo.UpdatePassword(email, newPassword)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка обновления пароля: %v", err), http.StatusInternalServerError)
		return
	}

	// Возвращаем успешный ответ (можно вернуть JSON с сообщением или статус)
	w.WriteHeader(http.StatusOK)
	// Пишем ответ и проверяем на наличие ошибки
	if _, err := w.Write([]byte("Пароль успешно обновлён")); err != nil {
		handleError(w, r, fmt.Errorf("ошибка записи ответа: %v", err), http.StatusInternalServerError)
		return
	}
}

// @Summary Страница сброса пароля
// @Description Эта страница отображается пользователю после успешной проверки токена восстановления пароля.
// Она позволяет восстановить пароль, предоставляя необходимые поля ввода.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param token query string true "Токен восстановления пароля"
// @Success 200 {object} ResetPasswordResponse "Данные для страницы изменения пароля"
// @Failure 400 {string} string "Некорректный токен"
// @Failure 500 {string} string "Ошибка обработки запроса"
// @Router /reset-password-page [GET]
func (uh *UserHandler) ResetPasswordPage(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	token := r.URL.Query().Get("token")

	if token == "" {
		handleError(w, r, fmt.Errorf("токен не найден"), http.StatusBadRequest)
		return
	}

	claims := &jwt.StandardClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil || parsedToken == nil {
		handleError(w, r, fmt.Errorf("недействительный токен: %v", err), http.StatusUnauthorized)
		return
	}

	if claims.ExpiresAt < time.Now().Unix() {
		handleError(w, r, fmt.Errorf("истёк срок действия токена: %v", err), http.StatusUnauthorized)
		return
	}

	response := ResetPasswordResponse{
		Token: token,
		Email: claims.Subject,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		handleError(w, r, fmt.Errorf("ошибка сериализации ответа: %v", err), http.StatusInternalServerError)
		return
	}
}

// ReviewsBots возвращает список всех отзывов ботов.
// @Summary Получение всех отзывов ботов
// @Description Обрабатывает запрос и возвращает все существующие отзывы ботов из базы данных.
// @Tags         Пользователи
// @Accept plain
// @Produce json
// @Success 200 {array} ReviewsBots "Массив объектов с отзывами"
// @Failure 404 {object} ErrorResponse "Отзывы не найдены"
// @Failure 500 {object} ErrorResponse "Ошибка на сервере: %v"
// @Router /reviews-bots [get]
func (uh *UserHandler) ReviewsBots(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем все отзывы из базы данных
	rows, err := uh.UsersRepo.db.Query(ctx, "SELECT ReviewID, ReviewText, ReviewDate, Rating, CustomerName FROM reviews_bots")
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при обращении к базе данных: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var reviews []ReviewsBots

	// Собираем все полученные строки
	for rows.Next() {
		var review ReviewsBots
		if err := rows.Scan(&review.ReviewID, &review.ReviewText, &review.ReviewDate, &review.Rating, &review.CustomerName); err != nil {
			handleError(w, r, fmt.Errorf("ошибка сканирования отзыва: %v", err), http.StatusInternalServerError)
			return
		}
		reviews = append(reviews, review)
	}

	// Проверяем, что нет никаких скрытых ошибок
	if err := rows.Err(); err != nil {
		handleError(w, r, fmt.Errorf("ошибка обращения к базе данных: %v", err), http.StatusInternalServerError)
		return
	}

	// Проверяем, есть ли хотя бы один отзыв
	if len(reviews) == 0 {
		handleError(w, r, fmt.Errorf("отзывы не найдены: %v", err), http.StatusNotFound)
		return
	}

	// Возвращаем полученный список отзывов
	respondWithJSON(w, http.StatusOK, reviews)
}

// RevokeSessionHandler обрабатывает запрос на отмену существующего сеанса пользователя.
// Получает идентификатор сеанса и удаляет его из хранилища.
// @Summary Отмена активного сеанса пользователя
// @Description Обеспечивает безопасный выход пользователя из своего профиля путём отмены сеанса.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param session_request body SessionRequest true "Запрос на отмену сеанса"
// @Success 200 {object} map[string]string "Сеанс успешно отменён"
// @Failure 401 {object} map[string]string "Необходимо авторизоваться"
// @Failure 400 {object} map[string]string "Некорректный запрос"
// @Failure 500 {object} map[string]string "Ошибка на сервере: %v"
// @Router /revoke-session [post]
func (uh *UserHandler) RevokeSessionHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("необходимо авторизоваться: %v", err), http.StatusUnauthorized)
		return
	}

	// Декодируем тело запроса
	var req SessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handleError(w, r, fmt.Errorf("ошибка при разборе запроса: %v", err), http.StatusBadRequest)
		return
	}

	// Получаем идентификатор сеанса
	sessionID := req.SessionID

	// Идентификатор текущего пользователя
	userID := sess.UserID

	// Удаляем сеанс из БД
	result, err := uh.UsersRepo.db.Exec(ctx, `
        DELETE FROM sessions 
        WHERE id = $1 AND user_id = $2`,
		sessionID, userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при отмене сеанса: %v", err), http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		handleError(w, r, fmt.Errorf("сеанс не найден или уже аннулирован: %v", err), http.StatusNotFound)
		return
	}

	// Формируем успешный ответ
	response := map[string]string{
		"message": "Сеанс успешно отменён",
	}

	respondWithJSON(w, http.StatusOK, response)
}

// SaveCompanyInfoHandler сохраняет или обновляет информацию о компании.
// Данный обработчик получает форму с параметрами компании и сохраняет их в репозитории.
// Затем перенаправляет обратно на страницу редактирования компании.
// @Summary Сохранение информации о компании
// @Description Обновляет информацию о компании на основании полученных данных.
// @Tags         Пользователи
// @Accept x-www-form-urlencoded
// @Produce html
// @Param name formData string false "Название компании"
// @Param logo_url formData string false "Адрес логотипа компании"
// @Param website_url formData string false "Сайт компании"
// @Success 302 {string} string "Переход на страницу администрирования компании"
// @Failure 500 {object} ErrorResponse "Ошибка на сервере: %v"
// @Router /company/save [post]
func (uh *UserHandler) SaveCompanyInfoHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Получаем данные из формы
	name := r.FormValue("name")
	logoURL := r.FormValue("logo_url")
	websiteURL := r.FormValue("website_url")

	// Сохраняем или обновляем информацию о компании
	err := uh.UsersRepo.saveCompanyInfo(name, logoURL, websiteURL)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при сохранении информации о компании: %v", err), http.StatusInternalServerError)
		return
	}

	// Переходим обратно на страницу редактирования компании
	http.Redirect(w, r, "/admin/company", http.StatusFound)
}

// SendPasswordReset обрабатывает запрос на сброс пароля.
// Принимает JSON с полем "email", находит пользователя по этому адресу,
// создает временный JWT-токен и отправляет ссылку для сброса пароля на указанный почтовый ящик.
// @Summary Запрос на сброс пароля
// @Description Приложение инициирует процедуру сброса пароля путем отправки временного токена на почту пользователя.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param password_reset_request body PasswordResetRequest true "Запрос на сброс пароля"
// @Success 200 {object} map[string]string "Ссылка для сброса пароля отправлена"
// @Failure 400 {object} map[string]string "Некорректный запрос (пример: отсутствует поле Email)"
// @Failure 404 {object} map[string]string "Пользователь с таким E-Mail не найден"
// @Failure 500 {object} map[string]string "Ошибка сервера: %v"
// @Router /password/reset [post]
func (uh *UserHandler) SendPasswordReset(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Читаем данные из тела запроса
	var req PasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handleError(w, r, fmt.Errorf("ошибка при декодировании данных: %v", err), http.StatusBadRequest)
		return
	}

	// Проверяем наличие обязательного поля Email
	if req.Email == "" {
		handleError(w, r, fmt.Errorf("поле 'email' обязательно для заполнения"), http.StatusBadRequest)
		return
	}

	// Поиск пользователя по email
	user, err := uh.UsersRepo.FindUserByEmail(req.Email)
	if err != nil && err.Error() == "not found" {
		handleError(w, r, fmt.Errorf("пользователь с данным email не найден: %v", err), http.StatusNotFound)
		return
	} else if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при поиске пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	// Генерация JWT-токена для сброса пароля
	expirationTime := time.Now().Add(time.Hour)
	claims := &jwt.StandardClaims{
		Subject:   user.Email,
		ExpiresAt: expirationTime.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при генерации JWT-токена: %v", err), http.StatusInternalServerError)
		return
	}

	// Составляем ссылку для сброса пароля
	resetLink := fmt.Sprintf("http://localhost:3000/reset?token=%s&auto=true", tokenString)

	// Запускаем отправку письма в отдельной горутине
	go func() {
		if err := uh.SendEmail(user.Email, resetLink); err != nil {
			handleError(w, r, fmt.Errorf("ошибка при отправке письма пользователю: %v", err), http.StatusInternalServerError)
			return
		}
	}()

	// Формируем успешный ответ
	response := map[string]string{"message": "Ссылка для сброса пароля успешно отправлена на указанный email. Проверьте почту и следуйте инструкциям в письме."}

	respondWithJSON(w, http.StatusOK, response)
}

// SendMessageHandler обрабатывает отправку сообщения между пользователями.
// @Summary Отправка сообщения другому пользователю
// @Description Отправляет сообщение от текущего пользователя другому пользователю.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param message body MessageRequest true "Параметры сообщения"
// @Success 200 {object} map[string]string "Сообщение успешно отправлено"
// @Failure 401 {object} map[string]string "Необходима авторизация"
// @Failure 400 {object} map[string]string "Недопустимый запрос"
// @Failure 500 {object} map[string]string "Ошибка на сервере: %v"
// @Router /send-message [post]
func (uh *UserHandler) SendMessageHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("необходимо авторизоваться: %v", err), http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodOptions {
		// Предварительная проверка CORS
		w.WriteHeader(http.StatusOK)
		return
	}

	var req MessageRequest

	// Декодируем JSON из тела запроса
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handleError(w, r, fmt.Errorf("ошибка при декодировании данных: %v", err), http.StatusBadRequest)
		return
	}

	// Проверяем, что UserID отправителя не равен нулю
	if sess.UserID == 0 {
		handleError(w, r, fmt.Errorf("неопределённый пользователь: %v", err), http.StatusUnauthorized)
		return
	}

	// Отправляем сообщение
	if err := uh.UsersRepo.SendMessage(ctx, sess.UserID, req.RecipientID, req.Message); err != nil {
		handleError(w, r, fmt.Errorf("ошибка при отправке сообщения: %v", err), http.StatusInternalServerError)
		return
	}

	// Формируем успешный ответ
	response := map[string]string{"message": "сообщение успешно отправлено"}

	respondWithJSON(w, http.StatusOK, response)
}

// CheckSession проверяет действительность сессии пользователя и возвращает информацию о нём.
// Эта функция проверяет куки сессии и извлекает информацию о соответствующем пользователю.
// @Summary Проверка активности сессии пользователя
// @Description Проверяет куки сессии и возвращает информацию о текущем авторизованном пользователе.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Success 200 {object} SessionRequest "Информация о действующем пользователе"
// @Failure 401 {object} ErrorResponse "Сессия недействительна или отсутствует"
// @Failure 500 {object} ErrorResponse "Ошибка на стороне сервера: %v"
// @Router /check_session [get]
func (uh *UserHandler) CheckSession(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем cookie с идентификатором сессии
	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		handleError(w, r, fmt.Errorf("cookie сессии не найдена или повреждена: %v", err), http.StatusUnauthorized)
		return
	}

	// Получаем ID пользователя по сессии
	userID, err := uh.UsersRepo.getSessionByID(ctx, sessionCookie.Value)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при проверке сессии:= %v", err), http.StatusInternalServerError)
		return
	}

	// Получаем информацию о пользователе
	user, err := uh.UsersRepo.GetByID(r.Context(), userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении информации о пользователе: %v", err), http.StatusInternalServerError)
		return
	}

	// Ответ пользователю
	resp := map[string]interface{}{
		"isAuthenticated": true,
		"user":            user,
	}

	// Генерируем ответ
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка сериализации ответа: %v", err), http.StatusInternalServerError)
		return
	}
}

// SessionsHandler обрабатывает запрос на получение списка активных сессий пользователя.
// Получает активный список сессий текущего пользователя и формирует ответ в формате JSON.
// @Summary Список активных сессий пользователя
// @Description Предоставляет список текущих сессий конкретного пользователя.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} map[string]interface{} "Список активных сессий пользователя"
// @Failure 401 {object} ErrorResponse "Необходима авторизация"
// @Failure 500 {object} ErrorResponse "Ошибка на стороне сервера: %v"
// @Router /sessions [GET]
func (uh *UserHandler) SessionsHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("необходимо авторизоваться: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID

	// Получаем активные сессии пользователя
	sessions, err := uh.UsersRepo.getSessionsByUserID(ctx, userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессий: %v", err), http.StatusInternalServerError)
		return
	}

	// Формируем ответ
	response := map[string]interface{}{
		"Sessions": sessions,
	}

	respondWithJSON(w, http.StatusOK, response)
}

// @Summary Проверка существования пользователя
// @Description Проверяет существование пользователя по указанному имени пользователя (Username)
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param checkUser body CheckUserRequest true "Информация для проверки пользователя"
// @Success 200 {object} map[string]bool "Пользователь найден"
// @Failure 400 {object} map[string]string "Некорректный запрос"
// @Failure 404 {object} map[string]string "Пользователь не найден"
// @Failure 500 {object} map[string]string "Ошибка на стороне сервера"
// @Router /check-user [POST]
func (uh *UserHandler) CheckUser(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	var req CheckUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handleError(w, r, fmt.Errorf("ошибка при разборе данных запроса: %v", err), http.StatusBadRequest)
		return
	}

	if req.Username == nil || len(*req.Username) == 0 {
		handleError(w, r, fmt.Errorf("поле Username обязательно для заполнения"), http.StatusBadRequest)
		return
	}

	username := *req.Username

	user, err := uh.UsersRepo.GetByLoginOrEmail(r.Context(), username, username)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при поиске пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	if user == nil {
		handleError(w, r, fmt.Errorf("пользователь не найден: %v", err), http.StatusNotFound)
		return
	}

	response := map[string]bool{
		"exists": true,
	}

	respondWithJSON(w, http.StatusOK, response)
}

// @Summary Авторизация пользователя
// @Description Выполняет авторизацию пользователя, проверяя введённые учётные данные.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param credentials body LoginRequest true "Учётные данные пользователя"
// @Success 200 {object} map[string]interface{} "Авторизация прошла успешно"
// @Failure 400 {object} map[string]string "Некорректный запрос: %v"
// @Failure 401 {object} map[string]string "Неправильные учётные данные"
// @Failure 500 {object} map[string]string "Ошибка на сервере: %v"
// @Router /login [post]
func (uh *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handleError(w, r, fmt.Errorf("ошибка при чтении данных запроса: %v", err), http.StatusBadRequest)
		return
	}

	if req.Username == nil {
		handleError(w, r, fmt.Errorf("поле 'Username' обязательно должно быть установлено"), http.StatusBadRequest)
		return
	}

	// Проверка введённого имени пользователя и пароля
	u, err := uh.UsersRepo.checkPasswordByLoginOrEmail(r.Context(), *req.Username, *req.Username, req.PasswordHash)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при проверке учётных данных: %v", err), http.StatusInternalServerError)
		return
	}

	// Получаем пользователя по найденному ID
	user, err := uh.UsersRepo.GetByID(r.Context(), u.ID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	// Создаём сессию для залогиненного пользователя
	if err := uh.Sessions.Create(r.Context(), w, user, r); err != nil {
		handleError(w, r, fmt.Errorf("ошибка при создании сессии: %v", err), http.StatusInternalServerError)
		return
	}

	// Готовим успешный ответ
	response := map[string]interface{}{
		"exists": true,
		"user":   user,
	}

	respondWithJSON(w, http.StatusOK, response)
}

// Signout обрабатывает процесс выхода пользователя из системы.
// Уничтожает текущую сессию и отправляет ответ в формате JSON.
// @Summary Выход пользователя из системы
// @Description Завершает активную сессию пользователя и подтверждает выход.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Success 200 {object} Response "Пользователь успешно вышел из системы"
// @Failure 401 {object} ErrorResponse "Необходимо пройти аутентификацию перед выходом"
// @Failure 500 {object} ErrorResponse "Ошибка завершения сессии: %v"
// @Router /signout [post]
func (uh *UserHandler) Signout(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Проверяем наличие сессии
	_, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("необходимо предварительно войти в систему: %v", err), http.StatusUnauthorized)
		return
	}

	// Уничтожение текущей сессии пользователя.
	err = uh.Sessions.DestroyCurrent(ctx, w, r)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка завершения сессии: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]string{"message": "Вы успешно вышли из системы"}

	respondWithJSON(w, http.StatusOK, response)
}

// Signup обрабатывает запрос на регистрацию нового пользователя.
// Создает новую учетную запись пользователя и отправляет письмо подтверждения на указанный e-mail.
// @Summary Регистрация нового пользователя
// @Description Обрабатывает запрос на создание новой учетной записи пользователя и отправляет код подтверждения на электронную почту.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param signupRequest body SignUpRequest true "Информация для регистрации пользователя"
// @Success 201 {object} Response "Пользователь успешно зарегистрирован"
// @Failure 400 {object} ErrorResponse "Некорректные данные в запросе: %v"
// @Failure 405 {object} ErrorResponse "Используйте метод POST"
// @Failure 500 {object} ErrorResponse "Ошибка сервера при обработке запроса: %v"
// @Router /signup [post]
func (uh *UserHandler) Signup(w http.ResponseWriter, r *http.Request) {
	// Включаем поддержку CORS
	enableCors(&w)

	// Проверяем метод запроса
	if r.Method != http.MethodPost {
		handleError(w, r, fmt.Errorf("используйте метод POST"), http.StatusMethodNotAllowed)
		return
	}

	// Парсим тело запроса и получаем объект SignUpRequest
	signupRequest, err := parseSignupRequest(r)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при разборе данных формы: %v", err), http.StatusBadRequest)
		return
	}

	// Создание нового пользователя
	user, err := uh.createUser(r.Context(), signupRequest)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при создании пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	// Отправляем подтверждение регистрации и формируем сессию
	// if err := uh.handleVerificationAndSession(r.Context(), w, user, r); err != nil {
	// 	handleError(w, r, fmt.Errorf("ошибка отправки письма подтверждения: %v", err), http.StatusInternalServerError)
	// 	return
	// }

	// Формируем успешный ответ
	response := map[string]interface{}{
		"message": "Пользователь успешно зарегистрирован",
		"user":    user.ID,
	}

	respondWithJSON(w, http.StatusCreated, response)
}

// @Summary Основная точка входа для операций с социальным профилем пользователя
// @Description Этот обработчик распределяет запросы между методами handlePost и handleGet в зависимости от используемого HTTP-метода.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param Authorization header string true "Авторизационный токен JWT"
// @Router /social-profile [POST]
// @Security ApiKeyAuth
func (uh *UserHandler) SocialProfileHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		uh.handlePost(w, r) // Обрабатывает POST-запросы
	case http.MethodGet:
		uh.handleGet(w, r) // Обрабатывает GET-запросы
	default:
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET, POST")
		return
	}
}

// SubscribeHandler обрабатывает запрос на подписку пользователя на другого пользователя.
// Он принимает ID пользователя, на которого подписываются, и добавляет запись в базу данных.
// Если возникла ошибка, она отправляется в формате JSON.
// @Summary Подписка на пользователя
// @Description Обрабатывает запрос на подписку пользователя на другого пользователя.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param id path integer true "Идентификатор пользователя, на которого подписываемся"
// @Success 200 {object} Request "Сообщение об успешной подписке"
// @Failure 401 {object} ErrorResponse "Ошибка авторизации (необходимо войти): %v"
// @Failure 400 {object} ErrorResponse "Ошибка в значении ID пользователя: %v"
// @Failure 500 {object} ErrorResponse "Ошибка при выполнении операции: %v"
// @Router /subscribe/{id} [post]
func (uh *UserHandler) SubscribeHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	// Извлекаем ID пользователя, на которого хотим подписаться
	followedIdStr := r.PathValue("id")
	followedId, err := strconv.ParseInt(followedIdStr, 10, 64)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка преобразования значения ID пользователя: %v", err), http.StatusBadRequest)
		return
	}

	currentUserId := sess.UserID

	// Проверяем наличие пользователя в базе данных
	exists, err := uh.UsersRepo.UserExists(ctx, followedId)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка проверки наличия пользователя: %v", err), http.StatusInternalServerError)
		return
	}
	if !exists {
		handleError(w, r, fmt.Errorf("указанного пользователя не существует: %v", err), http.StatusBadRequest)
		return
	}

	// Проверяем, не подписан ли уже пользователь
	isFollowing, err := uh.UsersRepo.isFollowing(currentUserId, followedId)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка проверки состояния подписки: %v", err), http.StatusInternalServerError)
		return
	}
	if isFollowing {
		handleError(w, r, fmt.Errorf("уже подписаны на этого пользователя: %v", err), http.StatusConflict)
		return
	}

	// Выполняем операцию подписки
	err = uh.UsersRepo.SubscribeUser(currentUserId, followedId, ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при создании подписки: %v", err), http.StatusInternalServerError)
		return
	}

	// Формирование успешного ответа
	response := Request{
		Message: "успешно подписались",
		Number:  int(followedId),
	}

	respondWithJSON(w, http.StatusOK, response)
}

// UnblockHandler - обработчик для разблокировки пользователя.
// Получает идентификатор заблокированного пользователя из URL и пытается снять блокировку.
// Возвращает соответствующее сообщение об успехе или ошибку в формате JSON.
// @Summary Разблокировка пользователя
// @Description Позволяет пользователям снимать блокировки друг друга.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param id path integer true "Идентификатор пользователя, которого нужно разблокировать"
// @Success 200 {string} string "Пользователь успешно разблокирован"
// @Failure 401 {object} ErrorResponse "Ошибка авторизации (необходима активная сессия): %v"
// @Failure 400 {object} ErrorResponse "Ошибка парсинга ID пользователя: %v"
// @Failure 500 {object} ErrorResponse "Ошибка при снятии блокировки: %v"
// @Router /unblock/{id} [post]
func (uh *UserHandler) UnblockHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	// Извлекаем идентификатор пользователя из пути URL
	userId := r.PathValue("id")
	if userId == "" {
		handleError(w, r, fmt.Errorf("не указан идентификатор пользователя: %v", err), http.StatusBadRequest)
		return
	}

	// Преобразуем идентификатор пользователя в int
	userIdInt, err := strconv.Atoi(userId)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка преобразования идентификатора пользователя: %v", err), http.StatusBadRequest)
		return
	}

	blockerID := sess.UserID
	blockedID := int64(userIdInt)

	// Проверяем, блокировал ли текущий пользователь указанного пользователя
	isBlocked, err := uh.UsersRepo.isBlocked(blockerID, blockedID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка проверки блокировки: %v", err), http.StatusInternalServerError)
		return
	}

	if !isBlocked {
		handleError(w, r, fmt.Errorf("этого пользователя нельзя разблокировать, поскольку он не был заблокирован: %v", err), http.StatusBadRequest)
		return
	}

	// Пытаемся разблокировать пользователя
	err = uh.UsersRepo.unblockUser(blockerID, blockedID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка снятия блокировки: %v", err), http.StatusInternalServerError)
		return
	}

	response := "Пользователь успешно разблокирован"

	respondWithJSON(w, http.StatusOK, response)
}

// UnsubscribeHandler обрабатывает запрос на отмену подписки пользователя.
// Получает ID пользователя, от которого нужно отписаться, и удаляет подписку из базы данных.
// Возвращает сообщение об успехе или ошибке в формате JSON.
// @Summary Отмена подписки пользователя
// @Description Отменяет подписку пользователя на другого пользователя.
// @Tags Пользователи
// @Accept json
// @Produce json
// @Param id path integer true "ID пользователя, от которого необходимо отписаться"
// @Success 200 {object} Request "Сообщение об успешной отмене подписки"
// @Failure 401 {object} ErrorResponse "Ошибка авторизации (отсутствие сессии): %v"
// @Failure 400 {object} ErrorResponse "Ошибка преобразования параметра (неправильно указан ID): %v"
// @Failure 500 {object} ErrorResponse "Ошибка обработки запроса на сервере: %v"
// @Router /unsubscribe/{id} [post]
func (uh *UserHandler) UnsubscribeHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	// Получаем ID пользователя, от которого необходимо отписаться, из URL
	followedIdStr := r.PathValue("id")

	followedId, err := strconv.ParseInt(followedIdStr, 10, 64) // Преобразуем строку в int64
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка преобразования id пользователя: %v", err), http.StatusBadRequest)
		return
	}

	// ID текущего пользователя
	currentUserId := sess.UserID

	// Удаление подписки из базы данных с использованием нового метода
	err = uh.UsersRepo.UnsubscribeUser(currentUserId, followedId, ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка отмены подписки: %v", err), http.StatusInternalServerError)
		return
	}

	response := Request{
		Message: "успешно отписались",
		Number:  int(followedId),
	}

	respondWithJSON(w, http.StatusOK, response)
}

// UpdateAccountHandler обрабатывает обновление данных аккаунта пользователя.
// Получает сессию пользователя, проверяет метод запроса,
// обрабатывает и валидирует входящие данные в формате JSON,
// а затем обновляет профиль пользователя в базе данных.
//
// @Summary Обновление профиля пользователя
// @Description Обновляет имя пользователя, адрес электронной почты и настройки рекламы.
// @Tags Пользователи
// @Accept json
// @Produce json
// @Param update_data body AccountRequest true "Данные для обновления профиля"
// @Success 204 "Профиль успешно обновлён"
// @Failure 400 {object} ErrorResponse "Ошибка проверки данных (формат или пустые поля)"
// @Failure 401 {object} ErrorResponse "Ошибка авторизации (нет активной сессии)"
// @Failure 405 {object} ErrorResponse "Метод не поддерживается (должен быть POST)"
// @Failure 500 {object} ErrorResponse "Ошибка на стороне сервера"
// @Router /update_account [post]
func (uh *UserHandler) UpdateAccountHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаём новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка авторизации: %v", err), http.StatusUnauthorized)
		return
	}

	defer func() {
		if r := recover(); r != nil {
			debug := fmt.Errorf("возникла неожиданная ошибка: %v", err)
			panic(debug)
		}
	}()

	userID := sess.UserID

	// Проверяем метод запроса
	if r.Method != http.MethodPost {
		handleError(w, r, fmt.Errorf("этот метод не поддержан, используйте POST: %v", err), http.StatusMethodNotAllowed)
		return
	}

	// Обработка данных в формате JSON
	var accountRequest AccountRequest
	decoder := json.NewDecoder(r.Body)
	defer func() {
		if err := r.Body.Close(); err != nil {
			handleError(w, r, fmt.Errorf("ошибка закрытия тела запроса: %v", err), http.StatusInternalServerError)
			return
		}
	}()

	// Декодирование JSON в структуру AccountRequest
	if err := decoder.Decode(&accountRequest); err != nil {
		handleError(w, r, fmt.Errorf("ошибка декодирования данных: %v", err), http.StatusBadRequest)
		return
	}

	// Проверка CSRF-токена
	ok, err := uh.Tokens.Check(sess, accountRequest.CSRFToken)
	if !ok || err != nil {
		handleError(w, r, fmt.Errorf("ошибка проверки токена безопасности: %v", err), http.StatusForbidden)
		return
	}

	// Валидация данных пользователя
	if accountRequest.Username == nil || *accountRequest.Username == "" || accountRequest.Email == "" {
		handleError(w, r, fmt.Errorf("имя пользователя и электронная почта обязательны: %v", err), http.StatusBadRequest)
		return
	}

	// Приведение адреса электронной почты к нижнему регистру
	email := strings.ToLower(accountRequest.Email)

	// Обновление данных пользователя
	if err := uh.UsersRepo.UpdateUser(ctx, userID, accountRequest.Username, email, accountRequest.NoAds); err != nil {
		handleError(w, r, fmt.Errorf("ошибка обновления данных пользователя: %v", err), http.StatusInternalServerError)
		return
	}

	// Успешный ответ без содержимого (HTTP 204 No Content)
	w.WriteHeader(http.StatusNoContent)
}

// UploadAvatarHandler обрабатывает POST-запросы для загрузки аватара пользователя.
// @Summary Загрузка аватара пользователя
// @Description Обрабатывает POST-запрос для загрузки нового аватара пользователя.
// @Tags         Пользователи
// @Accept multipart/form-data
// @Produce json
// @Param avatar formData file true "Файл изображения аватара"
// @Success 200 {object} map[string]string "Аватар загружен успешно"
// @Failure 400 {object} map[string]string "Неправильный формат файла или другие ошибки клиента"
// @Failure 401 {object} map[string]string "Требуется авторизация (необходимо войти)"
// @Failure 500 {object} map[string]string "Ошибка сервера при обработке запроса (%v)" // Тут добавляется переменная для вывода текста ошибки
// @Router /users/upload_avatar [post]
func (uh *UserHandler) UploadAvatarHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("отсутствует авторизация: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID

	if err := uh.uploadAvatar(r, userID); err != nil {
		handleError(w, r, fmt.Errorf("ошибка при загрузке аватара: %v", err), http.StatusInternalServerError)
		return
	}

	// Формируем ответ
	response := map[string]string{
		"message": "Аватар успешно загружен",
	}

	respondWithJSON(w, http.StatusOK, response)
}

// UserSkillsGetHandler возвращает список навыков текущего пользователя.
// @Summary Получить список навыков пользователя
// @Description Обрабатывает GET-запрос для извлечения списка навыков пользователя.
// @Tags         Пользователи
// @Produce json
// @Success 200 {object} Response "Список навыков пользователя"
// @Failure 401 {object} ErrorResponse "Пользователь не авторизован"
// @Failure 500 {object} ErrorResponse "Ошибка сервера при обработке запроса"
// @Router /users/skills [get]
func (uh *UserHandler) UserSkillsGetHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("отсутствует авторизация: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID // Предполагаем, что userID - это int64 из сессии

	// Получаем все навыки пользователя
	skills, err := uh.UsersRepo.GetUserSkills(userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка получения навыков: %v", err), http.StatusInternalServerError)
		return
	}

	// Если у пользователя нет навыков, возвращаем пустой массив
	if skills == nil {
		skills = []Skill{}
	}

	// Формируем ответ
	response := struct {
		UserID int64   `json:"user_id"`
		Skills []Skill `json:"skills"`
	}{
		UserID: userID,
		Skills: skills,
	}

	respondWithJSON(w, http.StatusOK, response)
}

// UserSkillsPostHandler обрабатывает POST-запрос для сохранения списка навыков пользователя.
// @Summary Сохраняет список навыков пользователя
// @Description Обрабатывает POST-запрос для записи обновленного списка навыков пользователя.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param skills body UserSkills true "Объект с набором навыков пользователя"
// @Success 200 {object} map[string]interface{} "Запись навыков выполнена успешно"
// @Failure 400 {object} map[string]interface{} "Некорректный формат входящих данных"
// @Failure 401 {object} map[string]interface{} "Пользователь не авторизован"
// @Failure 500 {object} map[string]interface{} "Ошибка обработки запроса сервером"
// @Router /users/skills [post]
func (uh *UserHandler) UserSkillsPostHandler(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("отсутствует авторизация: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID // Предполагаем, что userID - это int64 из сессии

	var skills UserSkills
	if err := json.NewDecoder(r.Body).Decode(&skills); err != nil {
		handleError(w, r, fmt.Errorf("неверный формат передаваемых данных: %v", err), http.StatusBadRequest)
		return
	}
	defer func() {
		if err := r.Body.Close(); err != nil {
			handleError(w, r, fmt.Errorf("ошибка закрытия тела запроса: %v", err), http.StatusInternalServerError)
			return
		}
	}()

	// Обновляем навыки пользователя
	if err := uh.UpdateUserSkills(userID, skills.Skills); err != nil {
		handleError(w, r, fmt.Errorf("ошибка обновления навыков: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ClearUserSubcategories обрабатывает DELETE-запрос для удаления подкатегории у услуги пользователя.
// @Summary Удаление подкатегории у услуги пользователя
// @Description Обрабатывает DELETE-запрос для удаления подкатегории из услуги пользователя по ID подкатегории.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param request body DeleteSubcategoryRequest true "ID подкатегории для удаления"
// @Success 200 {object} map[string]string "Успешный ответ с сообщением об удалении"
// @Failure 400 {object} map[string]string "Некорректный формат входных данных"
// @Failure 401 {object} map[string]string "Отсутствует авторизация (необходимо войти)"
// @Failure 403 {object} map[string]string "Нет доступа (недостаточно прав)"
// @Failure 500 {object} map[string]string "Ошибка внутреннего сервера (например, база данных недоступна)"
// @Router /user/subcategories [delete]
func (uh *UserHandler) ClearUserSubcategories(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("отсутствует авторизация: %v", err), http.StatusUnauthorized)
		return
	}

	var request DeleteSubcategoryRequest

	// Декодируем JSON из тела запроса в структуру запроса на удаление подкатегории
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		handleError(w, r, fmt.Errorf("некорректный формат входных данных: %v", err), http.StatusBadRequest)
		return
	}

	// Пытаемся удалить подкатегорию у услуги пользователя по ID подкатегории и ID пользователя из сессии.
	err = uh.UsersRepo.RemoveSubcategoryFromUserService(ctx, sess.UserID, request.SubcategoryID)

	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка удаления подкатегории: %v", err), http.StatusInternalServerError)
		return
	}

	response := "Подкатегория успешно удалена."

	respondWithJSON(w, http.StatusOK, response)
}

// GetUserSubcategories обрабатывает GET-запрос для получения специальностей пользователя.
// @Summary Получение специальностей пользователя
// @Description Обрабатывает GET-запрос для получения всех специальностей и подкатегорий пользователя.
// @Tags         Пользователи
// @Produce json
// @Success 200 {object} Response "Успешный ответ с данными специальностей"
// @Failure 401 {object} Response "Неавторизованный доступ"
// @Failure 500 {object} Response "Ошибка сервера"
// @Router /user/subcategories [get]
func (uh *UserHandler) GetUserSubcategories(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("отсутствует авторизация: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID

	userSpecialtyResponse, err := uh.UsersRepo.GetAllCategoriesAndSubcategories(userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка получения специальностей: %v", err), http.StatusInternalServerError)
		return
	}

	response := userSpecialtyResponse

	respondWithJSON(w, http.StatusOK, response)
}

// SetUserSubcategories обрабатывает POST-запрос для добавления или обновления оказываемых услуг пользователя.
// @Summary Добавление или обновление услуг пользователя
// @Description Обрабатывает POST-запрос для добавления или обновления оказываемых услуг пользователя.
// @Tags         Пользователи
// @Accept json
// @Produce json
// @Param user_services body []UserService true "Список услуг пользователя"
// @Success 201 {object} map[string][]int64 "IDs добавленных услуг"
// @Success 204 "Услуги удалены"
// @Failure 400 {string} string "Некорректный формат входных данных"
// @Failure 401 {string} string "Отсутствует авторизация (необходимо войти)"
// @Failure 403 {string} string "Доступ запрещён (недостаточно прав)"
// @Failure 500 {string} string "Ошибка внутреннего сервера (например, ошибка базы данных)"
// @Router /user/subcategories [post]
func (uh *UserHandler) SetUserSubcategories(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("отсутствует авторизация: %v", err), http.StatusUnauthorized)
		return
	}

	var userServices []UserService
	// Декодируем JSON из тела запроса в массив услуг пользователя
	if err := json.NewDecoder(r.Body).Decode(&userServices); err != nil {
		handleError(w, r, fmt.Errorf("невозможно декодировать тело запроса: %v", err), http.StatusBadRequest)
		return
	}

	now := time.Now()
	for i := range userServices {
		userServices[i].UserID = sess.UserID // Устанавливаем ID пользователя для каждой услуги
		userServices[i].CreatedAt = now      // Устанавливаем время создания услуги
		userServices[i].UpdatedAt = now      // Устанавливаем время обновления услуги
	}

	if len(userServices) == 0 {
		err := uh.UsersRepo.DeleteUserServices(ctx, sess.UserID)
		if err != nil {
			handleError(w, r, fmt.Errorf("ошибка удаления услуг: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent) // Возвращаем статус 204 No Content
		return
	}

	newIDs, err := uh.UsersRepo.InsertUserServices(ctx, userServices)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка вставки услуг: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated) // Возвращаем статус 201 Created
	enc := json.NewEncoder(w)
	if err := enc.Encode(map[string][]int64{"ids": newIDs}); err != nil {
		handleError(w, r, fmt.Errorf("ошибка кодирования ответа: %v", err), http.StatusInternalServerError)
		return
	} // Возвращаем новые ID добавленных услуг
}
// Открытый ключ для подписи JWT
const secretKey = "your_secret_key"
package user

import "net/http"

// enableCors - функция для включения CORS
// Она должна быть вызвана перед ответом на запрос

func EnableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "http://localhost:3000") // замените на ваш frontend
	(*w).Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	(*w).Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
}

func enableCors(w *http.ResponseWriter) {
	// (*w).Header().Set("Access-Control-Allow-Origin", "https://unclaimeds.ru")
	(*w).Header().Set("Access-Control-Allow-Origin", "https://unclaimeds.ru")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	(*w).Header().Set("Access-Control-Allow-Credentials", "true")
	(*w).Header().Set("Content-Type", "application/json")
}
package user

import (
	"context"
	"encoding/json"
	"net/http"
)

// Photos returns a list of photos associated with the user
func (uh *UserHandler) Photos(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	userId := r.URL.Query().Get("user_id")

	if userId == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}

	photos, err := uh.UsersRepo.GetUserPhotos(ctx, userId)
	if err != nil {
		http.Error(w, "Failed to get user photos: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(photos); err != nil {
		http.Error(w, "Failed to encode photos: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// GetUserPhotos returns a list of photos associated with the user
func (urepositary *UserRepository) GetUserPhotos(context.Context, string) ([]Photo, error) {
	photos := []Photo{
		{URL: "https://example.com/photo1.jpg"},
		{URL: "https://example.com/photo2.jpg"},
		{URL: "https://example.com/photo3.jpg"},
	}
	return photos, nil
}
package user

import (
	"log/slog"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/unclaim/the_server_part.git/pkg/session"
	"github.com/unclaim/the_server_part.git/pkg/token"
)

type UserHandler struct {
	Sessions  session.SessionManager
	Tokens    token.TokenManager
	UsersRepo *UserRepository
	Logger    *slog.Logger // Добавлено поле для логгера
}

// ReviewsBots представляет собой структуру отзыва.
type ReviewsBots struct {
	ReviewID     int       `json:"review_id"`              // Уникальный идентификатор отзыва
	ReviewText   string    `json:"review_text,omitzero"`   // Текст отзыва
	ReviewDate   time.Time `json:"review_date,omitzero"`   // Дата создания отзыва
	Rating       int       `json:"rating,omitzero"`        // Оценка отзыва (например, от 1 до 5)
	CustomerName string    `json:"customer_name,omitzero"` // Имя клиента, оставившего отзыв
}

// DeleteSubcategoryRequest представляет запрос на удаление подкатегории.
type DeleteSubcategoryRequest struct {
	SubcategoryID int64 `json:"subcategory_id,omitzero"` // ID подкатегории для удаления из услуги пользователя
}

// Photo представляет собой структуру для хранения информации о фотографии.
type Photo struct {
	URL string `json:"url,omitzero"` // URL фотографии
}

// AccountRequest представляет запрос на обновление аккаунта пользователя.
type AccountRequest struct {
	CSRFToken string  `json:"csrf_token,omitzero"` // CSRF-токен для защиты от подделки запросов
	Username  *string `json:"username,omitzero"`   // Имя пользователя (может быть nil)
	Email     string  `json:"email,omitzero"`      // Электронная почта пользователя
	NoAds     bool    `json:"no_ads,omitzero"`     // Флаг, указывающий на отсутствие рекламы в аккаунте
}

// CategoryResponse представляет структуру для категорий.
type CategoryResponse struct {
	ID   int    `json:"id,omitzero"`   // Уникальный идентификатор категории
	Name string `json:"name,omitzero"` // Название категории
}

// Company представляет информацию о компании.
type Company struct {
	ID          int       `json:"id,omitzero"`           // Уникальный идентификатор компании
	Name        string    `json:"name,omitzero"`         // Название компании
	LogoURL     string    `json:"logo_url,omitzero"`     // URL логотипа компании
	WebsiteURL  string    `json:"website_url,omitzero"`  // URL веб-сайта компании
	LastUpdated time.Time `json:"last_updated,omitzero"` // Дата последнего обновления информации о компании
}

// ErrorResponse представляет структуру для ошибок API.
type ErrorResponse struct {
	ErrorMessage string   `json:"errorMessage,omitzero"` // Сообщение об ошибке
	ErrorType    string   `json:"errorType,omitzero"`    // Тип ошибки (например, "validation", "not_found" и т.д.)
	StackTrace   []string `json:"stackTrace,omitzero"`   // Стек вызовов (может быть nil или пустым)
}

// MessageReq представляет структуру запроса к API для отметки сообщения как прочитанного.
type MessageReq struct {
	ID int64 `json:"id,omitzero"` // Уникальный идентификатор сообщения
}

// MessageRequest представляет структуру запроса для отправки сообщения.
type MessageRequest struct {
	RecipientID int64  `json:"recipient_id,omitzero"` // Идентификатор получателя сообщения
	Message     string `json:"message,omitzero"`      // Текст сообщения
}

// MessageResponse представляет структуру ответа API на запрос с сообщением.
type MessageResponse struct {
	StatusCode int         `json:"statusCode,omitzero"` // Код статуса HTTP-ответа
	Body       interface{} `json:"body,omitzero"`       // Тело ответа (может содержать любые данные)
}

// Order представляет структуру заказа.
type Order struct {
	ID     int    `json:"id,omitzero"`     // Уникальный идентификатор заказа
	Item   string `json:"item,omitzero"`   // Название товара или услуги
	Amount int    `json:"amount,omitzero"` // Количество товара или сумма заказа
}

// PasswordRequest представляет структуру запроса для изменения пароля пользователя.
type PasswordRequest struct {
	OldPassword  string `json:"old_password,omitzero"` // Текущий пароль пользователя
	NewPassword1 string `json:"pass1,omitzero"`        // Новый пароль (первый ввод)
	NewPassword2 string `json:"pass2,omitzero"`        // Новый пароль (второй ввод для подтверждения)
}

// PasswordResetRequest представляет структуру запроса для сброса пароля по email.
type PasswordResetRequest struct {
	Email string `json:"email,omitzero"` // Электронная почта пользователя для сброса пароля
}

// Request представляет тело общего запроса с сообщением и числовым параметром.
type Request struct {
	Message string `json:"message,omitzero"` // Текст сообщения
	Number  int    `json:"number,omitzero"`  // Числовой параметр запроса
}

// ResetPasswordParams содержит параметры для сброса пароля.
type ResetPasswordParams struct {
	Token string `json:"token,omitzero"` // Токен сброса пароля, полученный пользователем
	Email string `json:"email,omitzero"` // Электронная почта пользователя, связанная с токеном
}

// ResetPasswordRequest представляет структуру запроса для сброса пароля.
type ResetPasswordRequest struct {
	Token       string `json:"token,omitzero"`        // Токен для сброса пароля
	Email       string `json:"email,omitzero"`        // Электронная почта пользователя
	NewPassword string `json:"new_password,omitzero"` // Новый пароль
}

// ResetPasswordResponse представляет структуру ответа на запрос сброса пароля.
type ResetPasswordResponse struct {
	Token string `json:"token,omitzero"` // Токен, подтверждающий успешный сброс пароля
	Email string `json:"email,omitzero"` // Электронная почта пользователя
}

// Response представляет собой тело ответа с кодом статуса и данными.
type Response struct {
	StatusCode int         `json:"statusCode,omitzero"` // Код статуса HTTP-ответа
	Body       interface{} `json:"body,omitzero"`       // Тело ответа (может содержать любые данные)
}

// SessionRequest представляет структуру запроса для работы с сессией.
type SessionRequest struct {
	Message   string `json:"message,omitzero"`    // Сообщение, связанное с сессией
	SessionID string `json:"session_id,omitzero"` // Уникальный идентификатор сессии
}

// SigninRequest представляет структуру запроса для входа пользователя.
type SigninRequest struct {
	Username     *string `json:"username,omitzero"`      // Имя пользователя (может быть nil)
	PasswordHash string  `json:"password_hash,omitzero"` // Хэш пароля пользователя
}

// SignUpRequest представляет структуру запроса для регистрации нового пользователя.
type SignUpRequest struct {
	FirstName string `json:"first_name,omitzero"`    // Имя пользователя
	LastName  string `json:"last_name,omitzero"`     // Фамилия пользователя
	Username  string `json:"username,omitzero"`      // Имя пользователя для входа
	Email     string `json:"email,omitzero"`         // Электронная почта пользователя
	Password  string `json:"password_hash,omitzero"` // Хэш нового пароля
}

// SignupResponse представляет ответ на запрос регистрации нового пользователя.
type SignupResponse struct {
	Message  string `json:"message,omitzero"`  // Сообщение об успешной регистрации или ошибке (опционально)
	Error    string `json:"error,omitzero"`    // Сообщение об ошибке (опционально)
	Redirect string `json:"redirect,omitzero"` // URL для перенаправления после успешной регистрации (опционально)
}

// Skill представляет структуру навыка с идентификатором категории и навыка.
type Skill struct {
	CategoryID int `json:"category_id,omitzero"` // Идентификатор категории навыка
	SkillID    int `json:"skill_id,omitzero"`    // Идентификатор самого навыка
}

// UserService представляет услугу, предоставляемую пользователем.
type UserService struct {
	ID             int64     `json:"id,omitzero"`              // Уникальный идентификатор услуги
	UserID         int64     `json:"user_id,omitzero"`         // Идентификатор пользователя, предоставляющего услугу
	CategoryID     int       `json:"category_id,omitzero"`     // Идентификатор категории услуги
	CategoryName   string    `json:"category_name,omitzero"`   // Название категории услуги
	SubcategoryIDs []int64   `json:"subcategory_ids,omitzero"` // Массив идентификаторов подкатегорий услуги
	CreatedAt      time.Time `json:"created_at,omitzero"`      // Дата и время создания услуги
	UpdatedAt      time.Time `json:"updated_at,omitzero"`      // Дата и время последнего обновления услуги
}

// UserSpecialtyResponse представляет ответ с услугами пользователя.
type UserSpecialtyResponse struct {
	ID           int64         `json:"id,omitzero"`            // Уникальный идентификатор ответа
	UserID       int64         `json:"user_id,omitzero"`       // Идентификатор пользователя, чьи услуги возвращаются в ответе
	UserServices []UserService `json:"user_services,omitzero"` // Список услуг, предоставляемых пользователем
}

// TotalUserCount представляет общее количество пользователей.
type TotalUserCount struct {
	Total int64 `json:"total,omitzero"` // Общее количество пользователей
}

// UserCount представляет количество пользователей по типу.
type UserCount struct {
	Type  string `json:"type,omitzero"`  // Тип пользователей (например, активные, неактивные)
	Count int64  `json:"count,omitzero"` // Количество пользователей данного типа
}

// UserExport представляет информацию о пользователе и дате экспорта данных.
type UserExport struct {
	UserID     int       `json:"user_id,omitzero"`     // Уникальный идентификатор пользователя
	ExportDate time.Time `json:"export_date,omitzero"` // Дата экспорта данных пользователя
}

// UserNotFoundError представляет ошибку, когда пользователь не найден.
type UserNotFoundError struct {
	UserID int64 `json:"user_id,omitzero"` // Идентификатор пользователя, который не был найден
}

// UserRepository предоставляет методы для работы с пользователями в базе данных.
type UserRepository struct {
	db *pgxpool.Pool // Подключение к пулу соединений базы данных
}

// NewUsersRepository создает новый экземпляр UserRepository с заданным пулом соединений.
func NewUsersRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

// UserResponse представляет ответ с информацией о пользователях.
type UserResponse struct {
	UserCounts     []UserCount    `json:"user_counts,omitzero"`      // Список количеств пользователей по типам
	TotalUserCount TotalUserCount `json:"total_user_count,omitzero"` // Общее количество пользователей
}

// UserSkills представляет информацию о навыках пользователя.
type UserSkills struct {
	UserID int64 `json:"user_id,omitzero"` // Уникальный идентификатор пользователя
	Skills []int `json:"skills,omitzero"`  // Список идентификаторов навыков пользователя
}

// WorkPreferences представляет предпочтения пользователя в работе.
type WorkPreferences struct {
	UserID                   int64    `json:"user_id,omitzero"`                   // Уникальный идентификатор пользователя
	Availability             string   `json:"availability,omitzero"`              // Доступность пользователя для работы
	Location                 string   `json:"location,omitzero"`                  // Местоположение пользователя
	Specializations          []string `json:"specialties,omitzero"`               // Список специализаций пользователя
	Skills                   []string `json:"skills,omitzero"`                    // Список навыков пользователя
	AvailableSpecializations []string `json:"available_specializations,omitzero"` // Доступные специализации для работы
}

// VerifyCode представляет объект, используемый для проверки кода верификации.
type VerifyCode struct {
	ID    int64  `json:"id,omitzero"`          // Уникальный идентификатор записи проверки кода.
	Email string `json:"email,omitzero"`       // Адрес электронной почты пользователя.
	Code  int64  `json:"verify_code,omitzero"` // Код верификации, отправленный пользователю.
}

// User представляет пользователя с информацией о его профиле.
type User struct {
	ID             int64      `json:"id"`                    // Уникальный идентификатор пользователя в системе.
	Version        int64      `json:"ver,omitzero"`          // Версия профиля пользователя.
	Blacklisted    bool       `json:"blacklisted,omitzero"`  // Статус черного списка: true, если пользователь в черном списке, иначе false.
	Sex            *string    `json:"sex,omitzero"`          // Пол пользователя, представленный как строка (ENUM).
	FollowersCount int64      `json:"followers_count"`       // Количество подписчиков пользователя.
	Verified       bool       `json:"verified,omitzero"`     // Статус подтверждения профиля (true - подтвержден, false - не подтвержден).
	NoAds          bool       `json:"no_ads"`                // Флаг отключения рекламы (true - реклама отключена).
	CanUploadShot  bool       `json:"can_upload_shot"`       // Флаг, указывающий, может ли пользователь загружать работы на платформу.
	Pro            bool       `json:"pro"`                   // Флаг, указывающий, является ли пользователь профессионалом (true - да).
	Type           string     `json:"type"`                  // Тип пользователя, например, "обычный" или "профессионал".
	FirstName      *string    `json:"first_name"`            // Имя пользователя.
	LastName       *string    `json:"last_name"`             // Фамилия пользователя.
	MiddleName     *string    `json:"middle_name"`           // Отчество пользователя (если есть).
	Username       *string    `json:"username"`              // Уникальное имя пользователя.
	PasswordHash   string     `json:"password_hash"`         // Хэш пароля пользователя.
	Bdate          *time.Time `json:"bdate"`                 // Дата рождения пользователя.
	Phone          *string    `json:"phone"`                 // Номер телефона пользователя.
	Email          string     `json:"email"`                 // Электронная почта пользователя.
	HTMLURL        *string    `json:"html_url"`              // URL-адрес профиля пользователя в формате HTML.
	AvatarURL      *string    `json:"avatar_url"`            // URL-адрес аватара пользователя.
	Bio            *string    `json:"bio"`                   // Краткая информация о пользователе.
	Location       *string    `json:"location"`              // Местоположение пользователя.
	CreatedAt      time.Time  `json:"created_at"`            // Дата создания профиля пользователя.
	UpdatedAt      time.Time  `json:"updated_at"`            // Дата последнего обновления профиля пользователя.
	Links          UserLinks  `json:"links"`                 // Внешние ссылки пользователя (веб-сайт, Twitter и др.).
	Teams          []Team     `json:"teams"`                 // Список команд, в которых состоит пользователь.
	IsFollowing    bool       `json:"is_following,omitzero"` // Указывает, подписан ли текущий пользователь на данного пользователя.
	IsBlocked      bool       `json:"is_blocked,omitzero"`   // Указывает, заблокирован ли текущий пользователь данным пользователем.
}

// UserLinks представляет ссылки пользователя на внешние ресурсы.
type UserLinks struct {
	Web      string `json:"web,omitzero"`      // URL веб-сайта пользователя.
	Twitter  string `json:"twitter,omitzero"`  // URL профиля пользователя в Twitter.
	VK       string `json:"vk,omitzero"`       // URL профиля пользователя Вконтакте.
	Telegram string `json:"telegram,omitzero"` // URL профиля в Telegram.
	WhatsApp string `json:"whatsapp,omitzero"` // URL профиля в WhatsApp.
}

// Team представляет команду, в которой состоит пользователь.
type Team struct {
	ID        int       `json:"id,omitzero"`         // Уникальный идентификатор команды.
	Name      string    `json:"name,omitzero"`       // Название команды.
	Login     string    `json:"login,omitzero"`      // Логин команды для доступа.
	HTMLURL   string    `json:"html_url,omitzero"`   // URL профиля команды на Dribbble.
	AvatarURL string    `json:"avatar_url,omitzero"` // URL аватара команды.
	Bio       string    `json:"bio,omitzero"`        // Биография команды в формате HTML.
	Location  string    `json:"location,omitzero"`   // Местоположение команды.
	Links     UserLinks `json:"links,omitzero"`      // Внешние ссылки (например, веб-сайт и Twitter команды).
	Type      string    `json:"type,omitzero"`       // Тип команды (например, "Team").
	CreatedAt time.Time `json:"created_at,omitzero"` // Дата создания команды.
	UpdatedAt time.Time `json:"updated_at,omitzero"` // Дата последнего обновления команды.
}

// Message представляет сообщение в системе.
type Message struct {
	ID        int64     `json:"id,omitzero"`         // Уникальный идентификатор сообщения.
	SenderID  int64     `json:"sender_id,omitzero"`  // Идентификатор отправителя сообщения.
	Content   string    `json:"content,omitzero"`    // Содержимое сообщения.
	CreatedAt time.Time `json:"created_at,omitzero"` // Дата и время отправки сообщения.
	IsRead    bool      `json:"is_read,omitzero"`    // Статус прочтения сообщения (true - прочитано, false - не прочитано).
	Sender    User      `json:"sender,omitzero"`     // Добавляем информацию о пользователе, отправившем сообщение
}

// Реализуем методы UserInterface

// GetID возвращает уникальный идентификатор пользователя.
func (u *User) GetID() int64 {
	return u.ID
}

// GetUsrVersion возвращает версию профиля пользователя.
func (u *User) GetUsrVersion() int64 {
	return u.Version
}

// IsBlacklisted возвращает статус черного списка пользователя.
func (u *User) IsBlacklisted() bool {
	return u.Blacklisted
}

// GetSex возвращает пол пользователя.
func (u *User) GetSex() *string {
	return u.Sex
}

// GetFollowersCount возвращает количество подписчиков пользователя.
func (u *User) GetFollowersCount() int64 {
	return u.FollowersCount
}

// IsVerified возвращает статус подтверждения профиля пользователя.
func (u *User) IsVerified() bool {
	return u.Verified
}

// IsNoAds возвращает флаг отключения рекламы.
func (u *User) IsNoAds() bool {
	return u.NoAds
}

// CanUpload возвращает, может ли пользователь загружать работы на платформу.
func (u *User) CanUpload() bool {
	return u.CanUploadShot
}

// IsPro возвращает, является ли пользователь профессионалом.
func (u *User) IsPro() bool {
	return u.Pro
}

// GetType возвращает тип пользователя.
func (u *User) GetType() string {
	return u.Type
}

// GetFirstName возвращает имя пользователя.
func (u *User) GetFirstName() *string {
	return u.FirstName
}

// GetLastName возвращает фамилию пользователя.
func (u *User) GetLastName() *string {
	return u.LastName
}

// GetMiddleName возвращает отчество пользователя.
func (u *User) GetMiddleName() *string {
	return u.MiddleName
}

// GetUsername возвращает уникальное имя пользователя.
func (u *User) GetUsername() *string {
	return u.Username
}

// GetPasswordHash возвращает хэш пароля пользователя.
func (u *User) GetPasswordHash() string {
	return u.PasswordHash
}

// GetBdate возвращает дату рождения пользователя.
func (u *User) GetBdate() *time.Time {
	return u.Bdate
}

// GetPhone возвращает номер телефона пользователя.
func (u *User) GetPhone() *string {
	return u.Phone
}

// GetEmail возвращает электронную почту пользователя.
func (u *User) GetEmail() string {
	return u.Email
}

// GetHTMLURL возвращает URL-адрес профиля пользователя в формате HTML.
func (u *User) GetHTMLURL() *string {
	return u.HTMLURL
}

// GetAvatarURL возвращает URL-адрес аватара пользователя.
func (u *User) GetAvatarURL() *string {
	return u.AvatarURL
}

// GetBio возвращает краткую информацию о пользователе.
func (u *User) GetBio() *string {
	return u.Bio
}

// GetLocation возвращает местоположение пользователя.
func (u *User) GetLocation() *string {
	return u.Location
}

// GetCreatedAt возвращает дату и время создания профиля пользователя.
func (u *User) GetCreatedAt() time.Time {
	return u.CreatedAt
}

// GetUpdatedAt возвращает дату и время последнего обновления профиля пользователя.
func (u *User) GetUpdatedAt() time.Time {
	return u.UpdatedAt
}

// GetLinks возвращает внешние ссылки пользователя.
func (u *User) GetLinks() UserLinks {
	return u.Links
}

// GetTeams возвращает список команд, в которых состоит пользователь.
func (u *User) GetTeams() []Team {
	return u.Teams
}
package user

// todo:
const (
	SQL_USERS     = `select*from users;`
	SQL_READ_USER = `
 SELECT
        id,
        ver,
        blacklisted,
        sex,
		followers_count,   
		verified,
	    no_ads,
        can_upload_shot,    
        pro,
        type, 
        first_name,
        last_name,
        middle_name,
		username,
        location,
        bdate,
        phone,
        email,
		html_url,
        avatar_url,
        bio,
		location,       
        created_at,
        updated_at              
    FROM
        users
    WHERE
        id = $1;
`
	SQL_GET_USERNAME = `
 SELECT
        id,
        ver,
        blacklisted,
        sex,
		followers_count,   
		verified,
	    no_ads,
        can_upload_shot,    
        pro,
        type, 
        first_name,
        last_name,
        middle_name,
		username,
        location,
        bdate,
        phone,
        email,
		html_url,
        avatar_url,
        bio,
		location,       
        created_at,
        updated_at              
    FROM
        users
    WHERE
        username = $1;
`
	SQL_READ_USERNAME = `
 SELECT
        id,
        ver,
        blacklisted,
        sex,
		followers_count,   
		verified,
	    no_ads,
        can_upload_shot,    
        pro,
        type, 
        first_name,
        last_name,
        middle_name,
		username,
        location,
        bdate,
        phone,
        email,
		html_url,
        avatar_url,
        bio,
		location,       
        created_at,
        updated_at              
    FROM
        users
    WHERE
  username = $1;
	`
	SQL_READ_EMAIL_OR_USERNAME = `
	SELECT id,
    ver,
    username
FROM users
WHERE email = $1
    OR username = $2;
		`
	// SQL_CREATE_USER = `
	// INSERT INTO users (email, username, password_hash)
	// VALUES($1, $2, $3)
	// RETURNING id;
	// 	`

	SQL_CREATE_USER = `
	INSERT INTO users (first_name, last_name, username, email, password_hash) VALUES($1, $2, $3, $4, crypt($5, gen_salt('bf'))) RETURNING id;
		`

	SQL_READ_EMAIL_FOR_RESET_PWD = `SELECT id, ver, username, email FROM users WHERE email = $1;`

	SQL_CREATE_CODE = `
	INSERT INTO email_verify (email, verify_code)
	VALUES($1, $2)
	RETURNING id;
		`

	SQL_READ_CODE     = `SELECT id, email, verify_code FROM email_verify WHERE email = $1;`
	SQL_READ_VERIFIED = `SELECT id, verified FROM users WHERE id = $1;`

	SQL_UPDATE_VERIFIED = `update users set verified = true where email = $1;`
	// SQL_CREATE_PWD_SQL  = `UPDATE users SET password_hash = crypt($1, gen_salt('md5'))::bytea RETURNING id;`
	SQL_CREATE_PWD_SQL = `UPDATE users SET password_hash = crypt('007', gen_salt('md5')) where id=1;`
	SQL_READ_PWD_SQL   = `UPDATE users SET password_hash = crypt($1, gen_salt('md5'))::bytea RETURNING id;`
)

// SELECT*FROM users WHERE email = 'client@sllapshot.ru';
// SELECT*FROM users WHERE email = $1;

// SELECT id, username
//   FROM users
//  WHERE email = 'STERVA@mail.ru'
//    AND password_hash = crypt('w007', password_hash);
package user

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"github.com/lib/pq"
	"github.com/unclaim/the_server_part.git/pkg/session"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// UpdatePassword обновляет пароль пользователя в базе данных по адресу электронной почты.
// Новый пароль зашифровывается с использованием функции PostgreSQL crypt и генератора соли gen_salt с алгоритмом bcrypt.
// В случае успешной замены пароля возвращается nil, иначе возвращается соответствующая ошибка.
func (repository *UserRepository) UpdatePassword(email, newPassword string) error {
	// Подготовленный SQL-запрос для обновления пароля пользователя
	query := `
        UPDATE users 
        SET password_hash = crypt($1, gen_salt('bf'))
        WHERE email = $2
    `

	// Выполняем обновление пароля с новым значением и электронной почтой
	result, err := repository.db.Exec(context.Background(), query, newPassword, email)
	if err != nil {
		// Если произошла ошибка, возвращаем детализированное сообщение
		return fmt.Errorf("ошибка обновления пароля: %w", err)
	}

	// Проверяем количество затронутых строк (должна быть ровно одна)
	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("пользователь с указанной электронной почтой (%s) не найден", email)
	}

	// Успех, если обновление прошло успешно
	return nil
}

// blockUser - функция для блокировки одного пользователя другим
// blockerID - идентификатор пользователя, осуществляющего блокировку
// blockedID - идентификатор пользователя, подлежащего блокировке
// Функция возвращает ошибку, если процесс блокировки завершился неудачно
func (repository *UserRepository) blockUser(blockerID, blockedID int64) error {
	// Проверяем, пытается ли пользователь заблокировать сам себя
	if blockerID == blockedID {
		return fmt.Errorf("пользователь не может заблокировать самого себя")
	}

	// Выполняем SQL-запрос для добавления новой записи о блокировке
	_, err := repository.db.Exec(
		context.Background(),
		"INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2)",
		blockerID, blockedID,
	)

	// Обрабатываем потенциальные ошибки выполнения запроса
	if err != nil {
		// Проверяем наличие ошибки уникальности (нарушение уникального ключа),
		// которая возникает, если такой блок уже существовал ранее
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // Коды ошибок PostgreSQL
			return fmt.Errorf("пользователь с ID %d уже заблокирован пользователем с ID %d",
				blockedID, blockerID)
		}

		// Обработка всех остальных возможных ошибок выполнения запроса
		return fmt.Errorf("ошибка блокировки пользователя: %v", err)
	}

	// Блокировка успешно выполнена
	return nil
}

// checkPasswordByLoginOrEmail проверяет пароль пользователя по логину или почтовому адресу.
// Она выполняет запрос к базе данных, выбирая пользователя по логину или почте и сравнивая пароль с хранящимся хэшем.
// Если пользователь найден и пароль верный, возвращает информацию о пользователе.
// В противном случае возвращает nil и ошибку.
func (repository *UserRepository) checkPasswordByLoginOrEmail(ctx context.Context, Email, Username, pass string) (*User, error) {
	row := repository.db.QueryRow(ctx, ` SELECT id, username, email, ver, password_hash FROM users WHERE ((username = $1 AND password_hash = crypt($2, password_hash)) OR (email = $3 AND password_hash = crypt($4, password_hash))) `, Username, pass, Email, pass)

	return repository.passwordIsValidEmail(pass, row)
}

// checkPasswordByUserID проверяет пароль пользователя по его идентификатору.
// Она выбирает пользователя по идентификатору и сравнивает пароль с хранящимся хэшем.
// Если пользователь найден и пароль верный, возвращает информацию о пользователе.
// В противном случае возвращает nil и ошибку.
func (repository *UserRepository) checkPasswordByUserID(ctx context.Context, uid int64, pass string) (*User, error) {
	row := repository.db.QueryRow(ctx, ` SELECT id, username, ver, password_hash FROM users WHERE id = $1 AND password_hash = crypt($2, password_hash) `, uid, pass)

	return repository.passwordIsValid(pass, row)
}

// CheckUserExists проверяет, существует ли пользователь с указанным именем пользователя или e-mail.
//
// Аргументы:
// ctx     - Контекст выполнения запроса
// username - Имя пользователя для проверки
// email   - E-mail пользователя для проверки
//
// Возвращаемые значения:
// bool    - true, если пользователь найден, false - если не найден
// error   - Возникающая ошибка при обращении к базе данных
func (repository *UserRepository) CheckUserExists(ctx context.Context, username, email string) (bool, error) {
	// Подготавливаем SQL-запрос для проверки существования пользователя
	// Используется конструкция SELECT EXISTS, позволяющая эффективно проверять наличие хотя бы одной записи
	query := `
        SELECT EXISTS(
            SELECT 1
            FROM users
            WHERE username = $1 OR email = $2
        );
    `

	// Переменная для хранения результата проверки
	var exists bool

	// Выполняем запрос к базе данных и сканируем результат в переменную exists
	err := repository.db.QueryRow(ctx, query, username, email).Scan(&exists)
	if err != nil {
		// Если возникла ошибка при выполнении запроса или сканировании результата, возвращаем её
		return false, fmt.Errorf("ошибка при проверке существования пользователя: %w", err)
	}

	// Возвращаем результат проверки
	return exists, nil
}

// Проверяет статус верификации пользователя по его ID.
// Возвращает true, если пользователь подтвержден, false — если нет.
// Если произошла ошибка при чтении данных, возвращается соответствующая ошибка.
func (repository *UserRepository) checkVerifiedByUserID(ctx context.Context, uid int64) (bool, error) {
	// SQL-запрос для извлечения статуса верификации пользователя по его ID
	const SQL_READ_VERIFIED = `
        SELECT verified
        FROM users
        WHERE id = $1
        LIMIT 1
    `

	// Выполняем запрос к базе данных
	var verified bool
	err := repository.db.QueryRow(ctx, SQL_READ_VERIFIED, uid).Scan(&verified)
	if err != nil {
		// Преобразование ошибки для удобочитаемости
		return false, fmt.Errorf("ошибка при получении статуса верификации пользователя: %w", err)
	}

	// Возвращаем полученный статус верификации
	return verified, nil
}

// CreateAccountVerificationsCode создаёт новый код подтверждения аккаунта по указанному email.
// Возвращает ошибку, если не удаётся создать код или возникли проблемы с доступом к базе данных.
func (repository *UserRepository) CreateAccountVerificationsCode(ctx context.Context, email string, code int64) error {
	// SQL-запрос для создания кода подтверждения
	const SQL_CREATE_CODE = `
    INSERT INTO account_verifications (email, verification_code)
    VALUES ($1, $2)
    ON CONFLICT ON CONSTRAINT unique_email DO UPDATE
    SET verification_code = EXCLUDED.verification_code;
    `

	// Выполняем запрос на вставку или обновление кода подтверждения
	result, err := repository.db.Exec(ctx, SQL_CREATE_CODE, email, code)
	if err != nil {
		// Возвращаем ошибку, включающую детальную информацию о причине сбоя
		return fmt.Errorf("ошибка при создании кода подтверждения: %w", err)
	}

	// Проверяем число затронутых строк (опционально)
	rowsAffected := result.RowsAffected()
	if rowsAffected <= 0 {
		return fmt.Errorf("не удалось обновить или создать код подтверждения для email '%s'", email)
	}

	// Успешное выполнение операции
	return nil
}

// CreateHashPass создает Argon2-хэш пароля с заданной солью.
// plainPassword - обычный текст пароля
// salt - уникальная соль для хэширования
// return - массив байтов, содержащий сначала соль, затем хэшированный пароль
func (repository *UserRepository) CreateHashPass(plainPassword, salt string) ([]byte, error) {
	// Генерация хэша с использованием argon2
	hashBytes := argon2.IDKey([]byte(plainPassword), []byte(salt), 1, 64*1024, 4, 32)

	// Объединяем соль и хэшированный пароль в один срез байтов
	finalHash := make([]byte, len(salt)+len(hashBytes))
	copy(finalHash[:len(salt)], []byte(salt))
	copy(finalHash[len(salt):], hashBytes)

	return finalHash, nil
}

// CreateUser создает нового пользователя в репозитории пользователей.
// Функция принимает контекст выполнения операции, имя, фамилию,
// имя пользователя, электронную почту и пароль нового пользователя.
//
// Если данные некорректны или пользователь с такими именем или электронной
// почтой уже существует, возвращается ошибка проверки данных.
// Возвращается созданный объект User и возможная ошибка выполнения операции.
func (repository *UserRepository) CreateUser(
	ctx context.Context,
	firstname, lastname, username, email, password string,
) (*User, error) {
	// Проверяем правильность переданных данных
	if err := InputDataControl(firstname, lastname, username, email, password); err != nil {
		return nil, fmt.Errorf("некорректные входные данные: %w", err)
	}

	// Проверяем наличие такого пользователя в базе данных
	exists, err := repository.CheckUserExists(ctx, username, email)
	if err != nil {
		return nil, fmt.Errorf("ошибка при проверке наличия пользователя: %w", err)
	}

	if exists {
		return nil, errors.New("пользователь с указанным именем или e-mail уже существует")
	}

	// Создаем новый объект пользователя
	var uid int64
	user := &User{}

	// Выполняем запрос на создание пользователя в БД
	err = repository.db.QueryRow(ctx, SQL_CREATE_USER, firstname, lastname, username, email, password).Scan(&uid)
	if err != nil {
		return nil, fmt.Errorf("ошибка при создании пользователя: %w", err)
	}

	// Устанавливаем ID и возвращаем заполненный объект пользователя
	user.ID = uid
	user.FirstName = &firstname
	user.LastName = &lastname
	user.Username = &username
	user.Email = email

	return user, nil
}

// deleteUserByID удаляет пользователя из базы данных по его идентификатору.
// Возвращает ошибку, если операция не удалась, или если пользователь не найден.
func (repository *UserRepository) deleteUserByID(userID int64) error {
	// Проверяем, что userID больше нуля, так как нецелесообразно пытаться удалить пользователя с некорректным ID.
	if userID <= 0 {
		return fmt.Errorf("недопустимый идентификатор пользователя: %d", userID)
	}

	// Сначала проверяем, существует ли пользователь с данным ID
	var exists bool
	err := repository.db.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", userID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("ошибка при проверке существования пользователя с ID %d: %w", userID, err)
	}

	// Если пользователь не существует, возвращаем ошибку
	if !exists {
		return fmt.Errorf("пользователь с ID %d не найден в базе данных", userID)
	}

	// Выполняем SQL-запрос на удаление пользователя с указанным идентификатором.
	_, err = repository.db.Exec(context.Background(), "DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		return fmt.Errorf("не удалось выполнить запрос на удаление пользователя с ID %d: %w", userID, err)
	}

	return nil // Успешное удаление
}

// deleteUserFiles удаляет файлы пользователя по его ID
// directory -- путь к директории пользователя
// Возвращает ошибку, если не удалось удалить файлы
func (repository *UserRepository) deleteUserFiles(userID int64) error {
	// Формируем полный путь к директории пользователя
	directory := filepath.Join("./uploads", fmt.Sprint(userID))

	// Пытаемся удалить всю директорию рекурсивно
	err := os.RemoveAll(directory)
	if err != nil {
		// Конкретизируем тип ошибки для лучшего анализа
		switch {
		case os.IsNotExist(err):
			return fmt.Errorf("директория пользователя с ID %d не найдена: %w", userID, err)
		case os.IsPermission(err):
			return fmt.Errorf("недостаточно прав для удаления директории пользователя с ID %d: %w", userID, err)
		default:
			return fmt.Errorf("не удалось удалить файлы пользователя с ID %d: %w", userID, err)
		}
	}

	return nil
}

// Метод fetchUsers возвращает список пользователей согласно заданным критериям фильтрации.
// Параметры метода:
//   - limit (int): максимальное количество записей на странице.
//   - offset (int): смещение от начала списка.
//   - proStr (string): значение поля "pro": "", "true" или "false".
//   - onlineStr (string): статус онлайн ("true").
//   - categories (string): категории пользователей (строка формата CSV).
//   - location (string): местоположение пользователя.
//
// Результат:
//   - slice типа []User с записями пользователей.
//   - общее количество пользователей по запросу.
//   - возможная ошибка выполнения.
func (repository *UserRepository) fetchUsers(limit, offset int, proStr, onlineStr, categories, location string) ([]User, int, error) {
	var proFilter string
	switch proStr {
	case "":
		break // Пустое значение не накладывает ограничения
	case "true":
		proFilter = "AND u.pro = true"
	case "false":
		proFilter = "AND u.pro = false"
	default:
		// Логика для случаев, когда передано неожиданное значение
	}

	var onlineFilter string
	if onlineStr == "true" {
		onlineFilter = "AND s.id IS NOT NULL" // Пользователи с активной сессией
	}

	var categoriesFilter string
	if categories != "" {
		categoryIDs := strings.Split(categories, ",") // Разбиваем строку категорий
		// Формируем условие SQL-запроса
		var sb strings.Builder
		sb.WriteString("AND us.category_id IN (")
		for i, id := range categoryIDs {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(id)
		}
		sb.WriteString(")")
		categoriesFilter = sb.String()
	}

	var locationFilter string
	if location != "" {
		locationFilter = fmt.Sprintf("AND u.location = '%s'", location) // Добавляем проверку по полю location
	}

	// Основной запрос на получение уникальных пользователей с применением фильтров
	query := fmt.Sprintf(`
        SELECT DISTINCT u.id, u.pro, u.type, u.username, u.avatar_url, u.first_name, u.last_name, u.bio, u.location
        FROM users u 
        LEFT JOIN sessions s ON u.id = s.user_id AND s.status = 'active'
        LEFT JOIN user_skills us ON u.id = us.user_id
        WHERE u.blacklisted = false AND u.type IN ('USER', 'BOT') %s %s %s %s 
        LIMIT $1 OFFSET $2`, proFilter, onlineFilter, categoriesFilter, locationFilter)

	rows, err := repository.db.Query(context.Background(), query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("ошибка выполнения запроса: %v", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Pro, &user.Type, &user.Username, &user.AvatarURL, &user.FirstName, &user.LastName, &user.Bio, &user.Location); err != nil {
			return nil, 0, fmt.Errorf("ошибка чтения строки пользователя: %v", err)
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ошибка во время итерации результатов: %v", err)
	}

	// Подсчет общего числа пользователей с теми же условиями фильтрации
	var count int
	countQuery := fmt.Sprintf(`
        SELECT COUNT(DISTINCT u.id)
        FROM users u 
        LEFT JOIN sessions s ON u.id = s.user_id AND s.status = 'active' 
        LEFT JOIN user_skills us ON u.id = us.user_id
        WHERE u.blacklisted = false AND u.type IN ('USER', 'BOT') %s %s %s %s`, proFilter, onlineFilter, categoriesFilter, locationFilter)

	err = repository.db.QueryRow(context.Background(), countQuery).Scan(&count)
	if err != nil {
		return nil, 0, fmt.Errorf("ошибка подсчета количества пользователей: %v", err)
	}

	return users, count, nil
}

// Получение пользователя по email
func (repository *UserRepository) FindUserByEmail(email string) (User, error) {
	var user User
	err := repository.db.QueryRow(context.Background(), "SELECT email FROM users WHERE email = $1", email).Scan(&user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			return User{}, fmt.Errorf("пользователь с email %s не найден", email)
		}
		return User{}, fmt.Errorf("ошибка при выполнении запроса: %v", err)
	}
	return user, nil
}

// GetArchiveMessages извлекает архив сообщений текущего пользователя, которые были прочитаны.
// Аргументы:
//   - currentUserId (int64): уникальный идентификатор текущего пользователя.
//
// Возвращаемые значения:
//   - []Message: срез сообщений архива.
//   - error: возможная ошибка выполнения.
func (repository *UserRepository) GetArchiveMessages(currentUserId int64) ([]Message, error) {
	rows, err := repository.db.Query(context.Background(),
		`
        SELECT 
            m.id, m.sender_id, m.content, m.created_at, m.is_read, 
            u.id AS user_id, u.username, u.avatar_url  
        FROM messages m 
        JOIN users u ON m.sender_id = u.id 
        WHERE m.recipient_id = $1 AND m.is_read = TRUE`,
		currentUserId)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var msg Message
		var user User

		if err := rows.Scan(&msg.ID, &msg.SenderID, &msg.Content, &msg.CreatedAt, &msg.IsRead, &user.ID, &user.Username, &user.AvatarURL); err != nil {
			continue // Пропускаем сообщение, если возникли проблемы со сканированием
		}
		msg.Sender = user // Связываем пользователя с сообщением
		messages = append(messages, msg)
	}

	return messages, nil
}

// GetByEmail ищет пользователя по адресу электронной почты.
// Возвращает найденного пользователя или ошибку, если пользователь не найден или произошел сбой.
func (repository *UserRepository) GetByEmail(ctx context.Context, Email string) (*User, error) {
	row := repository.db.QueryRow(ctx, SQL_READ_EMAIL_FOR_RESET_PWD, Email)
	return parseRowToUserReset(row)
}

// GetByID получает пользователя по уникальному идентификатору.
// Возвращает найденного пользователя или ошибку, если пользователь не найден или произошел сбой.
func (repository *UserRepository) GetByID(ctx context.Context, id int64) (*User, error) {
	row := repository.db.QueryRow(ctx, SQL_READ_USER, id)
	return parseRowToUser(row)
}

// GetByLogin находит пользователя по имени входа (login).
// Возвращает найденного пользователя или ошибку, если пользователь не найден или произошел сбой.
func (repository *UserRepository) GetByLogin(ctx context.Context, login string) (*User, error) {
	row := repository.db.QueryRow(ctx, SQL_GET_USERNAME, login)
	return parseRowToUser(row)
}

// GetByName выбирает пользователя по имени пользователя (username).
// Возвращает найденного пользователя или ошибку, если пользователь не найден или произошел сбой.
func (repository *UserRepository) GetByName(ctx context.Context, username string) (*User, error) {
	row := repository.db.QueryRow(ctx, SQL_READ_USERNAME, username)
	return parseRowToUser(row)
}

// Функция для получения информации о компании из базы данных
func (repository *UserRepository) getCompanyInfo() (Company, error) {
	var company Company
	err := repository.db.QueryRow(context.Background(), "SELECT id, name, logo_url, website_url, last_updated FROM company LIMIT 1").Scan(&company.ID, &company.Name, &company.LogoURL, &company.WebsiteURL, &company.LastUpdated)
	return company, err
}

// getEmailByUserID получает email пользователя по его идентификатору
// userID - уникальный идентификатор пользователя
// Возвращает email пользователя или ошибку, если таковой не найден или произошли технические трудности
func (repository *UserRepository) getEmailByUserID(ctx context.Context, userID int64) (string, error) {
	// Подготовим переменную для хранения результата
	var email string

	// SQL-запрос для получения email пользователя по его ID
	query := "SELECT email FROM users WHERE id = $1 LIMIT 1;"

	// Выполняем запрос и записываем результат в переменную
	err := repository.db.QueryRow(ctx, query, userID).Scan(&email)
	if err != nil {
		// Отлавливаем случай, когда пользователь не найден
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("пользователь с идентификатором %d не найден", userID)
		}

		// В остальных случаях сообщаем о технической ошибке
		return "", fmt.Errorf("ошибка при попытке получить email пользователя с идентификатором %d: %w", userID, err)
	}

	// Результат успешно получен, возвращаем email
	return email, nil
}

// getExportDate возвращает дату последнего экспорта данных пользователя
// userID - идентификатор пользователя
// Возвращает время последней выгрузки данных или ошибку, если возникли проблемы
func (repository *UserRepository) getExportDate(ctx context.Context, userID int64) (time.Time, error) {
	// Переменная для хранения даты экспорта
	var exportDate time.Time

	// SQL-запрос для получения даты последнего экспорта
	query := "SELECT export_date FROM exports WHERE user_id = $1 LIMIT 1;"

	// Выполняем запрос и пытаемся записать результат
	err := repository.db.QueryRow(ctx, query, userID).Scan(&exportDate)
	if err != nil {
		// Случай, когда данных нет
		if err == sql.ErrNoRows {
			return time.Time{}, fmt.Errorf("экспорт данных для пользователя с идентификатором %d не обнаружен", userID)
		}

		// Другие ошибки запроса
		return time.Time{}, fmt.Errorf("ошибка при попытке получить дату экспорта для пользователя с идентификатором %d: %w", userID, err)
	}

	// Данные получены успешно
	return exportDate, nil
}

// GetNewMessages возвращает список новых сообщений для указанного пользователя
// currentUserId - идентификатор пользователя, чьи новые сообщения надо вернуть
// Возвращает набор сообщений и ошибку, если таковая имеется
func (repository *UserRepository) GetNewMessages(currentUserId int64) ([]Message, error) {
	// SQL-запрос для получения новых сообщений
	query := `
        SELECT 
            m.id, m.sender_id, m.content, m.created_at, m.is_read, 
            u.id AS user_id, u.username, u.avatar_url  
        FROM messages m 
        JOIN users u ON m.sender_id = u.id 
        WHERE m.recipient_id = $1 AND m.is_read = FALSE
        ORDER BY m.created_at ASC
    `

	// Выполняем запрос к базе данных
	rows, err := repository.db.Query(context.Background(), query, currentUserId)
	if err != nil {
		return nil, fmt.Errorf("ошибка при выполнении запроса к базе данных: %w", err)
	}
	defer rows.Close() // Гарантированно закроем ресурсы после окончания работы

	// Сборка списка сообщений
	var messages []Message
	for rows.Next() {
		var msg Message
		var user User

		// Сканируем полученные данные
		if err := rows.Scan(&msg.ID, &msg.SenderID, &msg.Content, &msg.CreatedAt, &msg.IsRead, &user.ID, &user.Username, &user.AvatarURL); err != nil {
			return nil, fmt.Errorf("ошибка при разборе данных сообщения: %w", err)
		}

		// Связываем отправителя с сообщением
		msg.Sender = user
		messages = append(messages, msg)
	}

	// Проверка наличия ошибок при разрыве соединения с базой данных
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при закрытии соединений: %w", err)
	}

	return messages, nil
}

// getSessionByID ищет пользователя по идентификатору сессии
// sessionID - идентификатор сессии
// Возвращает идентификатор пользователя и ошибку, если сессия не найдена или произошла ошибка
func (repository *UserRepository) getSessionByID(ctx context.Context, sessionID string) (int64, error) {
	var userID int64

	// SQL-запрос для получения идентификатора пользователя по идентификатору сессии
	query := "SELECT user_id FROM sessions WHERE id = $1"

	// Выполняем запрос к базе данных
	err := repository.db.QueryRow(ctx, query, sessionID).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("сессия с идентификатором %s не найдена", sessionID)
		}
		return 0, fmt.Errorf("ошибка при выполнении запроса: %w", err)
	}

	return userID, nil
}

// getSessionsByUserID загружает активные сеансы для пользователя по его идентификатору
// userID - идентификатор пользователя
// Возвращает набор активных сеансов и ошибку, если возникла проблема при выборе данных
func (repository *UserRepository) getSessionsByUserID(ctx context.Context, userID int64) ([]session.Session, error) {
	// SQL-запрос для загрузки активных сеансов пользователя
	query := `
        SELECT id, ip, browser, operating_system, created_at, first_login
        FROM sessions
        WHERE user_id = $1
        ORDER BY created_at DESC
    `

	// Выполняем запрос к базе данных
	rows, err := repository.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("ошибка при загрузке сеансов пользователя с идентификатором %d: %w", userID, err)
	}
	defer rows.Close() // гарантированное освобождение ресурсов

	// Собираем список сеансов
	var sessions []session.Session
	for rows.Next() {
		var sess session.Session
		if err := rows.Scan(&sess.ID, &sess.IP, &sess.Browser, &sess.OperatingSystem, &sess.CreatedAt, &sess.FirstLogin); err != nil {
			return nil, fmt.Errorf("ошибка при разбора данных о сеансах пользователя с идентификатором %d: %w", userID, err)
		}
		sessions = append(sessions, sess)
	}

	// Проверяем, не случилось ли ошибок после закрытия cursor'a
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при завершении выборки данных о сеансах пользователя с идентификатором %d: %w", userID, err)
	}

	return sessions, nil
}

// GetUserCategories возвращает список категорий пользователя по его идентификатору.
// Метод работает следующим образом:
// 1. Получаются идентификаторы категорий пользователя из таблицы user_skills.
// 2. После этого выполняется запрос для получения полных данных категорий из таблицы categories.
// Если пользователь не привязан ни к одной категории, возвращается пустой срез.
// В случае любых ошибок при получении данных формируются соответствующие информационные сообщения.
//
// Параметры:
//
//	userId (int) - Идентификатор пользователя.
//
// Возвращает:
//
//	[]CategoryResponse - Список категорий пользователя.
//	error - Ошибка выполнения запроса, если такая имеется.
func (repo *UserRepository) GetUserCategories(userId int) ([]CategoryResponse, error) {
	// Шаг 1: получаем идентификаторы категорий пользователя
	categoryIDsQuery := `
        SELECT category_id FROM user_skills WHERE user_id = $1;
    `

	rows, err := repo.db.Query(context.Background(), categoryIDsQuery, userId)
	if err != nil {
		return nil, fmt.Errorf("ошибка выполнения запроса к таблице user_skills: %v", err)
	}
	defer rows.Close()

	var categoryIDs []int
	for rows.Next() {
		var categoryID int
		if err := rows.Scan(&categoryID); err != nil {
			return nil, fmt.Errorf("ошибка считывания id категории: %v", err)
		}
		categoryIDs = append(categoryIDs, categoryID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка после завершения чтения строк: %v", err)
	}

	// Если categoryIDs пуст, возвращаем пустой массив категорий
	if len(categoryIDs) == 0 {
		return []CategoryResponse{}, nil
	}

	// Шаг 2: получаем полные данные категорий по их идентификаторам
	categoryNamesQuery := `
        SELECT id, name FROM categories WHERE id = ANY($1);
    `

	categoryRows, err := repo.db.Query(context.Background(), categoryNamesQuery, categoryIDs)
	if err != nil {
		return nil, fmt.Errorf("ошибка выполнения запроса к таблице categories: %v", err)
	}
	defer categoryRows.Close()

	var categories []CategoryResponse
	for categoryRows.Next() {
		var category CategoryResponse
		if err := categoryRows.Scan(&category.ID, &category.Name); err != nil {
			return nil, fmt.Errorf("ошибка считывания названия категории: %v", err)
		}
		categories = append(categories, category)
	}

	if err := categoryRows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка после завершения чтения строк: %v", err)
	}

	return categories, nil
}

func (repository *UserRepository) getUserData(ctx context.Context, userID int64) (User, error) {
	var user User
	query := `
SELECT username, pro, type, created_at FROM users WHERE id = $1;`

	row := repository.db.QueryRow(ctx, query, userID)
	err := row.Scan(
		&user.Username, &user.Pro, &user.Type, &user.CreatedAt,
	)

	// Обработка ошибки при извлечении данных
	if err != nil {
		if err == pgx.ErrNoRows {
			// Специальная обработка ситуации, когда пользователь не найден
			return user, fmt.Errorf("пользователь с идентификатором %d не найден", userID)
		}

		// Обработка общих ошибок
		return user, fmt.Errorf("ошибка при сканировании данных пользователя с идентификатором %d: %w", userID, err)
	}

	return user, nil
}

// GetUserProfile извлекает информацию о пользователе и количество его подписок.
// userId - ID профиля пользователя, который нужно получить.
// currentUserId - ID текущего пользователя для проверки подписок.
// Возвращает профиль пользователя, количество подписок и ошибку (если есть).
func (repository *UserRepository) GetUserProfile(userId int64, currentUserId int64) (User, int64, error) {
	var profile User // Структура для хранения профиля пользователя

	// Запрос для извлечения данных профиля пользователя
	err := repository.db.QueryRow(context.Background(),
		"SELECT id, ver, blacklisted, sex, followers_count, verified, no_ads, can_upload_shot, pro, type, first_name, last_name, middle_name, username, password_hash, bdate, phone, email, html_url, avatar_url, bio, location, created_at, updated_at FROM users WHERE id = $1", userId).
		Scan(&profile.ID, &profile.Version, &profile.Blacklisted, &profile.Sex, &profile.FollowersCount, &profile.Verified, &profile.NoAds, &profile.CanUploadShot, &profile.Pro, &profile.Type, &profile.FirstName, &profile.LastName, &profile.MiddleName, &profile.Username, &profile.PasswordHash, &profile.Bdate, &profile.Phone, &profile.Email, &profile.HTMLURL, &profile.AvatarURL, &profile.Bio, &profile.Location, &profile.CreatedAt, &profile.UpdatedAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			return profile, 0, fmt.Errorf("пользователь с id %d не найден", userId)
		}

		return profile, 0, err
	}

	// Проверка подписки текущего пользователя на запрашиваемого пользователя
	err = repository.db.QueryRow(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM subscriptions WHERE follower_id = $1 AND followed_id = $2)",
		currentUserId, userId).Scan(&profile.IsFollowing)

	if err != nil {

		return profile, 0, err
	}

	// Получение общего количества подписчиков
	err = repository.db.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM subscriptions WHERE followed_id = $1",
		userId).Scan(&profile.FollowersCount)

	if err != nil {

		return profile, 0, err
	}

	// Получаем количество подписок текущего пользователя
	var subscriptionsCount int64
	err = repository.db.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM subscriptions WHERE follower_id = $1",
		userId).Scan(&subscriptionsCount)

	if err != nil {

		return profile, 0, err
	}

	return profile, subscriptionsCount, nil
}

// GetUserSkills получает все навыки пользователя по его идентификатору.
func (repository *UserRepository) GetUserSkills(userID int64) ([]Skill, error) {
	rows, err := repository.db.Query(context.Background(), `
        SELECT category_id, id 
        FROM user_skills 
        WHERE user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("ошибка получения навыков пользователя: %v", err)
	}
	defer rows.Close()

	var skills []Skill // Используем тип Skill здесь

	for rows.Next() {
		var skill Skill
		if err := rows.Scan(&skill.CategoryID, &skill.SkillID); err != nil {
			return nil, fmt.Errorf("ошибка сканирования навыка: %v", err)
		}
		// Если у пользователя нет навыков, мы устанавливаем пустой массив
		if skills == nil {
			skills = []Skill{} // Инициализируем пустой массив навыков
		}
		skills = append(skills, skill) // Добавляем навык в массив
	}

	// Проверка на ошибки из rows
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при итерации по результатам: %v", err)
	}

	return skills, nil
}

// GetWorkPreferences получает рабочие предпочтения пользователя из базы данных.
func (repository *UserRepository) GetWorkPreferences(ctx context.Context, userId int64) (*WorkPreferences, error) {
	var wp WorkPreferences
	row := repository.db.QueryRow(ctx, `
		SELECT id, user_id, availability, location, specialties, skills 
		FROM user_work_preferences WHERE user_id = $1`, userId)

	var specialtiesJSON, skillsJSON []byte
	err := row.Scan(&wp.UserID, &wp.UserID, &wp.Availability, &wp.Location, &specialtiesJSON, &skillsJSON)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil // Если нет записей, возвращаем nil
		}
		return nil, fmt.Errorf("не удалось получить рабочие предпочтения: %v", err)
	}

	// Преобразование JSONB в массивы строк
	if err := json.Unmarshal(specialtiesJSON, &wp.Specializations); err != nil {
		return nil, fmt.Errorf("не удалось преобразовать специальности из JSON: %v", err)
	}

	if err := json.Unmarshal(skillsJSON, &wp.Skills); err != nil {
		return nil, fmt.Errorf("не удалось преобразовать навыки из JSON: %v", err)
	}

	return &wp, nil
}

// isBlocked - функция проверки, заблокирован ли пользователь
// blockerID - ID пользователя, который может блокировать
// blockedID - ID пользователя, которого проверяем, заблокирован ли он
// Возвращает true, если пользователь заблокирован, и ошибку, если что-то пошло не так.
func (repository *UserRepository) isBlocked(blockerID, blockedID int64) (bool, error) {
	var exists bool

	// Выполнение SQL-запроса для проверки существования блокировки
	err := repository.db.QueryRow(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2)",
		blockerID, blockedID).Scan(&exists)

	// Обработка ошибок, которые могут возникнуть при выполнении запроса
	if err != nil {
		// Если ошибка связана с базой данных (например, соединение недоступно),
		// формируем и возвращаем соответствующее сообщение об ошибке.
		return false, fmt.Errorf("ошибка проверки блокировки пользователя: %v", err)
	}

	// Возвращаем результат проверки блокировки и nil в качестве ошибки
	return exists, nil
}

func (repository *UserRepository) isFollowing(followerId, followedId int64) (bool, error) {
	var exists bool
	err := repository.db.QueryRow(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM subscriptions WHERE follower_id = $1 AND followed_id = $2)",
		followerId, followedId).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("ошибка проверки блокировки пользователя: %v", err)
	}
	return exists, nil
}

// isUniqueViolation проверяет, является ли ошибка нарушением уникальности.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if ok := errors.As(err, &pgErr); ok {
		// Проверяем код ошибки для нарушения уникальности
		return pgErr.Code == "23505" // Код ошибки для уникальности в PostgreSQL
	}
	return false
}

// passwordIsValidEmail проверяет пароль пользователя по адресу электронной почты.
// В случае успеха возвращает найденного пользователя, иначе возвращает ошибку.
// Не раскрывает подробности о типе ошибки для защиты от атак методом перебора.
func (repository *UserRepository) passwordIsValidEmail(pass string, row pgx.Row) (*User, error) {
	// Структура для хранения пользователя
	var user User

	// Читаем данные из строки результата
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Version, &user.PasswordHash)
	if err != nil {
		// Независимо от конкретной причины ошибки, возвращаем обобщённую ошибку
		return nil, ErrInvalidCredentials
	}

	// Проверяем пароль с использованием метода comparePasswordAndHash
	match, err := ComparePasswordAndHash(pass, user.PasswordHash)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if !match {
		// Неправильный пароль
		return nil, ErrInvalidCredentials
	}

	return &user, nil
}

// Define custom error type to hide details from attackers
var ErrInvalidCredentials = errors.New("неверные учетные данные")

// ComparePasswordAndHash проверяет соответствие открытого пароля и его хэша
// pass - пароль в открытом виде
// hash - хэшированный пароль из базы данных
// Возвращает true, если пароль совпадает, иначе false
func ComparePasswordAndHash(pass, hash string) (bool, error) {
	// Реализуйте ваш любимый алгоритм сравнения паролей
	// Например, bcrypt.CompareHashAndPassword или другой подходящий инструмент
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
	if err != nil {
		return false, err
	}
	return true, nil
}

func (repository *UserRepository) passwordIsValid(pass string, row pgx.Row) (*User, error) {
	// Подготавливаем объект пользователя
	var user User

	// Выполняем Scan для считывания данных из строки
	err := row.Scan(&user.ID, &user.Username, &user.Version, &user.PasswordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("пользователь не найден") // Легче читать и понимать ошибку
		}
		return nil, fmt.Errorf("ошибка при сканировании данных пользователя: %w", err)
	}

	// Проверяем пароль с помощью bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(pass))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return nil, errors.New("неправильный пароль")
		}
		return nil, fmt.Errorf("ошибка при проверке пароля: %w", err)
	}

	return &user, nil
}

// ReadVerificationCode извлекает проверочный код по адресу электронной почты
// email - электронный адрес пользователя
// Возвращает VerifyCode или ошибку, если произошел сбой
func (repository *UserRepository) ReadVerificationCode(ctx context.Context, email string) (*VerifyCode, error) {
	// Готовим объект для хранения результата
	code := &VerifyCode{}

	// SQL-запрос для получения проверочного кода
	query := `
        SELECT id, email, code
        FROM verify_codes
        WHERE email = $1
        LIMIT 1
    `

	// Выполняем запрос к базе данных
	err := repository.db.QueryRow(ctx, query, email).Scan(&code.ID, &code.Email, &code.Code)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("проверочный код для электронного адреса %s не найден", email)
		}
		return nil, fmt.Errorf("ошибка при получении проверочного кода: %w", err)
	}

	return code, nil
}

// Функция для сохранения информации о компании
func (repository *UserRepository) saveCompanyInfo(name, logoURL, websiteURL string) error {
	// Попробуйте обновить существующую информацию о компании
	_, err := repository.db.Exec(context.Background(), "INSERT INTO company (name, logo_url, website_url, last_updated) VALUES ($1, $2, $3, CURRENT_TIMESTAMP) ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, logo_url = EXCLUDED.logo_url, website_url = EXCLUDED.website_url, last_updated = CURRENT_TIMESTAMP", name, logoURL, websiteURL)
	return err
}

func (repository *UserRepository) SaveWorkPreferences(ctx context.Context, wp WorkPreferences) error {
	if wp.UserID <= 0 {
		return fmt.Errorf("недопустимый идентификатор пользователя")
	}
	if wp.Availability == "" || wp.Location == "" {
		return fmt.Errorf("доступность и местоположение не могут быть пустыми")
	}

	_, err := repository.db.Exec(ctx, `
        INSERT INTO user_work_preferences (user_id, availability, location, specialties, skills)
        VALUES ($1, $2, $3, $4::jsonb, $5::jsonb)
        ON CONFLICT (user_id) DO UPDATE SET 
        availability = EXCLUDED.availability,
        location = EXCLUDED.location,
        specialties = COALESCE(EXCLUDED.specialties, user_work_preferences.specialties),
        skills = COALESCE(EXCLUDED.skills, user_work_preferences.skills)`,
		wp.UserID, wp.Availability, wp.Location, wp.Specializations, wp.Skills,
	)

	if err != nil {
		return fmt.Errorf("не удалось сохранить рабочие предпочтения: %w", err)
	}

	return nil
}

// sendMessage вставляет новое сообщение в базу данных
// senderId - идентификатор отправителя
// recipientId - идентификатор получателя
// message - содержимое сообщения
// Возвращает ошибку, если сообщение слишком длинное или возникла ошибка базы данных
func (repository *UserRepository) SendMessage(ctx context.Context, senderId, recipientId int64, message string) error {
	// Проверка длины сообщения
	if len(message) > 500 {
		return fmt.Errorf("сообщение слишком длинное (длина:= %d символов)", len(message))
	}

	// Подготовка SQL-запроса для вставки сообщения
	insertQuery := `
        INSERT INTO messages (sender_id, recipient_id, content)
        VALUES ($1, $2, $3)
    `

	// Выполнение запроса к базе данных
	_, err := repository.db.Exec(ctx, insertQuery, senderId, recipientId, message)
	if err != nil {
		return fmt.Errorf("ошибка при сохранении сообщения: %w", err)
	}

	return nil
}

// DeleteUserServices удаляет все услуги пользователя по его ID.
// Возвращает ошибку, если не удалось выполнить запрос к базе данных.
func (repository *UserRepository) DeleteUserServices(ctx context.Context, userID int64) error {
	// Выполняем SQL-запрос для удаления услуг пользователя из таблицы user_services
	result, err := repository.db.Exec(ctx, `DELETE FROM user_services WHERE user_id = $1`, userID)
	if err != nil {
		// Возвращаем ошибку с дополнительной информацией о неудачном запросе
		return fmt.Errorf("ошибка удаления услуг пользователя с ID %d: %v", userID, err)
	}

	// Проверяем количество затронутых строк
	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		// Если не было удалено ни одной строки, это может означать, что пользователь не имел услуг
		return fmt.Errorf("услуги для пользователя с ID %d не найдены", userID)
	}

	return nil // Успешное завершение функции без ошибок
}

// InsertUserServices добавляет новые услуги пользователя в базу данных.
// Принимает список объектов UserService и контекст выполнения операции.
// Возвращает список идентификаторов вновь созданных записей услуг и возможную ошибку.
// Метод также удаляет существующие услуги пользователя перед добавлением новых.
func (repository *UserRepository) InsertUserServices(ctx context.Context, userServices []UserService) ([]int64, error) {
	var newIDs []int64

	// Проверяем, есть ли хотя бы одна услуга для добавления
	if len(userServices) == 0 {
		return newIDs, nil // Если список пуст, ничего не добавляем
	}

	// Берём первый элемент массива для извлечения userID
	userID := userServices[0].UserID

	// Начало транзакции для безопасного выполнения операций
	tx, err := repository.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("ошибка начала транзакции: %w", err)
	}

	// Откат транзакции в случае ошибки
	defer func() {
		if p := recover(); p != nil { // Если произошла паника, выполняем откат
			_ = tx.Rollback(ctx)
			panic(p) // Повторно поднимаем панику после отката
		}
		if err != nil { // Если была обнаружена ошибка, выполняем откат
			rollbackErr := tx.Rollback(ctx)
			if rollbackErr != nil {
				err = fmt.Errorf("%w, rollback error: %v", err, rollbackErr)
			}
		} else { // Иначе фиксируем изменения
			commitErr := tx.Commit(ctx)
			if commitErr != nil {
				err = fmt.Errorf("ошибка фиксации изменений: %w", commitErr)
			}
		}
	}()

	// Сначала удаляем старые услуги пользователя
	if _, err = tx.Exec(ctx, `
        DELETE FROM user_services WHERE user_id = $1
    `, userID); err != nil {
		return nil, fmt.Errorf("ошибка удаления существующих услуг пользователя с ID %d: %w", userID, err)
	}

	// Далее последовательно вставляем каждую услугу
	for _, service := range userServices {
		var newID int64

		// Вставка новой услуги
		err = tx.QueryRow(ctx, `
            INSERT INTO user_services (user_id, category_id, subcategory_ids, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
        `, service.UserID, service.CategoryID, service.SubcategoryIDs, service.CreatedAt, service.UpdatedAt).
			Scan(&newID)

		if err != nil {
			return nil, fmt.Errorf("ошибка вставки услуги для пользователя с ID %d: %w", service.UserID, err)
		}

		// Добавляем полученный ID в результирующий список
		newIDs = append(newIDs, newID)
	}

	return newIDs, nil
}

// fetchUserServices извлекает услуги пользователя по его ID из базы данных.
// Возвращает список UserService и ошибку, если что-то пошло не так.
func (repository *UserRepository) fetchUserServices(userID int64) ([]UserService, error) {
	ctx := context.Background() // Создаем контекст для выполнения запроса

	// Выполняем SQL-запрос для получения услуг пользователя
	rows, err := repository.db.Query(ctx,
		`SELECT us.id,
				us.user_id,
				us.category_id,
				c.name AS category_name,
				us.subcategory_ids
		 FROM user_services us
		 JOIN categories c ON us.category_id = c.id
		 WHERE us.user_id = $1
		 ORDER BY c.id`, userID)

	if err != nil {
		return nil, fmt.Errorf("ошибка выполнения запроса: %v", err) // Возвращаем ошибку с дополнительной информацией
	}
	defer rows.Close() // Закрываем rows после завершения работы с ними

	var userServices []UserService // Список для хранения услуг пользователя

	// Перебираем строки результата запроса
	for rows.Next() {
		var userService UserService

		var subcategoryIDs pq.Int64Array // Используем pq.Int64Array для работы с массивом подкатегорий
		if err = rows.Scan(&userService.ID, &userService.UserID, &userService.CategoryID, &userService.CategoryName, &subcategoryIDs); err != nil {
			return nil, fmt.Errorf("ошибка сканирования строки: %v", err) // Возвращаем ошибку при сканировании строки
		}

		userService.SubcategoryIDs = subcategoryIDs // Присваиваем массив подкатегорий в структуру UserService

		userServices = append(userServices, userService) // Добавляем услугу в список
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при переборе строк: %v", err) // Проверяем на наличие ошибок после перебора строк
	}

	return userServices, nil // Возвращаем список услуг пользователя и nil как ошибку (успешное выполнение)
}

// GetAllCategoriesAndSubcategories извлекает все категории и подкатегории услуг пользователя по его ID.
// Возвращает UserSpecialtyResponse и ошибку, если что-то пошло не так.
func (repository *UserRepository) GetAllCategoriesAndSubcategories(userID int64) (UserSpecialtyResponse, error) {
	// Получаем услуги пользователя
	userServices, err := repository.fetchUserServices(userID)
	if err != nil {
		return UserSpecialtyResponse{}, fmt.Errorf("ошибка получения услуг пользователя: %v", err)
	}

	// Инициализируем ответ
	response := UserSpecialtyResponse{
		UserID:       userID,
		UserServices: []UserService{},
	}

	// Создаем карту для хранения уникальных категорий услуг
	categoryMap := make(map[int]UserService)

	// Обрабатываем услуги пользователя
	for _, userService := range userServices {
		if existingService, exists := categoryMap[userService.CategoryID]; exists {
			// Если категория уже существует, объединяем подкатегории
			existingService.SubcategoryIDs = append(existingService.SubcategoryIDs, userService.SubcategoryIDs...)
			categoryMap[userService.CategoryID] = existingService // Обновляем существующую запись
		} else {
			// Если категория не существует, добавляем новую услугу в карту
			categoryMap[userService.CategoryID] = userService
		}
	}

	// Переносим уникальные услуги из карты в ответ
	for _, service := range categoryMap {
		response.UserServices = append(response.UserServices, service)
	}

	return response, nil // Возвращаем сформированный ответ и nil как ошибку (успешное выполнение)
}

// RemoveSubcategoryFromUserService удаляет подкатегорию из услуг пользователя по его ID.
// Если после удаления подкатегории не осталось подкатегорий для категории, удаляет запись услуги.
func (repository *UserRepository) RemoveSubcategoryFromUserService(ctx context.Context, userID int64, subcategoryID int64) error {
	// Удаляем подкатегорию из user_services
	_, err := repository.db.Exec(ctx,
		`UPDATE user_services 
		 SET subcategory_ids = array_remove(subcategory_ids, $1)
		 WHERE user_id = $2 AND $1 = ANY(subcategory_ids)`,
		subcategoryID, userID)
	if err != nil {
		return fmt.Errorf("ошибка удаления подкатегории: %v", err) // Возвращаем ошибку с дополнительной информацией
	}

	// Проверяем, к какой категории принадлежит подкатегория
	var categoryID int64
	err = repository.db.QueryRow(ctx,
		`SELECT category_id FROM subcategories WHERE id = $1`, subcategoryID).Scan(&categoryID)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil // Подкатегория не найдена - это не ошибка
		}
		return fmt.Errorf("ошибка получения категории для подкатегории: %v", err) // Возвращаем ошибку при проблемах с запросом
	}

	// Проверяем наличие оставшихся подкатегорий для данной категории
	var count int64
	err = repository.db.QueryRow(ctx,
		`SELECT COUNT(*) 
		 FROM user_services us 
		 WHERE us.user_id = $1 AND us.category_id = $2 AND array_length(us.subcategory_ids, 1) > 0`, userID, categoryID).Scan(&count)

	if err != nil {
		return fmt.Errorf("ошибка проверки наличия подкатегорий: %v", err)
	}

	if count == 0 {
		_, err = repository.db.Exec(ctx,
			`DELETE FROM user_services WHERE user_id = $1 AND category_id = $2`, userID, categoryID)
		if err != nil {
			return fmt.Errorf("ошибка удаления записи из user_services: %v", err)
		}
	}

	return nil
}

// SubscribeUser добавляет запись о подписке в базу данных.
// В случае успеха возвращает nil, в противном случае возвращает ошибку.
func (repository *UserRepository) SubscribeUser(followerId, followedId int64, ctx context.Context) error {
	// Выполняем SQL-запрос на вставку подписки
	_, err := repository.db.Exec(ctx,
		"INSERT INTO subscriptions (follower_id, followed_id) VALUES ($1, $2)",
		followerId, followedId)

	// Проверяем на ошибки
	if err != nil {

		// Проверяем, является ли ошибка нарушением уникальности
		if isUniqueViolation(err) {
			return fmt.Errorf("подписка уже существует для follower_id: %d и followed_id: %d", followerId, followedId)
		}

		// Если ошибка другого рода, возвращаем её с контекстом
		return fmt.Errorf("не удалось добавить подписку: %w", err)
	}

	// Если вставка прошла успешно, возвращаем nil
	return nil
}

// unblockUser - функция для разблокировки пользователя
// принимает ID блокирующего пользователя и ID заблокированного пользователя.
// Возвращает ошибку, если операция не удалась.
func (repository *UserRepository) unblockUser(blockerID, blockedID int64) error {
	// Выполняем запрос на удаление записи из таблицы 'blocks'
	_, err := repository.db.Exec(context.Background(), "DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2", blockerID, blockedID)

	if err != nil {
		// Проверяем ошибку и обрабатываем различные ситуации
		if err == sql.ErrNoRows {
			// Если запись не найдена, возвращаем об этом ошибку
			return fmt.Errorf("пользователь с ID %d не был заблокирован пользователем с ID %d", blockedID, blockerID)
		} else if errors.Is(err, context.Canceled) {
			// Если контекст отменён, возвращаем ошибку
			return fmt.Errorf("операция была отменена: %w", err)
		} else if errors.Is(err, context.DeadlineExceeded) {
			// Если время выполнения запроса истекло
			return fmt.Errorf("время выполнения запроса истекло: %w", err)
		}
		// Если произошла другая ошибка, возвращаем её
		return fmt.Errorf("не удалось разблокировать пользователя: %w", err)
	}

	// Возвращаем nil, если операция прошла успешно
	return nil
}

// UnsubscribeUser удаляет подписку для указанного пользователя.
func (repository *UserRepository) UnsubscribeUser(currentUserId int64, followedId int64, ctx context.Context) error {
	// Проверяем, существует ли подписка
	var exists bool
	err := repository.db.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM subscriptions WHERE follower_id = $1 AND followed_id = $2)",
		currentUserId, followedId).Scan(&exists)

	// Обрабатываем возможные ошибки выполнения запроса
	if err != nil {

		return fmt.Errorf("не удалось проверить существование подписки: %w", err)
	}

	// Если подписка не существует, возвращаем соответствующую ошибку
	if !exists {
		return fmt.Errorf("подписка не найдена для пользователя с ID %d на пользователя с ID %d", currentUserId, followedId)
	}

	// Выполняем удаление подписки
	result, err := repository.db.Exec(ctx,
		"DELETE FROM subscriptions WHERE follower_id = $1 AND followed_id = $2",
		currentUserId, followedId)

	// Обрабатываем возможные ошибки выполнения запроса
	if err != nil {

		return fmt.Errorf("не удалось отменить подписку: %w", err)
	}

	// Проверяем количество затронутых строк
	if result.RowsAffected() == 0 {
		return fmt.Errorf("не удалось отменить подписку, возможно она уже была отменена")
	}

	return nil // Успешное завершение, подписка отменена
}

// UpdateEmail обновляет адрес электронной почты пользователя по его идентификатору.
// Возвращает ошибку, если что-то пошло не так.
func (repository *UserRepository) UpdateEmail(ctx context.Context, userID int64, userEmail string) error {
	// Здесь реализуйте логику обновления электронной почты в базе данных.
	// Например:
	_, err := repository.db.Exec(ctx, "UPDATE users SET email = $1 WHERE id = $2", userEmail, userID)
	return err
}

func (repository *UserRepository) updateExportDate(ctx context.Context, userID int64) error {
	query := `
		INSERT INTO exports (user_id, export_date)
		VALUES ($1, CURRENT_TIMESTAMP)
		ON CONFLICT (user_id) DO UPDATE SET export_date = CURRENT_TIMESTAMP;`

	// Выполняем запрос и обрабатываем ошибку
	if _, err := repository.db.Exec(ctx, query, userID); err != nil {
		return fmt.Errorf("ошибка при обновлении даты экспорта: %w", err)
	}

	return nil
}

// UpdateThePasswordInTheSettings обновляет пароль пользователя в базе данных.
// Возвращает ошибку, если что-то пошло не так.
func (repository *UserRepository) UpdateThePasswordInTheSettings(ctx context.Context, userID int64, newPassword string) error {
	// Проверяем переданные параметры на валидность
	// if err := validateUserInput(userID, newPassword); err != nil {
	// 	return fmt.Errorf("недопустимые входные данные: %w", err)
	// }

	var currentPasswordHash string
	// Получаем текущий пароль пользователя
	err := repository.db.QueryRow(ctx, "SELECT password_hash FROM users WHERE id = $1", userID).Scan(&currentPasswordHash)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("пользователь с ID %d не найден", userID)
		}
		return fmt.Errorf("ошибка при получении текущего пароля пользователя: %w", err)
	}

	// Проверяем, совпадает ли новый пароль со старым
	if err := comparePasswords(currentPasswordHash, newPassword); err != nil {
		return err
	}

	// Выполняем обновление пароля в базе данных
	var updatedID int64
	err = repository.db.QueryRow(ctx,
		"UPDATE users SET password_hash = crypt($1, gen_salt('bf')), ver = ver + 1 WHERE id = $2 RETURNING id",
		newPassword, userID).Scan(&updatedID)

	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("пользователь с ID %d не найден", userID)
		}
		return fmt.Errorf("ошибка обновления пароля в базе данных: %w", err)
	}

	return nil
}

// UpdateProfile обновляет данные профиля указанного пользователя.
func (repository *UserRepository) UpdateProfile(userID int64, firstName, lastName, middleName, location, bio string, noAds bool) error {
	// Обновляем данные в базе данных
	_, err := repository.db.Exec(context.Background(), `
		UPDATE users 
		SET first_name = $1, 
		    last_name = $2, 
		    middle_name = $3, 
		    location = $4, 
		    bio = $5, 
		    no_ads = $6, 
		    updated_at = CURRENT_TIMESTAMP 
		WHERE id = $7`,
		firstName, lastName, middleName, location, bio, noAds, userID)

	if err != nil {
		return fmt.Errorf("ошибка обновления профиля пользователя: %v", err)
	}

	return nil
}

// updateUserLinks обновляет ссылки пользователя в базе данных и кэширует их.
// Параметры:
//
//	ctx     - контекст выполнения операции
//	userID  - идентификатор пользователя
//	vk      - ссылка VK
//	telegram - ссылка Telegram
//	whatsapp - ссылка WhatsApp
//	web     - веб-сайт пользователя
//	twitter - ссылка Twitter
//
// Возвращаемое значение:
//
//	error - ошибка выполнения операции, если она возникает
func (repository *UserRepository) updateUserLinks(ctx context.Context, userID int64, vk, telegram, whatsapp, web, twitter string) error {
	// Собираем новую структуру ссылок
	links := UserLinks{
		VK:       vk,
		Telegram: telegram,
		WhatsApp: whatsapp,
		Web:      web,
		Twitter:  twitter,
	}

	// Кэшируем новые ссылки пользователя
	userLinksCache.Store(userID, links)

	// Обновляем данные в базе данных
	if _, err := repository.db.Exec(ctx,
		`UPDATE users SET links = $1 WHERE id = $2`,
		links,
		userID,
	); err != nil {
		return fmt.Errorf("ошибка обновления ссылок пользователя: %w", err)
	}

	return nil
}

// UpdateUserSkills обновляет навыки пользователя в базе данных.
func (repository *UserRepository) UpdateUserSkills(userID int64, skills []int) error {
	// Удаляем существующие навыки пользователя
	_, err := repository.db.Exec(context.Background(), `
        DELETE FROM user_skills 
        WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("ошибка удаления старых навыков пользователя: %v", err)
	}

	// Если навыков нет, ничего не добавляем
	if len(skills) == 0 {
		return nil
	}

	// Добавляем новые навыки пользователя с обработкой конфликта
	for _, skillID := range skills {
		_, err := repository.db.Exec(context.Background(), `
            INSERT INTO user_skills (user_id, category_id) 
            VALUES ($1, $2) 
            ON CONFLICT (user_id, category_id) DO NOTHING`, userID, skillID)
		if err != nil {
			return fmt.Errorf("ошибка добавления навыка пользователя: %v", err)
		}
	}

	return nil
}

// UpdateUser обновляет информацию о пользователе в базе данных.
func (repository *UserRepository) UpdateUser(ctx context.Context, userID int64, username *string, email string, noAds bool) error {
	// Проверка на наличие пользователя
	var exists bool
	err := repository.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)", userID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("ошибка при проверке существования пользователя: %w", err)
	}
	if !exists {
		return fmt.Errorf("пользователь с ID %d не найден", userID)
	}

	// Обновление данных пользователя
	if username != nil {
		// Учитываем случай, если username == nil
		_, err = repository.db.Exec(ctx, "UPDATE users SET username=$1, email=$2, no_ads=$3 WHERE id=$4",
			*username, email, noAds, userID)
	} else {
		_, err = repository.db.Exec(ctx, "UPDATE users SET email=$1, no_ads=$2 WHERE id=$3",
			email, noAds, userID)
	}

	if err != nil {
		return fmt.Errorf("ошибка при обновлении пользователя: %w", err)
	}

	return nil
}

// UserExists - функция для проверки существования пользователя по его ID
func (repository *UserRepository) UserExists(ctx context.Context, userID int64) (bool, error) {
	var exists bool
	err := repository.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", userID).Scan(&exists)
	if err != nil {
		// Обработка ошибки выполнения запроса
		return false, fmt.Errorf("ошибка проверки существования пользователя: %v", err)
	}
	return exists, nil
}

// Users возвращает список всех зарегистрированных пользователей
// Возвращает список пользователей и ошибку, если что-то пошло не так
func (repository *UserRepository) Users(ctx context.Context) ([]*User, error) {
	// Выполняем SQL-запрос с указанием конкретных полей
	query := `
        SELECT 
            id, ver, blacklisted, followers_count, sex, username, 
            first_name, last_name, middle_name, password_hash, location, bio, bdate, phone, email, avatar_url, 
            verified, no_ads, can_upload_shot, pro, created_at, updated_at
        FROM users
        ORDER BY random();
    `

	// Выполняем запрос
	rows, err := repository.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("ошибка выполнения запроса: %w", err)
	}
	defer rows.Close() // Освобождаем ресурсы после завершения работы

	// Резервируем память под пользователей
	var users []*User

	// Перебор всех строк результата
	for rows.Next() {
		// Создаем новый экземпляр пользователя
		user := &User{}

		// Сканируем каждую колонку в соответствующую структуру
		err := rows.Scan(
			&user.ID,
			&user.Version,
			&user.Blacklisted,
			&user.FollowersCount,
			&user.Sex,
			&user.Username,
			&user.FirstName,
			&user.LastName,
			&user.MiddleName,
			&user.PasswordHash,
			&user.Location,
			&user.Bio,
			&user.Bdate,
			&user.Phone,
			&user.Email,
			&user.AvatarURL,
			&user.Verified,
			&user.NoAds,
			&user.CanUploadShot,
			&user.Pro,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("ошибка при сканировании данных пользователя: %w", err)
		}

		// Добавляем пользователя в срез
		users = append(users, user)
	}

	// Проверяем, были ли ошибки при обходе
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при итерации по результатам: %w", err)
	}

	return users, nil
}

// Verified устанавливает статус верификации пользователя в true в базе данных по указанному email.
// Выполняет SQL-команду для обновления поля 'verified' пользователя, связанного с предоставленным адресом электронной почты.
// Возвращает ошибку, если выполнение команды SQL терпит неудачу.
func (repository *UserRepository) Verified(email string) error {
	// Проверка на нулевую ссылку на репозиторий
	if repository == nil {
		return fmt.Errorf("указатель на репозиторий равен нулю")
	}

	// Проверка на нулевое соединение с базой данных
	if repository.db == nil {
		return fmt.Errorf("соединение с базой данных равно нулю")
	}

	// Создание контекста для выполнения SQL-команды
	ctx := context.Background()

	// Выполнение SQL-команды для изменения статуса верификации
	_, err := repository.db.Exec(ctx, SQL_UPDATE_VERIFIED, email)

	// Проверка возникновения ошибки при выполнении команды
	if err != nil {
		// Форматирование и вывод ошибки
		errFmt := fmt.Errorf("не удалось обновить статус верификации: %v", err.Error())
		fmt.Println(errFmt.Error()) // Печать ошибки в консоль
		return errFmt
	}

	// Успешное завершение без ошибок
	return nil
}
package user

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

// validateUserInput проверяет правильность входных данных
// func validateUserInput(userID int64, newPassword string) error {
// 	if userID <= 0 {
// 		return fmt.Errorf("некорректный идентификатор пользователя %d", userID)
// 	}
// 	if newPassword == "" {
// 		return fmt.Errorf("новый пароль не может быть пустым")
// 	}
// 	// Здесь можно добавить проверки сложности пароля
// 	if err := validatePasswordStrength(newPassword); err != nil {
// 		return fmt.Errorf("пароль не соответствует требованиям безопасности: %w", err)
// 	}
// 	return nil
// }

// validatePasswordStrength проверяет, соответствует ли пароль требованиям безопасности.
// func validatePasswordStrength(password string) error {
// 	if len(password) < 8 {
// 		return fmt.Errorf("пароль должен содержать как минимум 8 символов")
// 	}

// 	hasLower := false   // Флаг для наличия строчной буквы
// 	hasUpper := false   // Флаг для наличия прописной буквы
// 	hasDigit := false   // Флаг для наличия цифры
// 	hasSpecial := false // Флаг для наличия специального символа

// 	// Проходим по каждому символу в пароле и устанавливаем соответствующие флаги
// 	for _, char := range password {
// 		switch {
// 		case unicode.IsLower(char):
// 			hasLower = true
// 		case unicode.IsUpper(char):
// 			hasUpper = true
// 		case unicode.IsDigit(char):
// 			hasDigit = true
// 		case unicode.IsPunct(char) || unicode.IsSymbol(char):
// 			hasSpecial = true
// 		}
// 	}

// 	// Проверяем все флаги и возвращаем соответствующие ошибки
// 	if !hasLower {
// 		return fmt.Errorf("пароль должен содержать как минимум одну строчную букву")
// 	}
// 	if !hasUpper {
// 		return fmt.Errorf("пароль должен содержать как минимум одну прописную букву")
// 	}
// 	if !hasDigit {
// 		return fmt.Errorf("пароль должен содержать как минимум одну цифру")
// 	}
// 	if !hasSpecial {
// 		return fmt.Errorf("пароль должен содержать как минимум один специальный символ")
// 	}

// 	return nil // Если все проверки прошли, возвращаем nil
// }

// validateEmail проверяет, соответствует ли адрес электронной почты стандарту.
// Возвращает ошибку, если адрес недопустим.
func validateEmail(email string) error {
	if !isValidEmailFormat(email) {
		return errors.New("недопустимый формат адреса электронной почты")
	}
	return nil
}

// uploadAvatar загружает аватар пользователя, проверяет наличие файла, его размер и сохраняет файл,
// обновляя соответствующий URL в базе данных.
func (uh *UserHandler) uploadAvatar(r *http.Request, userID int64) error {
	// Извлекаем файл аватара из запроса.
	file, header, err := r.FormFile("avatar")
	if err != nil {
		if err == http.ErrMissingFile {
			return nil // Если файл не загружен, возвращаем nil (возможно, это не ошибка)
		}
		return fmt.Errorf("ошибка при получении файла аватара: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			slog.Debug("Ошибка закрытия файла: %v", slog.Any("вот ошибка", cerr))
		}
	}()

	// Проверяем размер файла.
	if header.Size > 800*1024 { // Максимальный размер 800К
		return fmt.Errorf("размер аватара превышает допустимый предел в 800Кб")
	}

	// Получаем расширение файла аватара.
	ext := uh.getFileExtension(header.Filename)
	if ext == "" {
		return fmt.Errorf("неподдерживаемое расширение файла")
	}

	// Определяем путь для сохранения файла.
	avatarPath := fmt.Sprintf("../images/avatars/%d.%s", userID, ext)

	// Сохраняем файл аватара.
	if err := uh.saveFile(avatarPath, file); err != nil {
		return fmt.Errorf("ошибка при сохранении файла аватара: %w", err)
	}

	// Формируем URL для аватара.
	avatarURL := fmt.Sprintf("/images/avatars/%d.%s", userID, ext) // Доступный для пользователей URL

	// Обновляем URL в базе данных.
	if _, err := uh.UsersRepo.db.Exec(context.Background(), "UPDATE users SET avatar_url = $1 WHERE id = $2", avatarURL, userID); err != nil {
		return fmt.Errorf("ошибка при обновлении аватара пользователя с ID %d: %w", userID, err)
	}

	return nil // Возвращаем nil, если всё прошло успешно
}

// getFileExtension возвращает расширение файла из его имени.
// filename - имя файла, из которого извлекается расширение
// Возвращает расширение файла или пустую строку, если расширение не поддерживается
func (uh *UserHandler) getFileExtension(filename string) string {
	// Список разрешенных расширений
	allowedExtensions := map[string]bool{
		"jpg":  true,
		"jpeg": true,
		"png":  true,
		"gif":  true,
		"bmp":  true,
		"tiff": true,
		"webp": true,
		"svg":  true,
	}

	// Чистим имя файла от пути
	filename = filepath.Base(filename)

	// Получаем расширение файла
	ext := strings.ToLower(filepath.Ext(filename)[1:])

	// Проверяем разрешение расширения
	if allowedExtensions[ext] {
		return ext
	}

	return ""
}

// updateProfileData обновляет данные профиля указанного пользователя.
func (uh *UserHandler) updateProfileData(userID int64, update User) error {
	err := uh.UsersRepo.UpdateProfile(userID, *update.FirstName, *update.LastName, *update.MiddleName, *update.Location, *update.Bio, update.NoAds)
	return err
}

// sendEmail отправляет письмо с прикрепленным файлом
// to - адрес получателя
// fileName - имя файла для вложения
// Возвращает ошибку, если отправка не удалась
func sendEmail(to string, fileName string) error {
	// Настройки SMTP-сервера
	host := "smtp.example.com"
	port := 587
	username := "your_username"
	password := "your_password"

	// Настройка MIME-сообщения
	m := gomail.NewMessage()
	m.SetHeader("From", "youremail@example.com")
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Ваши экспортированные данные")
	m.SetBody("text/plain", "Ваши данные прикреплены в архиве.")

	// Присоединяем ZIP-файл
	m.Attach(fileName)

	// Настройка SMTP-дилер
	d := gomail.NewDialer(host, port, username, password)

	// Отправляем письмо
	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("ошибка отправки письма: %w", err)
	}

	return nil
}

// SendEmail отправляет письмо сброса пароля с использованием шаблона
// to - адрес получателя
// resetLink - ссылка для восстановления пароля
// Возвращает ошибку, если отправка не удалась
func (uh *UserHandler) SendEmail(to string, resetLink string) error {
	// Авторизационные данные
	from := "duginea@mail.ru"
	password := "L9BtgetNuRcPkWUvN9wz"
	subject := "Сброс пароля"

	// Загружаем HTML-шаблон из файла
	tmpl, err := template.ParseFiles("../website/email_template.html")
	if err != nil {
		return fmt.Errorf("ошибка при загрузке шаблона письма: %w", err)
	}

	// Подготавливаем данные для передачи в шаблон
	data := struct {
		ResetLink string
	}{
		ResetLink: resetLink,
	}

	// Используем bytes.Buffer для хранения тела письма
	var body bytes.Buffer
	err = tmpl.Execute(&body, data)
	if err != nil {
		return fmt.Errorf("ошибка при подготовке тела письма: %w", err)
	}

	// Составляем заголовки письма
	msg := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-version: 1.0;\r\n" +
		"Content-type: text/html; charset=UTF-8\r\n" +
		"\r\n" + body.String()

	// Устанавливаем параметры SMTP-сервера
	smtpServer := "smtp.mail.ru:587"
	auth := smtp.PlainAuth("", from, password, "smtp.mail.ru")

	// Отправляем письмо через TLS
	err = smtp.SendMail(smtpServer, auth, from, []string{to}, []byte(msg))
	if err != nil {
		return fmt.Errorf("ошибка отправки письма: %w", err)
	}

	return nil
}

// saveToJSON сохраняет данные пользователя в JSON-файл с отступами.
// data - структура данных пользователя
// filename - имя выходного файла
// Возвращает ошибку, если возникли проблемы с созданием файла или сериализацией данных
func saveToJSON(data User, filename string) error {
	// Открываем файл для записи
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("ошибка открытия файла %s: %w", filename, err)
	}
	defer func() {
		closeErr := file.Close()
		if closeErr != nil {
			slog.Debug("ошибка закрытия файла %s: %v", filename, closeErr)
		}
	}()

	// Настраиваем JSON-кодировщик с отступами
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	// Сериализуем данные
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("ошибка сериализации данных: %w", err)
	}

	return nil
}

// saveFile сохраняет файл по заданному пути.
// path - абсолютный путь к файлу
// file - читаемый объект (обычно http.File или аналогичный)
// Возвращает ошибку, если что-то пошло не так
func (uh *UserHandler) saveFile(path string, file io.Reader) error {
	// Проверяем существование целевой директории
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if mkdirErr := os.MkdirAll(dir, 0755); mkdirErr != nil {
			return fmt.Errorf("ошибка создания директории %s: %w", dir, mkdirErr)
		}
	}

	// Открываем файл для записи
	out, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("ошибка открытия файла %s: %w", path, err)
	}
	defer func() {
		closeErr := out.Close()
		if closeErr != nil {
			slog.Debug("Ошибка закрытия файла %s: %v", path, closeErr)
		}
	}()

	// Копируем данные из входящего файла в выходной
	written, copyErr := io.Copy(out, file)
	if copyErr != nil {
		return fmt.Errorf("ошибка копирования данных в файл %s (%d байт скопировано): %w", path, written, copyErr)
	}

	return nil
}

// parseRowToUser считывает данные из строки базы данных и заполняет структуру User.
func parseRowToUser(row pgx.Row) (*User, error) {
	user := &User{}

	// Пытаемся сканировать данные из строки
	err := row.Scan(
		&user.ID,
		&user.Version,
		&user.Blacklisted,
		&user.Sex,
		&user.FollowersCount, // Считывание количества подписчиков
		&user.Verified,
		&user.NoAds,
		&user.CanUploadShot, // Убедитесь, что это поле существует в базе данных
		&user.Pro,
		&user.Type, // Считывание типа пользователя
		&user.FirstName,
		&user.LastName,
		&user.MiddleName,
		&user.Username,
		&user.PasswordHash, // Считывание хэша пароля
		&user.Bdate,
		&user.Phone,
		&user.Email,
		&user.HTMLURL, // Считывание HTML URL
		&user.AvatarURL,
		&user.Bio,
		&user.Location,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	// Если не удалось найти пользователя, возвращаем nil, nil
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	// Обрабатываем все другие ошибки
	// if err != nil {
	// 	return nil, fmt.Errorf("ошибка сканирования строки пользователя: %w", err)
	// }

	return user, nil
}

// parseRowToUserReset превращает строку результата запроса в объект пользователя
// row - строка результата запроса
// Возвращает пользователя и ошибку, если что-то пошло не так
func parseRowToUserReset(row pgx.Row) (*User, error) {
	// Создаем экземпляр пользователя
	user := &User{}

	// Сканируем данные из строки в структуру пользователя
	err := row.Scan(
		&user.ID,       // Уникальный идентификатор пользователя
		&user.Version,  // Версия профиля пользователя
		&user.Username, // Имя пользователя
		&user.Email,    // Электронная почта пользователя
	)

	// Проверяем ошибки
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("пользователь не найден: %w", err)
	} else if err != nil {
		return nil, fmt.Errorf("ошибка при сканировании данных пользователя: %w", err)
	}
	return user, nil
}

// isValidEmailFormat проверяет, соответствует ли адрес электронной почты допустимому формату.
func isValidEmailFormat(email string) bool {
	// Пример регулярного выражения для валидации адреса электронной почты.
	const emailRegex = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegex)
	return re.MatchString(email)
}
func IsDuplicatedKeyError(err error) bool {
	var perr *pgconn.PgError
	if errors.As(err, &perr) {
		return perr.Code == "DUPLICATED_KEY"
	}
	return false
}

// HandleDuplicateError перехватывает и формирует особые сообщения для ошибок дублирования ключа
// err - ошибка, полученная из запроса к базе данных
// Возвращает ошибку с описанием или исходную ошибку
func HandleDuplicateError(err error) error {
	if err == nil {
		return nil
	}

	if IsDuplicatedKeyError(err) {
		return fmt.Errorf("попробуйте изменить уникальное значение, данное поле уже занято: %w", err)
	}

	return err
}

// generateRandomCode генерирует случайный шестнадцатиричный код заданной длины
// max - желаемая длина кода
// Возвращает код в виде int64 и ошибку, если что-то пошло не так
// func generateRandomCode(max int) (int64, error) {
// 	// Проверяем входные данные
// 	if max <= 0 {
// 		return 0, errors.New("максимальная длина должна быть положительной")
// 	}

// 	// Максимальное число, которое можно представить
// 	maxNum := big.NewInt(int64(math.Pow10(max)))

// 	// Генерируем случайное число в диапазоне от 0 до maxNum
// 	num, err := rand.Int(rand.Reader, maxNum)
// 	if err != nil {
// 		return 0, fmt.Errorf("ошибка генерации случайного числа: %w", err)
// 	}

// 	// Преобразуем в base64 представление для увеличения энтропии
// 	encoded := base64.StdEncoding.EncodeToString(num.Bytes())

// 	// Оставляем первые max символов
// 	truncated := encoded[:max]

// 	// Преобразуем в десятичное представление
// 	parsed, err := strconv.ParseInt(truncated, 10, 64)
// 	if err != nil {
// 		return 0, fmt.Errorf("ошибка преобразования строки в число: %w", err)
// 	}

// 	return parsed, nil
// }

// deleteAvatar удаляет аватар пользователя по его ID.
// Если аватар отсутствует, устанавливает avatar_url в NULL.
func (uh *UserHandler) deleteAvatar(userID int64) error {
	// Проверяем, существует ли аватар у пользователя
	var avatarPath string
	err := uh.UsersRepo.db.QueryRow(context.Background(), "SELECT avatar_url FROM users WHERE id = $1", userID).Scan(&avatarPath)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("пользователь с ID %d не найден", userID)
		}
		return fmt.Errorf("ошибка при запросе аватара пользователя с ID %d: %w", userID, err)
	}

	// Если аватар присутствует, удаляем его физически
	if avatarPath != "" {
		if _, statErr := os.Stat(avatarPath); statErr == nil {
			removeErr := os.Remove(avatarPath)
			if removeErr != nil {
				return fmt.Errorf("ошибка при удалении файла аватара: %w", removeErr)
			}
		} else if os.IsNotExist(statErr) {
			// Аватар уже удалён, идём дальше
		} else {
			return fmt.Errorf("ошибка при проверке существования файла аватара: %w", statErr)
		}
	}

	// Обновляем запись в базе данных, устанавливаем avatar_url в NULL
	updateResult, updateErr := uh.UsersRepo.db.Exec(context.Background(), "UPDATE users SET avatar_url = NULL WHERE id = $1", userID)
	if updateErr != nil {
		return fmt.Errorf("ошибка при обновлении аватара пользователя с ID %d: %w", userID, updateErr)
	}

	// Проверяем, сколько строк было изменено
	affected := updateResult.RowsAffected()

	if affected == 0 {
		return fmt.Errorf("пользователь с ID %d не найден", userID)
	}

	return nil // Всё прошло успешно
}

// comparePasswords сравнивает хэш старого пароля с новым паролем
func comparePasswords(currentHash, newPassword string) error {
	// Используем bcrypt для безопасного сравнения паролей
	err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(newPassword))
	if err == nil {
		// Если пароли совпадают, возвращаем ошибку
		return errors.New("новый пароль не может совпадать со старым паролем")
	}
	// Если ошибок нет, значит пароли разные
	return nil
}

// respondWithJSON отправляет ответ клиенту в виде JSON с заданным статусом и телом.
// Поддерживает запись в лог файлов ошибок и форматы успешного ответа.
func respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	response := Response{
		StatusCode: statusCode,
		Body:       data,
	}
	// Установка типа содержимого в JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	// Выполняем маршаллинг JSON и пишем ответ клиенту
	if err := json.NewEncoder(w).Encode(response); err != nil {
		// Сообщение клиенту о внутренней ошибке сервера
		http.Error(w, "Ошибка формирования ответа", http.StatusInternalServerError)
		return
	}
}
package user

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/unclaim/the_server_part.git/pkg/session"
)

// Новый метод проверки HTTP-метода
func checkMethod(w http.ResponseWriter, r *http.Request, allowedMethods []string) bool {
	for _, method := range allowedMethods {
		if r.Method == method {
			return true
		}
	}
	handleError(w, r, fmt.Errorf("неверный метод (%s)", r.Method), http.StatusMethodNotAllowed)
	return false
}

// PersonalData представляет собой объект, содержащий персональные данные пользователя.
// Объект предназначен для передачи информации о пользователе, включая имя, фамилию, дату рождения, пол, местоположение и электронную почту.
// @SWAGGER_STRUCT_NAME PersonalData
type PersonalData struct {
	// FirstName — имя пользователя.
	// Примечание: необязательное поле.
	// example: Иван
	FirstName *string `json:"first_name,omitempty"`

	// LastName — фамилия пользователя.
	// Примечание: необязательное поле.
	// example: Иванов
	LastName *string `json:"last_name,omitempty"`

	// Bdate — дата рождения пользователя.
	// Примечание: необязательное поле.
	// example: 1990-01-01T00:00:00Z
	Bdate *time.Time `json:"bdate,omitempty"`

	// Sex — пол пользователя ("male"/"female").
	// Примечание: необязательное поле.
	// example: male
	Sex *string `json:"sex,omitempty"`

	// Location — местонахождение пользователя.
	// Примечание: необязательное поле.
	// example: Москва
	Location *string `json:"location,omitempty"`

	// Email — электронная почта пользователя.
	// Примечание: обязательное поле.
	// example: ivan@mail.ru
	Email string `json:"email"`
}

// Обработчик для просмотра личных данных пользователя
// GET /account/personal-data
//
// Возвращает персональные данные текущего авторизованного пользователя из базы данных.
// Только владелец аккаунта имеет доступ к просмотру собственных персональных данных.
// Ответ включает следующие поля: имя, фамилия, дата рождения, пол, город проживания и email.
//
// @Summary      Просмотр личных данных пользователя
// @Description  Позволяет авторизованному пользователю просмотреть собственные персональные данные.
// @Tags         account
// @Accept       json
// @Produce      json
// @Success      200 {object} PersonalData "Успешное получение личных данных"
// @Failure      401 {object} ErrorResponse "Ошибка аутентификации"
// @Failure      500 {object} ErrorResponse "Ошибка сервера"
// @Security     BearerAuth
// @Router       /account/personal-data [get]
func (uh *UserHandler) GetUserPersonalData(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Проверяем метод запроса (только GET разрешен)
	if !checkMethod(w, r, []string{"GET"}) {
		return
	}

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID

	// Получаем личные данные пользователя
	personalData, err := uh.UsersRepo.GetUserPersonalData(ctx, userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка загрузки сообщений: %v", err), http.StatusInternalServerError)
		return
	}

	// Формирование ответа
	response := Response{
		StatusCode: http.StatusOK,
		Body:       personalData,
	}

	// Отправляем JSON-ответ с результатами
	if err := json.NewEncoder(w).Encode(response); err != nil {
		handleError(w, r, fmt.Errorf("ошибка формирования ответа: %v", err), http.StatusInternalServerError)
		return
	}
}

// Реализация метода GetUserPersonalData для чтения данных из базы данных
func (repository *UserRepository) GetUserPersonalData(ctx context.Context, userID int64) (*PersonalData, error) {
	// Подготавливаем запрос к базе данных
	query := ` SELECT first_name, last_name, bdate, sex, location, email FROM users WHERE id = $1`

	// Выполняем запрос с передачей параметра userID
	row := repository.db.QueryRow(ctx, query, userID)

	// Переменные для приёма данных из базы
	var firstName sql.NullString
	var lastName sql.NullString
	var bdate sql.NullTime
	var sex sql.NullString
	var location sql.NullString
	var email string

	// Сканируем результат запроса
	err := row.Scan(
		&firstName,
		&lastName,
		&bdate,
		&sex,
		&location,
		&email,
	)

	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("ошибка получения персональных данных пользователя: %v", err)
	}

	// Преобразование nullable-значений в обычные указатели
	result := &PersonalData{
		FirstName: func(ns sql.NullString) *string {
			if ns.Valid {
				return &ns.String
			}
			return nil
		}(firstName),
		LastName: func(ns sql.NullString) *string {
			if ns.Valid {
				return &ns.String
			}
			return nil
		}(lastName),
		Bdate: func(nt sql.NullTime) *time.Time {
			if nt.Valid {
				return &nt.Time
			}
			return nil
		}(bdate),
		Sex: func(ns sql.NullString) *string {
			if ns.Valid {
				return &ns.String
			}
			return nil
		}(sex),
		Location: func(ns sql.NullString) *string {
			if ns.Valid {
				return &ns.String
			}
			return nil
		}(location),
		Email: email,
	}

	return result, nil
}

// Обработчик для обновления личных данных пользователя
// PUT /account/personal-data
//
// Метод позволяет авторизованному пользователю обновить свою персональную информацию, такую как имя, фамилию, дату рождения, пол, город проживания и email.
// Запрос должен содержать JSON-данные с новыми значениями полей.
//
// @Summary Обновление личных данных пользователя
// @Description Позволяет авторизованному пользователю изменить собственную личную информацию.
// @Tags account
// @Accept json
// @Produce json
// @Param request body PersonalData true "Запрос на обновление личной информации"
// @Success 200 {object} SuccessResponse "Обновление успешно выполнено"
// @Failure 400 {object} ErrorResponse "Некорректный запрос"
// @Failure 401 {object} ErrorResponse "Ошибка аутентификации"
// @Failure 500 {object} ErrorResponse "Ошибка сервера"
// @Security BearerAuth
// @Router /account/personal-data [put]
func (uh *UserHandler) UpdateUserPersonalData(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID

	// Декодируем тело запроса
	var request PersonalData
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		handleError(w, r, fmt.Errorf("некорректный запрос: %v", err), http.StatusBadRequest)
		return
	}

	// Закрываем ресурс запроса и обрабатываем потенциальную ошибку.
	defer func() {
		if err := r.Body.Close(); err != nil {
			slog.Debug("Ошибка закрытия тела запроса", "ошибка", err)
		}
	}()

	// Сохранение изменений
	if err := uh.UsersRepo.UpdateUserPersonalData(ctx, userID, request); err != nil {
		handleError(w, r, fmt.Errorf("ошибка сохранения данных: %v", err), http.StatusInternalServerError)
		return
	}

	// Формируем успешный ответ
	msg := SuccessResponse{
		Message: "Данные успешно обновлены",
	}

	// Формирование ответа
	response := Response{
		StatusCode: http.StatusOK,
		Body:       msg,
	}

	// Отправляем JSON-ответ с результатами
	if err := json.NewEncoder(w).Encode(response); err != nil {
		handleError(w, r, fmt.Errorf("ошибка формирования ответа: %v", err), http.StatusInternalServerError)
		return
	}
}

type SuccessResponse struct {
	Message string
}

// Реализация метода UpdateUserPersonalData для обновления данных пользователя в базе данных
func (repo *UserRepository) UpdateUserPersonalData(ctx context.Context, userID int64, data PersonalData) error {
	// Подготавливаем SQL-запрос для обновления записей в таблице пользователей
	updateQuery := ` UPDATE users SET first_name = COALESCE($1, first_name), last_name = COALESCE($2, last_name), bdate = COALESCE($3, bdate), sex = COALESCE($4, sex), location = COALESCE($5, location), email = $6 WHERE id = $7 `

	_, err := repo.db.Exec(ctx, updateQuery,
		data.FirstName,
		data.LastName,
		data.Bdate,
		data.Sex,
		data.Location,
		data.Email,
		userID,
	)

	if err != nil {
		return fmt.Errorf("ошибка обновления данных пользователя: %v", err)
	}

	return nil
}

type Phone struct {
	Phone *string `json:"phone"` // Номер телефона пользователя.
}

// Обработчик для просмотра номера телефона пользователя
// GET /account/phone-number
//
// Возвращает номер телефона текущего авторизованного пользователя из базы данных.
// Доступ возможен только владельцу аккаунта.
//
// @Summary      Просмотр номера телефона пользователя
// @Description  Позволяет авторизованному пользователю посмотреть собственный номер телефона.
// @Tags         account
// @Accept       json
// @Produce      json
// @Success      200 {object} Response "Успешное получение номера телефона"
// @Failure      401 {object} ErrorResponse "Ошибка аутентификации"
// @Failure      500 {object} ErrorResponse "Ошибка сервера"
// @Security     BearerAuth
// @Router       /account/phone-number [get]
func (uh *UserHandler) GetUserPhoneNumber(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Проверяем метод запроса (только GET разрешен)
	if !checkMethod(w, r, []string{"GET"}) {
		return
	}

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID

	// Получаем телефон пользователя
	phoneNumber, err := uh.UsersRepo.GetUserPhoneNumber(ctx, userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка загрузки номера телефона: %v", err), http.StatusInternalServerError)
		return
	}
	phone := Phone{Phone: phoneNumber}
	// Формирование ответа
	response := Response{
		StatusCode: http.StatusOK,
		Body:       phone,
	}

	// Отправляем JSON-ответ с результатом
	if err := json.NewEncoder(w).Encode(response); err != nil {
		handleError(w, r, fmt.Errorf("ошибка формирования ответа: %v", err), http.StatusInternalServerError)
		return
	}
}

// Реализация метода GetUserPhoneNumber для чтения номера телефона из базы данных
func (repository *UserRepository) GetUserPhoneNumber(ctx context.Context, userID int64) (*string, error) {
	// Подготавливаем запрос к базе данных
	query := `SELECT phone FROM users WHERE id = $1`

	// Выполняем запрос с передачей параметра userID
	row := repository.db.QueryRow(ctx, query, userID)

	// Переменная для приема данных из базы
	var phone sql.NullString

	// Сканируем результат запроса
	err := row.Scan(&phone)

	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("ошибка получения номера телефона пользователя: %v", err)
	}

	// Если значение найдено, возвращаем его
	if phone.Valid {
		return &phone.String, nil
	}

	// Иначе возвращаем nil
	return nil, nil
}

// Обработчик для изменения номера телефона пользователя
// PUT /account/phone-number
//
// Изменяет номер телефона текущего авторизованного пользователя.
// Запрос должен содержать JSON-данные с новым номером телефона.
//
// @Summary      Изменение номера телефона пользователя
// @Description  Позволяет авторизованному пользователю поменять собственный номер телефона.
// @Tags         account
// @Accept       json
// @Produce      json
// @Param request body PhoneNumberUpdateRequest true "Запрос на изменение номера телефона"
// @Success      200 {object} SuccessResponse "Номер телефона успешно изменён"
// @Failure      400 {object} ErrorResponse "Некорректный запрос"
// @Failure      401 {object} ErrorResponse "Ошибка аутентификации"
// @Failure      500 {object} ErrorResponse "Ошибка сервера"
// @Security     BearerAuth
// @Router       /account/phone-number [put]
func (uh *UserHandler) UpdateUserPhoneNumber(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID

	// Декодируем тело запроса
	var request PhoneNumberUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		handleError(w, r, fmt.Errorf("некорректный запрос: %v", err), http.StatusBadRequest)
		return
	}

	// Закрываем ресурс запроса и обрабатываем потенциальную ошибку.
	defer func() {
		if err := r.Body.Close(); err != nil {
			slog.Debug("Ошибка закрытия тела запроса", "ошибка", err)
		}
	}()

	// Сохранение нового номера телефона
	if err := uh.UsersRepo.UpdateUserPhoneNumber(ctx, userID, request.Phone); err != nil {
		handleError(w, r, fmt.Errorf("ошибка сохранения номера телефона: %v", err), http.StatusInternalServerError)
		return
	}

	// Формируем успешный ответ
	msg := SuccessResponse{
		Message: "Номер телефона успешно изменён",
	}

	// Формирование ответа
	response := Response{
		StatusCode: http.StatusOK,
		Body:       msg,
	}

	// Отправляем JSON-ответ с результатами
	if err := json.NewEncoder(w).Encode(response); err != nil {
		handleError(w, r, fmt.Errorf("ошибка формирования ответа: %v", err), http.StatusInternalServerError)
		return
	}
}

// Struct для хранения данных запроса на обновление номера телефона
type PhoneNumberUpdateRequest struct {
	Phone string `json:"phone"`
}

// Реализация метода UpdateUserPhoneNumber для обновления номера телефона в базе данных
func (repo *UserRepository) UpdateUserPhoneNumber(ctx context.Context, userID int64, newPhone string) error {
	// Подготавливаем SQL-запрос для обновления записи в таблице пользователей
	updateQuery := `UPDATE users SET phone = $1 WHERE id = $2`

	_, err := repo.db.Exec(ctx, updateQuery, newPhone, userID)

	if err != nil {
		return fmt.Errorf("ошибка обновления номера телефона пользователя: %v", err)
	}

	return nil
}

// Обработчик для просмотра биографии пользователя
// GET /account/bio
//
// Возвращает биографию текущего авторизованного пользователя из базы данных.
// Доступ доступен только владельцу аккаунта.
//
// @Summary      Просмотр биографии пользователя
// @Description  Позволяет авторизованному пользователю просмотреть собственную биографическую информацию.
// @Tags         account
// @Accept       json
// @Produce      json
// @Success      200 {object} Bio "Биография успешно получена"
// @Failure      401 {object} ErrorResponse "Ошибка аутентификации"
// @Failure      500 {object} ErrorResponse "Ошибка сервера"
// @Security     BearerAuth
// @Router       /account/bio [get]
func (uh *UserHandler) GetUserBiography(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Проверяем метод запроса (только GET разрешен)
	if !checkMethod(w, r, []string{"GET"}) {
		return
	}

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID

	// Получаем биографию пользователя
	bio, err := uh.UsersRepo.GetUserBio(ctx, userID)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка загрузки биографии: %v", err), http.StatusInternalServerError)
		return
	}

	// Формирование ответа
	response := Response{
		StatusCode: http.StatusOK,
		Body:       Bio{Bio: bio},
	}

	// Отправляем JSON-ответ с результатами
	if err := json.NewEncoder(w).Encode(response); err != nil {
		handleError(w, r, fmt.Errorf("ошибка формирования ответа: %v", err), http.StatusInternalServerError)
		return
	}
}

// Реализация метода GetUserBio для чтения биографии из базы данных
func (repository *UserRepository) GetUserBio(ctx context.Context, userID int64) (*string, error) {
	// Подготавливаем запрос к базе данных
	query := `SELECT bio FROM users WHERE id = $1`

	// Выполняем запрос с передачей параметра userID
	row := repository.db.QueryRow(ctx, query, userID)

	// Переменная для приема данных из базы
	var bio sql.NullString

	// Сканируем результат запроса
	err := row.Scan(&bio)

	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("ошибка получения биографии пользователя: %v", err)
	}

	// Если значение найдено, возвращаем его
	if bio.Valid {
		return &bio.String, nil
	}

	// Иначе возвращаем nil
	return nil, nil
}

type Bio struct {
	Bio *string `json:"bio"`
}

// Обработчик для обновления биографии пользователя
// PUT /account/bio
//
// Изменяет биографию текущего авторизованного пользователя.
// Запрос должен содержать JSON-данные с новой биографией.
//
// @Summary      Обновление биографии пользователя
// @Description  Позволяет авторизованному пользователю изменить собственную биографическую информацию.
// @Tags         account
// @Accept       json
// @Produce      json
// @Param request body Bio true "Запрос на обновление биографии"
// @Success      200 {object} SuccessResponse "Биография успешно обновлена"
// @Failure      400 {object} ErrorResponse "Некорректный запрос"
// @Failure      401 {object} ErrorResponse "Ошибка аутентификации"
// @Failure      500 {object} ErrorResponse "Ошибка сервера"
// @Security     BearerAuth
// @Router       /account/bio [put]
func (uh *UserHandler) UpdateUserBiography(w http.ResponseWriter, r *http.Request) {
	// Включаем CORS
	enableCors(&w)

	// Используем контекст из запроса, а не создаем новый.
	ctx := r.Context()

	// Получаем сессию из контекста
	sess, err := session.SessionFromContext(ctx)
	if err != nil {
		handleError(w, r, fmt.Errorf("ошибка при получении сессии: %v", err), http.StatusUnauthorized)
		return
	}

	userID := sess.UserID

	// Декодируем тело запроса
	var request Bio
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		handleError(w, r, fmt.Errorf("некорректный запрос: %v", err), http.StatusBadRequest)
		return
	}

	// Закрываем ресурс запроса и обрабатываем потенциальную ошибку.
	defer func() {
		if err := r.Body.Close(); err != nil {
			slog.Debug("Ошибка закрытия тела запроса", "ошибка", err)
		}
	}()

	// Сохранение новых данных
	if err := uh.UsersRepo.UpdateUserBio(ctx, userID, request.Bio); err != nil {
		handleError(w, r, fmt.Errorf("ошибка сохранения биографии: %v", err), http.StatusInternalServerError)
		return
	}

	// Формируем успешный ответ
	msg := SuccessResponse{
		Message: "Биография успешно обновлена",
	}

	// Формирование ответа
	response := Response{
		StatusCode: http.StatusOK,
		Body:       msg,
	}

	// Отправляем JSON-ответ с результатами
	if err := json.NewEncoder(w).Encode(response); err != nil {
		handleError(w, r, fmt.Errorf("ошибка формирования ответа: %v", err), http.StatusInternalServerError)
		return
	}
}

// Реализация метода UpdateUserBio для обновления биографии в базе данных
func (repo *UserRepository) UpdateUserBio(ctx context.Context, userID int64, newBio *string) error {
	// Подготавливаем SQL-запрос для обновления биографии пользователя
	updateQuery := `UPDATE users SET bio = $1 WHERE id = $2`

	_, err := repo.db.Exec(ctx, updateQuery, newBio, userID)

	if err != nil {
		return fmt.Errorf("ошибка обновления биографии пользователя: %v", err)
	}

	return nil
}
