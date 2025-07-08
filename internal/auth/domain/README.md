# internal/auth/domain/ports.go - Список Дел и Вещей для Домика "Авторизация"
Здесь мы говорим, что умеет делать наш сервис авторизации (AuthService) и что ему нужно от хранилища данных (AuthRepository). Это просто обещания (интерфейсы), без деталей реализации.
```go
package domain

import (
	"context"
	"time"
)

// AuthService — это "входящий порт". Это список дел, которые умеет делать наш домик "Auth".
// Другие части приложения (например, обработчики HTTP-запросов) будут вызывать эти методы.
type AuthService interface {
	RegisterUser(ctx context.Context, email, password string) (User, error)           // Зарегистрировать пользователя
	VerifyEmail(ctx context.Context, email, code string) (User, error)               // Подтвердить email пользователя по коду
	CompleteRegistration(ctx context.Context, userID string, name, surname, username string) (User, error) // Завершить регистрацию
	LoginUser(ctx context.Context, login, password string) (Session, error)          // Войти в систему
	LogoutUser(ctx context.Context, sessionID string) error                          // Выйти из системы
	ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error // Изменить пароль
	ResetPasswordRequest(ctx context.Context, email string) error                    // Запросить сброс пароля
	ResetPasswordConfirm(ctx context.Context, email, code, newPassword string) error // Подтвердить сброс пароля
	GetSession(ctx context.Context, sessionID string) (Session, error)               // Получить данные сессии
}

// AuthRepository — это "исходящий порт". Это список вещей, которые нужны домику "Auth" от внешнего мира.
// Это обещает, что где-то будет код, который умеет выполнять эти действия с базой данных.
type AuthRepository interface {
	SaveUser(ctx context.Context, user User) error                               // Сохранить пользователя
	GetUserByEmail(ctx context.Context, email string) (User, error)              // Найти пользователя по email
	GetUserByUsername(ctx context.Context, username string) (User, error)        // Найти пользователя по username
	SaveSession(ctx context.Context, session Session, expiresAt time.Time) error // Сохранить сессию
	GetSessionByID(ctx context.Context, sessionID string) (Session, error)       // Получить сессию по ID
	DeleteSession(ctx context.Context, sessionID string) error                   // Удалить сессию
	UpdateUser(ctx context.Context, user User) error                             // Обновить пользователя
	RecordFailedLoginAttempt(ctx context.Context, identifier string) error       // Записать неудачную попытку входа
	GetFailedLoginAttempts(ctx context.Context, identifier string) (int, time.Time, error) // Получить кол-во неудачных попыток
	ClearFailedLoginAttempts(ctx context.Context, identifier string) error       // Очистить неудачные попытки
}

```

# internal/auth/domain/service.go - Главный Работник Домика "Авторизация"
Это место, где живет настоящая логика регистрации и входа. Он использует AuthRepository (который знает, как работать с базой данных), чтобы выполнить свою работу.
```go
package domain

import (
	"context"
	"errors"
	"fmt"
	"time"

	"your-app-name/pkg/infrastructure/eventbus" // Импортируем нашу шину событий
	"your-app-name/pkg/email"                   // Для отправки писем
	"your-app-name/pkg/security"                // Для работы с паролями
	"your-app-name/internal/shared/common_errors" // Наши общие ошибки
)

// AuthServiceImplementation — это наш "главный работник" для домика Auth.
// Он умеет выполнять все, что обещает интерфейс AuthService.
type AuthServiceImplementation struct {
	repo AuthRepository     // Это "вещь", которую он использует: репозиторий для работы с базой данных.
	eb   eventbus.EventBus  // Наша шина событий, чтобы рассылать "новости"
	mailService email.MailService // Сервис для отправки писем
}

// NewAuthService создает нового "главного работника"
func NewAuthService(repo AuthRepository, eb eventbus.EventBus, mailService email.MailService) *AuthServiceImplementation {
	return &AuthServiceImplementation{
		repo: repo,
		eb:   eb,
		mailService: mailService,
	}
}

// RegisterUser - это одна из задач, которую умеет делать наш работник.
// Здесь он регистрирует нового пользователя.
func (s *AuthServiceImplementation) RegisterUser(ctx context.Context, email, password string) (User, error) {
	// 1. Проверяем, что пользователя с таким email еще нет.
	// Это как спросить у кладовщика (репозитория): "Есть такой пользователь?".
	_, err := s.repo.GetUserByEmail(ctx, email)
	if err == nil {
		// Если нашли пользователя, значит, он уже зарегистрирован.
		return User{}, common_errors.NewConflictError("Пользователь с таким email уже зарегистрирован")
	}
	if !errors.Is(err, common_errors.ErrNotFound) {
		// Если ошибка не ErrNotFound, значит что-то пошло не так с базой данных
		return User{}, fmt.Errorf("ошибка при проверке email: %w", err)
	}

	// 2. Хэшируем пароль. Это как превратить пароль в секретный код,
	// который никто не сможет прочитать напрямую.
	hashedPassword, err := security.HashPassword(password)
	if err != nil {
		return User{}, fmt.Errorf("не удалось хэшировать пароль: %w", err)
	}

	// 3. Генерируем код подтверждения email. Это как уникальный секретный код для почты.
	verificationCode := security.GenerateRandomCode(6) // 6-значный код

	// 4. Создаем нового пользователя.
	newUser := NewUser(email, hashedPassword, verificationCode)
	newUser.Status = UserStatusPendingVerification // Пользователь еще не подтвердил почту

	// 5. Сохраняем пользователя в базе данных.
	// Это как дать кладовщику (репозиторию) новую коробку с информацией.
	err = s.repo.SaveUser(ctx, newUser)
	if err != nil {
		return User{}, fmt.Errorf("не удалось сохранить пользователя: %w", err)
	}

	// 6. Отправляем письмо с кодом подтверждения.
	// Это как отправить почтового голубя с секретным кодом.
	err = s.mailService.SendEmail(email, "Подтверждение регистрации", fmt.Sprintf("Ваш код подтверждения: %s", verificationCode))
	if err != nil {
		// Здесь можно решить, что делать, если письмо не отправилось.
		// Пока просто логируем ошибку, но в реальном приложении можно добавить retry-логику.
		slog.Error("Не удалось отправить email подтверждения", "email", email, "error", err)
	}

	// 7. Публикуем событие "пользователь зарегистрирован".
	// Это как крикнуть "Новый пользователь зарегистрировался!" для всех, кто слушает.
	s.eb.Publish(ctx, UserRegisteredEvent{UserID: newUser.ID, Email: newUser.Email})

	return newUser, nil
}

// Другие методы (LoginUser, VerifyEmail и т.д.) будут выглядеть похожим образом,
// используя repo для взаимодействия с данными и eb для отправки событий.
// ...


```

# internal/auth/domain/auth.go - Игрушки и Правила Домика "Авторизация" 🧸
Эта папка — как коробка с игрушками и правилами игры для нашего домика "Авторизация". Здесь мы описываем, как выглядят пользователи (User), их сессии (Session), и другие важные вещи, которые нужны только этому домику. Здесь нет никакой логики сохранения данных, только описание самих "игрушек".
Где это: your-ultra-scalable-monolith/internal/auth/domain/auth.go
Что здесь:
Определение сущностей: Создание "чертежей" для основных вещей, таких как User (пользователь) и Session (сессия входа).
Правила для данных: Например, что у пользователя должен быть ID, email, хэш пароля.
Методы-помощники: Небольшие функции, которые помогают работать с этими "игрушками" (например, проверить, правильный ли пароль).
Пример:

```go
package domain

import (
	"time"

	"your-app-name/pkg/security" // Для работы с паролями
	"github.com/google/uuid"    // Для создания уникальных ID
)

// UserStatus определяет текущий статус пользователя.
type UserStatus string

const (
	UserStatusPendingVerification UserStatus = "pending_verification" // Ожидает подтверждения email
	UserStatusActive              UserStatus = "active"               // Активный пользователь
	UserStatusBlocked             UserStatus = "blocked"              // Заблокированный пользователь
)

// User - это наша "игрушка" - сущность пользователя.
// Она содержит всю важную информацию о пользователе.
type User struct {
	ID                    string     // Уникальный идентификатор пользователя
	Email                 string     // Электронная почта пользователя
	PasswordHash          string     // Хэш (зашифрованный) пароль пользователя
	Username              string     // Уникальное имя пользователя (может быть пустым сначала)
	Name                  string     // Имя пользователя
	Surname               string     // Фамилия пользователя
	Status                UserStatus // Текущий статус пользователя (см. выше)
	EmailVerificationCode string     // Код для подтверждения email (временный)
	CreatedAt             time.Time  // Дата и время создания пользователя
	UpdatedAt             time.Time  // Дата и время последнего обновления
}

// NewUser создает нового пользователя с начальными данными.
// Это как взять новый набор деталей для создания игрушки.
func NewUser(email, passwordHash, verificationCode string) User {
	return User{
		ID:                    uuid.New().String(), // Генерируем новый уникальный ID
		Email:                 email,
		PasswordHash:          passwordHash,
		Status:                UserStatusPendingVerification, // По умолчанию пользователь ожидает подтверждения
		EmailVerificationCode: verificationCode,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}
}

// CheckPassword - метод, который проверяет, совпадает ли введенный пароль с сохраненным хэшем.
// Это как проверить, подходит ли ключ к замку.
func (u *User) CheckPassword(password string) bool {
	return security.CheckPasswordHash(password, u.PasswordHash)
}

// MarkEmailAsVerified - устанавливает статус пользователя как "активный".
// Это как сказать: "Эта игрушка готова к игре!".
func (u *User) MarkEmailAsVerified() {
	u.Status = UserStatusActive
	u.UpdatedAt = time.Now()
}

// UpdateUsername - обновляет имя пользователя.
func (u *User) UpdateUsername(username string) {
    u.Username = username
    u.UpdatedAt = time.Now()
}

// Session - это наша "игрушка" - сущность сессии.
// Она хранит информацию о том, что пользователь вошел в систему.
type Session struct {
	ID        string    // Уникальный ID сессии
	UserID    string    // ID пользователя, которому принадлежит сессия
	ExpiresAt time.Time // Время, когда сессия перестанет быть действительной
	CreatedAt time.Time // Время создания сессии
	ClientIP  string    // IP-адрес клиента, который создал сессию (для безопасности)
	UserAgent string    // Информация о браузере/устройстве клиента
}

// NewSession создает новую сессию для пользователя.
func NewSession(userID, clientIP, userAgent string, expiresAt time.Time) Session {
	return Session{
		ID:        uuid.New().String(), // Генерируем новый уникальный ID для сессии
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
		ClientIP:  clientIP,
		UserAgent: userAgent,
	}
}

```