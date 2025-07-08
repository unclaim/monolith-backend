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

type CheckUserRequest struct {
	Username *string `json:"username" example:"test_user"`
}

type LoginRequest struct {
	Username     *string `json:"username,omitzero"`
	PasswordHash string  `json:"password_hash,omitzero"`
}

func (repository *UserRepository) GetByLoginOrEmail(ctx context.Context, username string, email string) (*User, error) {
	const SQL_READ_LOGIN_OR_EMAIL = `
		SELECT id, username, email, password_hash
		FROM users
		WHERE username = $1 OR email = $2
		LIMIT 1
	`
	row := repository.db.QueryRow(ctx, SQL_READ_LOGIN_OR_EMAIL, username, email)
	user, err := parseRowToUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("ошибка при парсинге строки пользователя: %w", err)
	}
	return user, nil
}

var (
	ErrMessageTooLong = errors.New("содержимое сообщения слишком длинное")
	ErrDatabaseError  = errors.New("ошибка базы данных")
)

func (repository *UserRepository) getUserProfileData(profileID, currentUserId int64) (Response, error) {
	profile, subscriptionsCount, err := repository.GetUserProfile(profileID, currentUserId)
	if err != nil {
		return Response{}, fmt.Errorf("не удалось получить профиль пользователя: %v", err)
	}
	messages, err := repository.GetNewMessages(currentUserId)
	if err != nil {
		return Response{}, fmt.Errorf("не удалось получить новые сообщения: %v", err)
	}
	isBlocked, err := repository.isBlocked(currentUserId, profileID)
	if err != nil {
		return Response{}, fmt.Errorf("не удалось проверить статус блокировки: %v", err)
	}
	isFollowing, err := repository.isFollowing(currentUserId, profileID)
	if err != nil {
		return Response{}, fmt.Errorf("не удалось проверить статус подписки: %v", err)
	}
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

func validateSignupRequest(req SignUpRequest) error {
	if req.FirstName == "" || req.LastName == "" || req.Username == "" || req.Email == "" || req.Password == "" {
		return errors.New("все поля обязательны для заполнения")
	}
	return nil
}

var userLinksCache sync.Map

func (uh *UserHandler) SendVerificationEmail(to string, code string) error {
	from := "duginea@mail.ru"
	password := "L9BtgetNuRcPkWUvN9wz"
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

func (uh *UserHandler) createUser(ctx context.Context, signupRequest SignUpRequest) (*User, error) {
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

func (uh *UserHandler) UpdateUserSkills(userID int64, skills []int) error {
	if len(skills) == 0 {
		return fmt.Errorf("список навыков пуст")
	}
	for _, skill := range skills {
		if skill < 0 {
			return fmt.Errorf("некорректный индекс навыка: %d", skill)
		}
	}
	err := uh.UsersRepo.UpdateUserSkills(userID, skills)
	if err != nil {
		return fmt.Errorf("ошибка при обновлении навыков пользователя с ID %d: %w", userID, err)
	}
	return nil
}
