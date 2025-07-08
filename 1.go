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

func (repository *UserRepository) UpdatePassword(email, newPassword string) error {
	query := `
        UPDATE users 
        SET password_hash = crypt($1, gen_salt('bf'))
        WHERE email = $2
    `
	result, err := repository.db.Exec(context.Background(), query, newPassword, email)
	if err != nil {
		return fmt.Errorf("ошибка обновления пароля: %w", err)
	}
	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("пользователь с указанной электронной почтой (%s) не найден", email)
	}
	return nil
}

func (repository *UserRepository) blockUser(blockerID, blockedID int64) error {
	if blockerID == blockedID {
		return fmt.Errorf("пользователь не может заблокировать самого себя")
	}
	_, err := repository.db.Exec(
		context.Background(),
		"INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2)",
		blockerID, blockedID,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("пользователь с ID %d уже заблокирован пользователем с ID %d",
				blockedID, blockerID)
		}
		return fmt.Errorf("ошибка блокировки пользователя: %v", err)
	}
	return nil
}

func (repository *UserRepository) checkPasswordByLoginOrEmail(ctx context.Context, Email, Username, pass string) (*User, error) {
	row := repository.db.QueryRow(ctx, ` SELECT id, username, email, ver, password_hash FROM users WHERE ((username = $1 AND password_hash = crypt($2, password_hash)) OR (email = $3 AND password_hash = crypt($4, password_hash))) `, Username, pass, Email, pass)
	return repository.passwordIsValidEmail(pass, row)
}

func (repository *UserRepository) checkPasswordByUserID(ctx context.Context, uid int64, pass string) (*User, error) {
	row := repository.db.QueryRow(ctx, ` SELECT id, username, ver, password_hash FROM users WHERE id = $1 AND password_hash = crypt($2, password_hash) `, uid, pass)
	return repository.passwordIsValid(pass, row)
}

func (repository *UserRepository) CheckUserExists(ctx context.Context, username, email string) (bool, error) {
	query := `
        SELECT EXISTS(
            SELECT 1
            FROM users
            WHERE username = $1 OR email = $2
        );
    `
	var exists bool
	err := repository.db.QueryRow(ctx, query, username, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("ошибка при проверке существования пользователя: %w", err)
	}
	return exists, nil
}

func (repository *UserRepository) checkVerifiedByUserID(ctx context.Context, uid int64) (bool, error) {
	const SQL_READ_VERIFIED = `
        SELECT verified
        FROM users
        WHERE id = $1
        LIMIT 1
    `
	var verified bool
	err := repository.db.QueryRow(ctx, SQL_READ_VERIFIED, uid).Scan(&verified)
	if err != nil {
		return false, fmt.Errorf("ошибка при получении статуса верификации пользователя: %w", err)
	}
	return verified, nil
}

func (repository *UserRepository) CreateAccountVerificationsCode(ctx context.Context, email string, code int64) error {
	const SQL_CREATE_CODE = `
    INSERT INTO account_verifications (email, verification_code)
    VALUES ($1, $2)
    ON CONFLICT ON CONSTRAINT unique_email DO UPDATE
    SET verification_code = EXCLUDED.verification_code;
    `
	result, err := repository.db.Exec(ctx, SQL_CREATE_CODE, email, code)
	if err != nil {
		return fmt.Errorf("ошибка при создании кода подтверждения: %w", err)
	}
	rowsAffected := result.RowsAffected()
	if rowsAffected <= 0 {
		return fmt.Errorf("не удалось обновить или создать код подтверждения для email '%s'", email)
	}
	return nil
}

func (repository *UserRepository) CreateHashPass(plainPassword, salt string) ([]byte, error) {
	hashBytes := argon2.IDKey([]byte(plainPassword), []byte(salt), 1, 64*1024, 4, 32)
	finalHash := make([]byte, len(salt)+len(hashBytes))
	copy(finalHash[:len(salt)], []byte(salt))
	copy(finalHash[len(salt):], hashBytes)
	return finalHash, nil
}

func (repository *UserRepository) CreateUser(
	ctx context.Context,
	firstname, lastname, username, email, password string,
) (*User, error) {
	if err := InputDataControl(firstname, lastname, username, email, password); err != nil {
		return nil, fmt.Errorf("некорректные входные данные: %w", err)
	}
	exists, err := repository.CheckUserExists(ctx, username, email)
	if err != nil {
		return nil, fmt.Errorf("ошибка при проверке наличия пользователя: %w", err)
	}
	if exists {
		return nil, errors.New("пользователь с указанным именем или e-mail уже существует")
	}
	var uid int64
	user := &User{}
	err = repository.db.QueryRow(ctx, SQL_CREATE_USER, firstname, lastname, username, email, password).Scan(&uid)
	if err != nil {
		return nil, fmt.Errorf("ошибка при создании пользователя: %w", err)
	}
	user.ID = uid
	user.FirstName = &firstname
	user.LastName = &lastname
	user.Username = &username
	user.Email = email
	return user, nil
}

func (repository *UserRepository) deleteUserByID(userID int64) error {
	if userID <= 0 {
		return fmt.Errorf("недопустимый идентификатор пользователя: %d", userID)
	}
	var exists bool
	err := repository.db.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", userID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("ошибка при проверке существования пользователя с ID %d: %w", userID, err)
	}
	if !exists {
		return fmt.Errorf("пользователь с ID %d не найден в базе данных", userID)
	}
	_, err = repository.db.Exec(context.Background(), "DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		return fmt.Errorf("не удалось выполнить запрос на удаление пользователя с ID %d: %w", userID, err)
	}
	return nil
}

func (repository *UserRepository) deleteUserFiles(userID int64) error {
	directory := filepath.Join("./uploads", fmt.Sprint(userID))
	err := os.RemoveAll(directory)
	if err != nil {
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

func (repository *UserRepository) fetchUsers(limit, offset int, proStr, onlineStr, categories, location string) ([]User, int, error) {
	var proFilter string
	switch proStr {
	case "":
		break
	case "true":
		proFilter = "AND u.pro = true"
	case "false":
		proFilter = "AND u.pro = false"
	default:
	}
	var onlineFilter string
	if onlineStr == "true" {
		onlineFilter = "AND s.id IS NOT NULL"
	}
	var categoriesFilter string
	if categories != "" {
		categoryIDs := strings.Split(categories, ",")
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
		locationFilter = fmt.Sprintf("AND u.location = '%s'", location)
	}
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
			continue
		}
		msg.Sender = user
		messages = append(messages, msg)
	}
	return messages, nil
}

func (repository *UserRepository) GetByEmail(ctx context.Context, Email string) (*User, error) {
	row := repository.db.QueryRow(ctx, SQL_READ_EMAIL_FOR_RESET_PWD, Email)
	return parseRowToUserReset(row)
}

func (repository *UserRepository) GetByID(ctx context.Context, id int64) (*User, error) {
	row := repository.db.QueryRow(ctx, SQL_READ_USER, id)
	return parseRowToUser(row)
}

func (repository *UserRepository) GetByLogin(ctx context.Context, login string) (*User, error) {
	row := repository.db.QueryRow(ctx, SQL_GET_USERNAME, login)
	return parseRowToUser(row)
}

func (repository *UserRepository) GetByName(ctx context.Context, username string) (*User, error) {
	row := repository.db.QueryRow(ctx, SQL_READ_USERNAME, username)
	return parseRowToUser(row)
}

func (repository *UserRepository) getCompanyInfo() (Company, error) {
	var company Company
	err := repository.db.QueryRow(context.Background(), "SELECT id, name, logo_url, website_url, last_updated FROM company LIMIT 1").Scan(&company.ID, &company.Name, &company.LogoURL, &company.WebsiteURL, &company.LastUpdated)
	return company, err
}

func (repository *UserRepository) getEmailByUserID(ctx context.Context, userID int64) (string, error) {
	var email string
	query := "SELECT email FROM users WHERE id = $1 LIMIT 1;"
	err := repository.db.QueryRow(ctx, query, userID).Scan(&email)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("пользователь с идентификатором %d не найден", userID)
		}
		return "", fmt.Errorf("ошибка при попытке получить email пользователя с идентификатором %d: %w", userID, err)
	}
	return email, nil
}

func (repository *UserRepository) getExportDate(ctx context.Context, userID int64) (time.Time, error) {
	var exportDate time.Time
	query := "SELECT export_date FROM exports WHERE user_id = $1 LIMIT 1;"
	err := repository.db.QueryRow(ctx, query, userID).Scan(&exportDate)
	if err != nil {
		if err == sql.ErrNoRows {
			return time.Time{}, fmt.Errorf("экспорт данных для пользователя с идентификатором %d не обнаружен", userID)
		}
		return time.Time{}, fmt.Errorf("ошибка при попытке получить дату экспорта для пользователя с идентификатором %d: %w", userID, err)
	}
	return exportDate, nil
}

func (repository *UserRepository) GetNewMessages(currentUserId int64) ([]Message, error) {
	query := `
        SELECT 
            m.id, m.sender_id, m.content, m.created_at, m.is_read, 
            u.id AS user_id, u.username, u.avatar_url  
        FROM messages m 
        JOIN users u ON m.sender_id = u.id 
        WHERE m.recipient_id = $1 AND m.is_read = FALSE
        ORDER BY m.created_at ASC
    `
	rows, err := repository.db.Query(context.Background(), query, currentUserId)
	if err != nil {
		return nil, fmt.Errorf("ошибка при выполнении запроса к базе данных: %w", err)
	}
	defer rows.Close()
	var messages []Message
	for rows.Next() {
		var msg Message
		var user User
		if err := rows.Scan(&msg.ID, &msg.SenderID, &msg.Content, &msg.CreatedAt, &msg.IsRead, &user.ID, &user.Username, &user.AvatarURL); err != nil {
			return nil, fmt.Errorf("ошибка при разборе данных сообщения: %w", err)
		}
		msg.Sender = user
		messages = append(messages, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при закрытии соединений: %w", err)
	}
	return messages, nil
}

func (repository *UserRepository) getSessionByID(ctx context.Context, sessionID string) (int64, error) {
	var userID int64
	query := "SELECT user_id FROM sessions WHERE id = $1"
	err := repository.db.QueryRow(ctx, query, sessionID).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("сессия с идентификатором %s не найдена", sessionID)
		}
		return 0, fmt.Errorf("ошибка при выполнении запроса: %w", err)
	}
	return userID, nil
}

func (repository *UserRepository) getSessionsByUserID(ctx context.Context, userID int64) ([]session.Session, error) {
	query := `
        SELECT id, ip, browser, operating_system, created_at, first_login
        FROM sessions
        WHERE user_id = $1
        ORDER BY created_at DESC
    `
	rows, err := repository.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("ошибка при загрузке сеансов пользователя с идентификатором %d: %w", userID, err)
	}
	defer rows.Close()
	var sessions []session.Session
	for rows.Next() {
		var sess session.Session
		if err := rows.Scan(&sess.ID, &sess.IP, &sess.Browser, &sess.OperatingSystem, &sess.CreatedAt, &sess.FirstLogin); err != nil {
			return nil, fmt.Errorf("ошибка при разбора данных о сеансах пользователя с идентификатором %d: %w", userID, err)
		}
		sessions = append(sessions, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при завершении выборки данных о сеансах пользователя с идентификатором %d: %w", userID, err)
	}
	return sessions, nil
}

func (repo *UserRepository) GetUserCategories(userId int) ([]CategoryResponse, error) {
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
	if len(categoryIDs) == 0 {
		return []CategoryResponse{}, nil
	}
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
	if err != nil {
		if err == pgx.ErrNoRows {
			return user, fmt.Errorf("пользователь с идентификатором %d не найден", userID)
		}
		return user, fmt.Errorf("ошибка при сканировании данных пользователя с идентификатором %d: %w", userID, err)
	}
	return user, nil
}

func (repository *UserRepository) GetUserProfile(userId int64, currentUserId int64) (User, int64, error) {
	var profile User
	err := repository.db.QueryRow(context.Background(),
		"SELECT id, ver, blacklisted, sex, followers_count, verified, no_ads, can_upload_shot, pro, type, first_name, last_name, middle_name, username, password_hash, bdate, phone, email, html_url, avatar_url, bio, location, created_at, updated_at FROM users WHERE id = $1", userId).
		Scan(&profile.ID, &profile.Version, &profile.Blacklisted, &profile.Sex, &profile.FollowersCount, &profile.Verified, &profile.NoAds, &profile.CanUploadShot, &profile.Pro, &profile.Type, &profile.FirstName, &profile.LastName, &profile.MiddleName, &profile.Username, &profile.PasswordHash, &profile.Bdate, &profile.Phone, &profile.Email, &profile.HTMLURL, &profile.AvatarURL, &profile.Bio, &profile.Location, &profile.CreatedAt, &profile.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return profile, 0, fmt.Errorf("пользователь с id %d не найден", userId)
		}
		return profile, 0, err
	}
	err = repository.db.QueryRow(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM subscriptions WHERE follower_id = $1 AND followed_id = $2)",
		currentUserId, userId).Scan(&profile.IsFollowing)
	if err != nil {
		return profile, 0, err
	}
	err = repository.db.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM subscriptions WHERE followed_id = $1",
		userId).Scan(&profile.FollowersCount)
	if err != nil {
		return profile, 0, err
	}
	var subscriptionsCount int64
	err = repository.db.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM subscriptions WHERE follower_id = $1",
		userId).Scan(&subscriptionsCount)
	if err != nil {
		return profile, 0, err
	}
	return profile, subscriptionsCount, nil
}

func (repository *UserRepository) GetUserSkills(userID int64) ([]Skill, error) {
	rows, err := repository.db.Query(context.Background(), `
        SELECT category_id, id 
        FROM user_skills 
        WHERE user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("ошибка получения навыков пользователя: %v", err)
	}
	defer rows.Close()
	var skills []Skill
	for rows.Next() {
		var skill Skill
		if err := rows.Scan(&skill.CategoryID, &skill.SkillID); err != nil {
			return nil, fmt.Errorf("ошибка сканирования навыка: %v", err)
		}
		if skills == nil {
			skills = []Skill{}
		}
		skills = append(skills, skill)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при итерации по результатам: %v", err)
	}
	return skills, nil
}

func (repository *UserRepository) GetWorkPreferences(ctx context.Context, userId int64) (*WorkPreferences, error) {
	var wp WorkPreferences
	row := repository.db.QueryRow(ctx, `
		SELECT id, user_id, availability, location, specialties, skills 
		FROM user_work_preferences WHERE user_id = $1`, userId)
	var specialtiesJSON, skillsJSON []byte
	err := row.Scan(&wp.UserID, &wp.UserID, &wp.Availability, &wp.Location, &specialtiesJSON, &skillsJSON)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("не удалось получить рабочие предпочтения: %v", err)
	}
	if err := json.Unmarshal(specialtiesJSON, &wp.Specializations); err != nil {
		return nil, fmt.Errorf("не удалось преобразовать специальности из JSON: %v", err)
	}
	if err := json.Unmarshal(skillsJSON, &wp.Skills); err != nil {
		return nil, fmt.Errorf("не удалось преобразовать навыки из JSON: %v", err)
	}
	return &wp, nil
}

func (repository *UserRepository) isBlocked(blockerID, blockedID int64) (bool, error) {
	var exists bool
	err := repository.db.QueryRow(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2)",
		blockerID, blockedID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("ошибка проверки блокировки пользователя: %v", err)
	}
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

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if ok := errors.As(err, &pgErr); ok {
		return pgErr.Code == "23505"
	}
	return false
}

func (repository *UserRepository) passwordIsValidEmail(pass string, row pgx.Row) (*User, error) {
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Version, &user.PasswordHash)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	match, err := ComparePasswordAndHash(pass, user.PasswordHash)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if !match {
		return nil, ErrInvalidCredentials
	}
	return &user, nil
}

var ErrInvalidCredentials = errors.New("неверные учетные данные")

func ComparePasswordAndHash(pass, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
	if err != nil {
		return false, err
	}
	return true, nil
}

func (repository *UserRepository) passwordIsValid(pass string, row pgx.Row) (*User, error) {
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Version, &user.PasswordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("пользователь не найден")
		}
		return nil, fmt.Errorf("ошибка при сканировании данных пользователя: %w", err)
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(pass))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return nil, errors.New("неправильный пароль")
		}
		return nil, fmt.Errorf("ошибка при проверке пароля: %w", err)
	}
	return &user, nil
}

func (repository *UserRepository) ReadVerificationCode(ctx context.Context, email string) (*VerifyCode, error) {
	code := &VerifyCode{}
	query := `
        SELECT id, email, code
        FROM verify_codes
        WHERE email = $1
        LIMIT 1
    `
	err := repository.db.QueryRow(ctx, query, email).Scan(&code.ID, &code.Email, &code.Code)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("проверочный код для электронного адреса %s не найден", email)
		}
		return nil, fmt.Errorf("ошибка при получении проверочного кода: %w", err)
	}
	return code, nil
}

func (repository *UserRepository) saveCompanyInfo(name, logoURL, websiteURL string) error {
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

func (repository *UserRepository) SendMessage(ctx context.Context, senderId, recipientId int64, message string) error {
	if len(message) > 500 {
		return fmt.Errorf("сообщение слишком длинное (длина:= %d символов)", len(message))
	}
	insertQuery := `
        INSERT INTO messages (sender_id, recipient_id, content)
        VALUES ($1, $2, $3)
    `
	_, err := repository.db.Exec(ctx, insertQuery, senderId, recipientId, message)
	if err != nil {
		return fmt.Errorf("ошибка при сохранении сообщения: %w", err)
	}
	return nil
}

func (repository *UserRepository) DeleteUserServices(ctx context.Context, userID int64) error {
	result, err := repository.db.Exec(ctx, `DELETE FROM user_services WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("ошибка удаления услуг пользователя с ID %d: %v", userID, err)
	}
	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("услуги для пользователя с ID %d не найдены", userID)
	}
	return nil
}

func (repository *UserRepository) InsertUserServices(ctx context.Context, userServices []UserService) ([]int64, error) {
	var newIDs []int64
	if len(userServices) == 0 {
		return newIDs, nil
	}
	userID := userServices[0].UserID
	tx, err := repository.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("ошибка начала транзакции: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		}
		if err != nil {
			rollbackErr := tx.Rollback(ctx)
			if rollbackErr != nil {
				err = fmt.Errorf("%w, rollback error: %v", err, rollbackErr)
			}
		} else {
			commitErr := tx.Commit(ctx)
			if commitErr != nil {
				err = fmt.Errorf("ошибка фиксации изменений: %w", commitErr)
			}
		}
	}()
	if _, err = tx.Exec(ctx, `
        DELETE FROM user_services WHERE user_id = $1
    `, userID); err != nil {
		return nil, fmt.Errorf("ошибка удаления существующих услуг пользователя с ID %d: %w", userID, err)
	}
	for _, service := range userServices {
		var newID int64
		err = tx.QueryRow(ctx, `
            INSERT INTO user_services (user_id, category_id, subcategory_ids, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
        `, service.UserID, service.CategoryID, service.SubcategoryIDs, service.CreatedAt, service.UpdatedAt).
			Scan(&newID)
		if err != nil {
			return nil, fmt.Errorf("ошибка вставки услуги для пользователя с ID %d: %w", service.UserID, err)
		}
		newIDs = append(newIDs, newID)
	}
	return newIDs, nil
}

func (repository *UserRepository) fetchUserServices(userID int64) ([]UserService, error) {
	ctx := context.Background()
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
		return nil, fmt.Errorf("ошибка выполнения запроса: %v", err)
	}
	defer rows.Close()
	var userServices []UserService
	for rows.Next() {
		var userService UserService
		var subcategoryIDs pq.Int64Array
		if err = rows.Scan(&userService.ID, &userService.UserID, &userService.CategoryID, &userService.CategoryName, &subcategoryIDs); err != nil {
			return nil, fmt.Errorf("ошибка сканирования строки: %v", err)
		}
		userService.SubcategoryIDs = subcategoryIDs
		userServices = append(userServices, userService)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при переборе строк: %v", err)
	}
	return userServices, nil
}

func (repository *UserRepository) GetAllCategoriesAndSubcategories(userID int64) (UserSpecialtyResponse, error) {
	userServices, err := repository.fetchUserServices(userID)
	if err != nil {
		return UserSpecialtyResponse{}, fmt.Errorf("ошибка получения услуг пользователя: %v", err)
	}
	response := UserSpecialtyResponse{
		UserID:       userID,
		UserServices: []UserService{},
	}
	categoryMap := make(map[int]UserService)
	for _, userService := range userServices {
		if existingService, exists := categoryMap[userService.CategoryID]; exists {
			existingService.SubcategoryIDs = append(existingService.SubcategoryIDs, userService.SubcategoryIDs...)
			categoryMap[userService.CategoryID] = existingService
		} else {
			categoryMap[userService.CategoryID] = userService
		}
	}
	for _, service := range categoryMap {
		response.UserServices = append(response.UserServices, service)
	}
	return response, nil
}

func (repository *UserRepository) RemoveSubcategoryFromUserService(ctx context.Context, userID int64, subcategoryID int64) error {
	_, err := repository.db.Exec(ctx,
		`UPDATE user_services 
		 SET subcategory_ids = array_remove(subcategory_ids, $1)
		 WHERE user_id = $2 AND $1 = ANY(subcategory_ids)`,
		subcategoryID, userID)
	if err != nil {
		return fmt.Errorf("ошибка удаления подкатегории: %v", err)
	}
	var categoryID int64
	err = repository.db.QueryRow(ctx,
		`SELECT category_id FROM subcategories WHERE id = $1`, subcategoryID).Scan(&categoryID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return fmt.Errorf("ошибка получения категории для подкатегории: %v", err)
	}
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

func (repository *UserRepository) SubscribeUser(followerId, followedId int64, ctx context.Context) error {
	_, err := repository.db.Exec(ctx,
		"INSERT INTO subscriptions (follower_id, followed_id) VALUES ($1, $2)",
		followerId, followedId)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("подписка уже существует для follower_id: %d и followed_id: %d", followerId, followedId)
		}
		return fmt.Errorf("не удалось добавить подписку: %w", err)
	}
	return nil
}

func (repository *UserRepository) unblockUser(blockerID, blockedID int64) error {
	_, err := repository.db.Exec(context.Background(), "DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2", blockerID, blockedID)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("пользователь с ID %d не был заблокирован пользователем с ID %d", blockedID, blockerID)
		} else if errors.Is(err, context.Canceled) {
			return fmt.Errorf("операция была отменена: %w", err)
		} else if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("время выполнения запроса истекло: %w", err)
		}
		return fmt.Errorf("не удалось разблокировать пользователя: %w", err)
	}
	return nil
}

func (repository *UserRepository) UnsubscribeUser(currentUserId int64, followedId int64, ctx context.Context) error {
	var exists bool
	err := repository.db.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM subscriptions WHERE follower_id = $1 AND followed_id = $2)",
		currentUserId, followedId).Scan(&exists)
	if err != nil {
		return fmt.Errorf("не удалось проверить существование подписки: %w", err)
	}
	if !exists {
		return fmt.Errorf("подписка не найдена для пользователя с ID %d на пользователя с ID %d", currentUserId, followedId)
	}
	result, err := repository.db.Exec(ctx,
		"DELETE FROM subscriptions WHERE follower_id = $1 AND followed_id = $2",
		currentUserId, followedId)
	if err != nil {
		return fmt.Errorf("не удалось отменить подписку: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("не удалось отменить подписку, возможно она уже была отменена")
	}
	return nil
}

func (repository *UserRepository) UpdateEmail(ctx context.Context, userID int64, userEmail string) error {
	_, err := repository.db.Exec(ctx, "UPDATE users SET email = $1 WHERE id = $2", userEmail, userID)
	return err
}

func (repository *UserRepository) updateExportDate(ctx context.Context, userID int64) error {
	query := `
		INSERT INTO exports (user_id, export_date)
		VALUES ($1, CURRENT_TIMESTAMP)
		ON CONFLICT (user_id) DO UPDATE SET export_date = CURRENT_TIMESTAMP;`
	if _, err := repository.db.Exec(ctx, query, userID); err != nil {
		return fmt.Errorf("ошибка при обновлении даты экспорта: %w", err)
	}
	return nil
}

func (repository *UserRepository) UpdateThePasswordInTheSettings(ctx context.Context, userID int64, newPassword string) error {
	var currentPasswordHash string
	err := repository.db.QueryRow(ctx, "SELECT password_hash FROM users WHERE id = $1", userID).Scan(&currentPasswordHash)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("пользователь с ID %d не найден", userID)
		}
		return fmt.Errorf("ошибка при получении текущего пароля пользователя: %w", err)
	}
	if err := comparePasswords(currentPasswordHash, newPassword); err != nil {
		return err
	}
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

func (repository *UserRepository) UpdateProfile(userID int64, firstName, lastName, middleName, location, bio string, noAds bool) error {
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

func (repository *UserRepository) updateUserLinks(ctx context.Context, userID int64, vk, telegram, whatsapp, web, twitter string) error {
	links := UserLinks{
		VK:       vk,
		Telegram: telegram,
		WhatsApp: whatsapp,
		Web:      web,
		Twitter:  twitter,
	}
	userLinksCache.Store(userID, links)
	if _, err := repository.db.Exec(ctx,
		`UPDATE users SET links = $1 WHERE id = $2`,
		links,
		userID,
	); err != nil {
		return fmt.Errorf("ошибка обновления ссылок пользователя: %w", err)
	}
	return nil
}

func (repository *UserRepository) UpdateUserSkills(userID int64, skills []int) error {
	_, err := repository.db.Exec(context.Background(), `
        DELETE FROM user_skills 
        WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("ошибка удаления старых навыков пользователя: %v", err)
	}
	if len(skills) == 0 {
		return nil
	}
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

func (repository *UserRepository) UpdateUser(ctx context.Context, userID int64, username *string, email string, noAds bool) error {
	var exists bool
	err := repository.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)", userID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("ошибка при проверке существования пользователя: %w", err)
	}
	if !exists {
		return fmt.Errorf("пользователь с ID %d не найден", userID)
	}
	if username != nil {
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

func (repository *UserRepository) UserExists(ctx context.Context, userID int64) (bool, error) {
	var exists bool
	err := repository.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("ошибка проверки существования пользователя: %v", err)
	}
	return exists, nil
}

func (repository *UserRepository) Users(ctx context.Context) ([]*User, error) {
	query := `
        SELECT 
            id, ver, blacklisted, followers_count, sex, username, 
            first_name, last_name, middle_name, password_hash, location, bio, bdate, phone, email, avatar_url, 
            verified, no_ads, can_upload_shot, pro, created_at, updated_at
        FROM users
        ORDER BY random();
    `
	rows, err := repository.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("ошибка выполнения запроса: %w", err)
	}
	defer rows.Close()
	var users []*User
	for rows.Next() {
		user := &User{}
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
		users = append(users, user)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при итерации по результатам: %w", err)
	}
	return users, nil
}

func (repository *UserRepository) Verified(email string) error {
	if repository == nil {
		return fmt.Errorf("указатель на репозиторий равен нулю")
	}
	if repository.db == nil {
		return fmt.Errorf("соединение с базой данных равно нулю")
	}
	ctx := context.Background()
	_, err := repository.db.Exec(ctx, SQL_UPDATE_VERIFIED, email)
	if err != nil {
		errFmt := fmt.Errorf("не удалось обновить статус верификации: %v", err.Error())
		fmt.Println(errFmt.Error())
		return errFmt
	}
	return nil
}
