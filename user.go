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
