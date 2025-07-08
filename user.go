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
