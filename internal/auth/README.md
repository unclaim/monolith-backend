# events.go - Газета Новостей Домика
Представьте, что каждый домик в нашем большом доме издает свою собственную газету новостей. В этой газете они публикуют объявления о важных событиях, которые произошли внутри их домика. Например, домик "Авторизация" может объявить: "Новый пользователь зарегистрировался!". Другие домики, которым интересны эти новости (например, домик "Уведомления", чтобы отправить приветственное письмо, или домик "Геймификация", чтобы начислить бонус за регистрацию), могут подписаться на эти новости.
Где это: your-ultra-scalable-monolith/internal/ДОМЕН/events.go (например, internal/auth/events.go)
Что здесь:
Определение событий: Это как шаблоны для статей в газете. Здесь мы описываем, как выглядит каждая новость. Например, новость о регистрации пользователя будет содержать его ID и Email.
Тип события: Каждая новость имеет свой "заголовок" или "тему", чтобы другие домики знали, о чем эта новость, и могли решить, стоит ли ее читать.
Как это работает:
Когда в домике происходит что-то важное (например, пользователь успешно зарегистрировался), "главный работник" (сервис) этого домика "публикует" соответствующую новость в своей газете.
Газета (наша событийная шина pkg/infrastructure/eventbus) рассылает эту новость всем, кто на нее подписан.
"Подписчики" (другие сервисы из других домиков), получив новость, могут выполнить какие-то действия в ответ.
Это очень мощный механизм, потому что домик, который публикует новость, не знает и не заботится о том, кто ее будет читать и что с ней делать. Он просто объявляет о событии. Это делает наши домики независимыми друг от друга.
Пример (internal/auth/events.go):

```go
package auth

import "fmt"

// UserRegisteredEvent - это событие, которое публикуется, когда новый пользователь успешно зарегистрирован.
// Оно содержит минимально необходимую информацию для других доменов.
type UserRegisteredEvent struct {
	UserID string // ID зарегистрированного пользователя
	Email  string // Email зарегистрированного пользователя
}

// EventType - это метод, который возвращает уникальный тип события.
// Это как заголовок статьи в газете.
func (UserRegisteredEvent) EventType() string {
	return "auth.UserRegistered"
}

// String - это вспомогательный метод для удобного вывода события.
func (e UserRegisteredEvent) String() string {
	return fmt.Sprintf("UserRegisteredEvent { UserID: %s, Email: %s }", e.UserID, e.Email)
}

// EmailVerifiedEvent - событие, когда email пользователя подтвержден.
type EmailVerifiedEvent struct {
	UserID string
	Email  string
}

func (EmailVerifiedEvent) EventType() string {
	return "auth.EmailVerified"
}

func (e EmailVerifiedEvent) String() string {
	return fmt.Sprintf("EmailVerifiedEvent { UserID: %s, Email: %s }", e.UserID, e.Email)
}

// UserLoggedInEvent - событие, когда пользователь успешно вошел в систему.
type UserLoggedInEvent struct {
	UserID    string
	SessionID string
	ClientIP  string
}

func (UserLoggedInEvent) EventType() string {
	return "auth.UserLoggedIn"
}

func (e UserLoggedInEvent) String() string {
	return fmt.Sprintf("UserLoggedInEvent { UserID: %s, SessionID: %s, ClientIP: %s }", e.UserID, e.SessionID, e.ClientIP)
}

// PasswordChangedEvent - событие, когда пользователь изменил свой пароль.
type PasswordChangedEvent struct {
	UserID string
}

func (PasswordChangedEvent) EventType() string {
	return "auth.PasswordChanged"
}

func (e PasswordChangedEvent) String() string {
	return fmt.Sprintf("PasswordChangedEvent { UserID: %s }", e.UserID)
}

// ... другие события, специфичные для домена Auth ...

```

Это позволяет нам строить гибкое и масштабируемое приложение, где добавление новой функциональности (например, "начисление очков за регистрацию") не требует изменения уже работающего кода в домене auth, а просто добавления нового "подписчика" в домене gamification.
Надеюсь, это описание событийной части делает картину еще более полной! Хотели бы вы, чтобы я показал, как один домен может "подписываться" на события другого домена?
