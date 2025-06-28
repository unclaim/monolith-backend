Проект "Proposal Management System"
Данный проект представляет собой бэкенд-систему для управления предложениями (Proposals), разработанную на Go. Система позволяет пользователям создавать, просматривать, обновлять и удалять предложения, управлять статусами предложений (черновик, на рассмотрении, утверждено, отклонено, архивировано), а также назначать участников с различными ролями к каждому предложению.
1. Основные функции проекта
Проект предоставляет следующие ключевые возможности:
 * Управление пользователями: Регистрация, аутентификация (на основе JWT или сессий в БД), управление профилями, получение информации о пользователях.
 * Управление задачами: Создание, просмотр, обновление, удаление задач, назначение задач пользователям, управление статусами задач.
 * Управление вложениями: Загрузка и скачивание файлов-вложений, связанных с задачами.
 * Управление предложениями:
   * CRUD-операции: Создание, получение, обновление и удаление предложений.
   * Управление статусами: Перевод предложений между статусами (draft, pending, approved, rejected, archived) с соблюдением бизнес-правил переходов.
   * Управление участниками: Добавление, удаление и обновление ролей пользователей, связанных с предложениями (владелец, участник, рецензент).
   * Авторизация: Строгая проверка прав доступа на все операции с предложениями и их участниками.
2. Структура проекта
Проект организован по принципу модульной архитектуры, где каждый основной функциональный блок (например, пользователи, задачи, предложения) имеет свою собственную структуру, включающую модели, DTO, репозитории, сервисы и API-хендлеры.
.
├── cmd/
│   └── main.go                  # Точка входа в приложение, инициализация всех компонентов
├── configs/
│   └── config.go                # Определение структуры конфигурации и загрузка из переменных окружения
├── internal/
│   ├── app/                     # Основная логика приложения, разбитая по доменам/модулям
│   │   ├── proposal/            # Модуль управления предложениями
│   │   │   ├── api/             # API-хендлеры для обработки HTTP-запросов (REST)
│   │   │   │   └── handler.go   # Методы: CreateProposal, GetProposalByID, UpdateProposal, DeleteProposal,
│   │   │   │                    #           ApproveProposal, RejectProposal, ArchiveProposal,
│   │   │   │                    #           AddMemberToProposal, GetMembersForProposal,
│   │   │   │                    #           UpdateProposalMemberRole, RemoveMemberFromProposal
│   │   │   ├── dto/             # Data Transfer Objects (DTOs) для запросов и ответов API
│   │   │   │   └── dto.go       # Structs: CreateProposalRequest, UpdateProposalRequest,
│   │   │   │                    #           GetProposalsFilter, AddProposalMemberRequest,
│   │   │   │                    #           ProposalResponse, ProposalMemberResponse
│   │   │   ├── migrations/      # SQL-миграции для базы данных (таблицы 'proposals', 'proposal_members')
│   │   │   │   └── *.sql
│   │   │   ├── model/           # Go-модели, представляющие структуры данных в БД
│   │   │   │   └── model.go     # Structs: Proposal, ProposalMember (с константами статусов и ролей)
│   │   │   └── repository/      # Репозитории для взаимодействия с базой данных (PostgreSQL)
│   │   │       └── repository.go# Interfaces: ProposalRepository, ProposalMemberRepository
│   │   │                        # Implementations: PGProposalRepository, PGProposalMemberRepository
│   │   ├── file_storage/        # Модуль для работы с файловым хранилищем
│   │   │   ├── api/
│   │   │   │   └── handler.go   # ServeAttachmentFile
│   │   │   └── service/
│   │   │       └── service.go   # SaveFile, GetFile, DeleteFile
│   │   ├── shared/              # Общие утилиты и компоненты, используемые в нескольких модулях
│   │   │   ├── auth/            # Аутентификация и авторизация
│   │   │   │   ├── api/
│   │   │   │   │   └── handler.go # RegisterUser, LoginUser, RefreshTokens, GetCSRFToken, LogoutUser
│   │   │   │   └── auth.go      # AuthService interface and implementation
│   │   │   ├── database/        # Инициализация подключения к БД
│   │   │   │   └── db.go
│   │   │   ├── server/          # Утилиты для HTTP-сервера (ответы, обработка ошибок)
│   │   │   │   └── server.go    # SendJSONResponse, SendErrorResponse, Error structures
│   │   │   ├── session/         # Управление сессиями (JWT/Database)
│   │   │   │   └── session.go
│   │   │   └── token/           # Управление токенами (JWT, CSRF)
│   │   │       └── token.go
│   │   ├── task/                # Модуль управления задачами
│   │   │   ├── api/
│   │   │   │   └── handler.go   # CreateTask, GetTasks, GetTaskByID, UpdateTask, DeleteTask,
│   │   │   │                    #   AssignTask, UnassignTask, CompleteTask, UploadTaskAttachment,
│   │   │   │                    #   DeleteTaskAttachment
│   │   │   ├── dto/
│   │   │   │   └── dto.go       # Request/Response DTOs for tasks and attachments
│   │   │   ├── migrations/
│   │   │   │   └── *.sql
│   │   │   ├── model/
│   │   │   │   └── model.go     # Task, TaskAttachment models
│   │   │   ├── repository/
│   │   │   │   └── repository.go# TaskRepository, TaskAttachmentRepository
│   │   │   └── service/
│   │   │       └── service.go   # TaskService implementation
│   │   └── user/                # Модуль управления пользователями
│   │       ├── api/
│   │       │   └── handler.go   # GetCurrentUser, UpdateUserProfile, GetUserByID
│   │       ├── dto/
│   │       │   └── dto.go       # Request/Response DTOs for users
│   │       ├── migrations/
│   │       │   └── *.sql
│   │       ├── model/
│   │       │   └── model.go     # User, UserRelationship, Message models
│   │       ├── repository/
│   │       │   └── repository.go# UserRepository, UserRelationshipRepository, MessageRepository
│   │       └── service/
│   │           └── service.go   # UserService implementation
│   └── router/                  # Централизованное управление HTTP-маршрутами и middleware
│       └── router.go            # InitRoutes, CorsMiddleware, AuthMiddleware, CSRFMiddleware

3. Общие принципы проектирования
 * Модульность: Приложение разделено на независимые модули, каждый из которых отвечает за свою область бизнес-логики.
 * Слоистая архитектура: Каждый модуль следует принципу Clean Architecture или Onion Architecture, с четким разделением на:
   * API (Handlers): Обработка HTTP-запросов, парсинг DTO, вызов сервисов, форматирование HTTP-ответов.
   * Service (Business Logic): Инкапсулирует бизнес-правила, валидацию, координацию между репозиториями.
   * Repository (Data Access): Абстрагирует доступ к базе данных, выполняет SQL-запросы.
   * Model: Определяет структуры данных, напрямую отображающие таблицы базы данных.
   * DTO (Data Transfer Objects): Используются для передачи данных между слоями и для API-контрактов.
 * Контекст (context.Context): Используется для передачи контекста запроса (отмена, таймауты, данные пользователя) между слоями приложения.
 * Обработка ошибок: Возвращаются типизированные ошибки из сервисного слоя, которые затем преобразуются в соответствующие HTTP-статусы в API-хендлерах.
 * Аутентификация и авторизация: Централизованная система аутентификации (JWT или сессии в БД) и middleware для защиты маршрутов. Авторизация (проверка прав доступа) реализована в сервисном слое.
 * Валидация: Используется библиотека github.com/go-playground/validator/v10 с тегами в DTO для валидации входящих запросов.
 * Пагинация и фильтрация: Реализованы для списочных запросов (например, получение предложений, задач) через DTO-фильтры и параметры запроса URL.
 * Конфигурация: Загрузка настроек приложения из переменных окружения для гибкости развертывания.
 * Миграции базы данных: Используется pressly/goose для управления схемами базы данных.
4. Как начать
 * Клонируй репозиторий:
   git clone <URL_твоего_репозитория>
cd <имя_проекта>

 * Настрой переменные окружения: Создай файл .env (или экспортируй переменные) с как минимум DATABASE_URL, JWT_SECRET (или SESSION_TYPE=database), CSRF_SECRET и PORT. Пример:
   DATABASE_URL="postgres://user:password@localhost:5432/yourdb?sslmode=disable"
JWT_SECRET="supersecretjwtkey"
CSRF_SECRET="supersecretcsrfkey"
PORT=8080

 * Установи зависимости Go:
   go mod tidy

 * Выполни миграции базы данных:
   go install github.com/pressly/goose/v3/cmd/goose@latest # Если goose не установлен
goose -dir internal/app/user/migrations postgres "$DATABASE_URL" up
goose -dir internal/app/task/migrations postgres "$DATABASE_URL" up
goose -dir internal/app/proposal/migrations postgres "$DATABASE_URL" up
# Если используешь сессии в БД:
goose -dir internal/app/shared/session/migrations postgres "$DATABASE_URL" up

 * Запусти приложение:
   go run cmd/main.go

   Сервер будет доступен по адресу http://localhost:8080 (или на указанном порту).
Этот файл предоставляет общее понимание проекта, его структуры и функциональности. Он может быть расширен дополнительными секциями, такими как "Тестирование", "Развертывание", "API-документация" и т.д., по мере развития проекта.

