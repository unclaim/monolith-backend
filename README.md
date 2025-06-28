# Платформа "TaskFlow"

## Описание платформы

**TaskFlow** — это современная децентрализованная платформа для создания, управления и выполнения задач, а также для публикации и реагирования на предложения (пропозалы). Она разработана с учетом масштабируемости, безопасности и удобства использования, предоставляя разделенный доступ для обычных пользователей и администраторов/модераторов.

**Основные концепции:**

* **Задачи:** Пользователи могут создавать задачи, описывая необходимую работу, и назначать их другим пользователям. Задачи могут иметь различные статусы (в процессе, выполнено, отменено).
* **Предложения (Пропозалы):** Пользователи могут публиковать предложения о проектах или услугах, а другие пользователи могут откликаться на них, чтобы предложить свои услуги или идеи.
* **Социальное взаимодействие:** Платформа включает базовые функции социального взаимодействия, такие как друзья и личные сообщения.
* **Ролевая модель:** Поддерживает различные роли пользователей (пользователь, администратор, модератор), что обеспечивает гибкий контроль доступа к функциям платформы.
* **Раздельные Gateway:** Для повышения безопасности и управляемости запросы обычных пользователей и администраторов обрабатываются через отдельные API-шлюзы.

## Стек технологий

* **Backend:** Go (Golang)
* **База данных:** PostgreSQL
* **Кэширование/Online Status:** Redis
* **HTTP-роутер:** Gorilla Mux
* **Логирование:** Logrus (структурированные логи)
* **Метрики:** Prometheus (сбор метрик производительности)
* **Мониторинг:** Grafana (визуализация метрик)
* **Докер:** Docker Compose (для локального развертывания и управления сервисами)

## Структура проекта

Проект состоит из трех основных компонентов, каждый из которых является отдельным Go-модулем:


.
├── public-gateway/         # API Gateway для обычных пользователей
│   ├── cmd/                # Точка входа приложения
│   │   └── main.go
│   ├── configs/            # Конфигурация приложения
│   ├── internal/           # Внутренняя логика Gateway
│   │   ├── clients/        # HTTP-клиенты для взаимодействия с монолитом
│   │   ├── handlers/       # Обработчики HTTP-запросов (аутентификация, проксирование)
│   │   ├── proxy/          # Логика проксирования запросов
│   │   └── shared/         # Общие утилиты (логирование, метрики, ошибки)
│   └── go.mod              # Определение Go-модуля
│
├── admin-gateway/          # API Gateway для администраторов и модераторов
│   ├── cmd/
│   │   └── main.go
│   ├── configs/
│   ├── internal/
│   │   ├── clients/
│   │   ├── handlers/
│   │   ├── proxy/
│   │   └── shared/
│   └── go.mod
│
└── monolith-backend/       # Монолитный Backend-сервис
├── cmd/                # Точка входа приложения
│   └── main.go
├── configs/            # Конфигурация приложения
├── internal/           # Внутренняя логика монолита
│   ├── app/            # Модули приложения (пользователи, задачи, предложения, онлайн-статус)
│   │   ├── online_status/ # Сервис и хранилище для отслеживания онлайн-статуса
│   │   ├── proposal/      # Модуль предложений (API, сервис, репозиторий, DTO, модель)
│   │   ├── shared/        # Общие компоненты приложения (аутентификация, БД, сессии, токены, логи, метрики, ошибки)
│   │   ├── task/          # Модуль задач
│   │   └── user/          # Модуль пользователей
│   └── router/         # Настройка HTTP-маршрутов и middleware
└── go.mod              # Определение Go-модуля

## Функциональные возможности платформы

### Для всех пользователей (через `public-gateway` на порту `8080`)

* **Аутентификация и Авторизация:**
    * Регистрация нового пользователя.
    * Вход в систему (логин).
    * Выход из системы (логаут).
    * Обновление JWT-токенов (для поддержания сессии).
    * Получение CSRF-токена.
* **Управление Профилем:**
    * Получение информации о собственном профиле (`/users/me`).
    * Получение информации о профиле другого пользователя по ID (`/users/{id}`).
    * Обновление собственного профиля.
* **Социальное взаимодействие:**
    * Отправка запроса на дружбу.
    * Принятие/отклонение запроса на дружбу.
    * Удаление из друзей.
    * Просмотр списка друзей.
    * Отправка личных сообщений.
    * Просмотр истории сообщений с конкретным пользователем.
* **Задачи:**
    * Создание новой задачи.
    * Просмотр списка всех задач.
    * Просмотр информации о конкретной задаче по ID.
    * Обновление задачи (только для автора/исполнителя).
    * Удаление задачи (только для автора).
    * Назначение задачи другому пользователю.
    * Отметка задачи как выполненной.
* **Предложения (Пропозалы):**
    * Создание нового предложения.
    * Просмотр списка всех предложений.
    * Просмотр информации о конкретном предложении по ID.
    * Обновление предложения.
    * Удаление предложения.
    * Принятие предложения.
    * Отклонение предложения.
* **Статус Онлайн:**
    * Автоматическое обновление статуса "онлайн" при активности пользователя.
    * Получение статуса "онлайн" для конкретного пользователя (`/users/{id}/online-status`).
    * Статус "онлайн" отображается в информации о пользователе (`/users/me`, `/users/{id}`).

### Для администраторов и модераторов (через `admin-gateway` на порту `8082`)

* **Управление Пользователями (только для роли `admin`):**
    * Получение списка всех зарегистрированных пользователей.
    * Блокировка пользователя.
    * Разблокировка пользователя.
    * Изменение роли пользователя (например, из `user` в `moderator` или `admin`).
* **Модерация Контента (для ролей `admin` и `moderator`):**
    * Просмотр списка задач, требующих модерации.
    * Одобрение задачи.
    * Отклонение задачи.
    * Просмотр списка предложений, требующих модерации.
    * Одобрение предложения.
    * Отклонение предложения.
* **Системная статистика (только для роли `admin`):**
    * Получение общей статистики по системе (например, количество пользователей, задач, предложений).

## Детальное описание кода

Ниже представлены ключевые файлы и их назначение, демонстрирующие, как реализован функционал.

### 1. Public Gateway (`public-gateway/`)

Этот Gateway обрабатывает все запросы от обычных пользователей. Он проксирует запросы к `monolith-backend` после аутентификации и добавления заголовков `X-User-ID` и `X-User-Role`.

* **Точка входа: `public-gateway/cmd/main.go`**
    * [Link to code (Line X-Y)](public-gateway/cmd/main.go)
    * Инициализирует конфигурацию, логгер, сервис аутентификации, CSRF-менеджер и HTTP-сервер.
    * Настраивает маршруты и применяет middleware (CORS, Recovery, Logging, Metrics, Auth, CSRF).
    * Слушает на порту `8080`.
* **Конфигурация: `public-gateway/configs/config.go`**
    * [Link to code (Line X-Y)](public-gateway/configs/config.go)
    * Загружает переменные окружения (`GATEWAY_PORT`, `BACKEND_URL`, `JWT_SECRET`, `CSRF_SECRET`, `LOG_LEVEL`).
* **Обработчики запросов: `public-gateway/internal/handlers/`**
    * `auth_handler.go`: Обрабатывает запросы на регистрацию, логин, логаут, обновление токенов, получение CSRF-токена. Перенаправляет их на `/internal` эндпоинты монолита.
        * [Link to code (Line X-Y)](public-gateway/internal/handlers/auth_handler.go)
    * `proxy_handler.go`: Основной обработчик, который проксирует все остальные запросы к монолиту, добавляя заголовки `X-User-ID` и `X-User-Role`.
        * [Link to code (Line X-Y)](public-gateway/internal/handlers/proxy_handler.go)
* **Middleware аутентификации: `public-gateway/internal/shared/auth/middleware.go`**
    * [Link to code (Line X-Y)](public-gateway/internal/shared/auth/middleware.go)
    * Валидирует JWT-токен из куки, извлекает `userID` и `userRole`, и добавляет их в контекст запроса, а также в заголовки `X-User-ID` и `X-User-Role` для монолита.
* **Метрики: `public-gateway/internal/shared/metrics/`**
    * `metrics.go`: Определяет Prometheus-метрики (счетчики, гистограммы, gauge).
        * [Link to code (Line X-Y)](public-gateway/internal/shared/metrics/metrics.go)
    * `middleware.go`: HTTP-middleware для сбора этих метрик для каждого запроса.
        * [Link to code (Line X-Y)](public-gateway/internal/shared/metrics/middleware.go)
* **Логирование: `public-gateway/internal/shared/logger/init.go`**
    * [Link to code (Line X-Y)](public-gateway/internal/shared/logger/init.go)
    * Инициализация `logrus` для структурированного логирования.

### 2. Admin Gateway (`admin-gateway/`)

Этот Gateway предназначен исключительно для администраторов и модераторов. Он слушает на другом порту (`8082`) и включает дополнительную проверку ролей на уровне Gateway.

* **Точка входа: `admin-gateway/cmd/main.go`**
    * [Link to code (Line X-Y)](admin-gateway/cmd/main.go)
    * Аналогичен `public-gateway/cmd/main.go`, но с портом `8082`.
    * **Ключевое отличие:** Включает дополнительный middleware, который проверяет, что роль пользователя (`X-User-Role`) является `admin` или `moderator`, прежде чем проксировать запрос к монолиту.
        * [Link to code (See `authRouter.Use` section for role check`)](admin-gateway/cmd/main.go)
* **Конфигурация: `admin-gateway/configs/config.go`**
    * [Link to code (Line X-Y)](admin-gateway/configs/config.go)
    * Аналогична `public-gateway`, но с другим портом по умолчанию.
* **Обработчики запросов: `admin-gateway/internal/handlers/auth_handler.go`**
    * [Link to code (Line X-Y)](admin-gateway/internal/handlers/auth_handler.go)
    * В отличие от Public Gateway, этот `auth_handler` **не предоставляет** эндпоинт для регистрации обычных пользователей, так как админы регистрируются или создаются иным путем.

### 3. Monolith Backend (`monolith-backend/`)

Сердце платформы, содержащее всю бизнес-логику, хранение данных и обработку запросов.

* **Точка входа: `monolith-backend/cmd/main.go`**
    * [Link to code (Line X-Y)](monolith-backend/cmd/main.go)
    * Инициализирует подключение к PostgreSQL и Redis.
    * Инициализирует все сервисы, репозитории, менеджеры и обработчики (хендлеры).
    * Настраивает основной HTTP-роутер.
    * Слушает на порту `8081`.
* **Конфигурация: `monolith-backend/configs/config.go`**
    * [Link to code (Line X-Y)](monolith-backend/configs/config.go)
    * Загружает `DATABASE_URL`, `REDIS_URL`, `JWT_SECRET`, `CSRF_SECRET`, `LOG_LEVEL`.
* **Роутер и Middleware: `monolith-backend/internal/router/router.go`**
    * [Link to code (Line X-Y)](monolith-backend/internal/router/router.go)
    * Определяет все API-маршруты платформы.
    * Применяет глобальные middleware (CORS, Recovery, Logging, Metrics).
    * **`authMiddleware`**: Извлекает `userID` и `userRole` из заголовков `X-User-ID` и `X-User-Role`, установленных Gateway, и добавляет их в контекст запроса.
    * **`UserActivityMiddleware`**: Обновляет статус активности пользователя в Redis при каждом аутентифицированном запросе.
    * **Разделение маршрутов по доступу:**
        * `/internal/*`: Маршруты для Gateway (регистрация, логин), без собственной аутентификации монолита.
        * `/api/v1/*`: Основные аутентифицированные маршруты для обычных пользователей.
        * `/api/v1/admin/*`: Маршруты для администраторов/модераторов с дополнительным middleware для проверки ролей.
        * `/api/v1/super-admin/*`: Маршруты только для администраторов с более строгой проверкой ролей.
* **Модуль Пользователей (`monolith-backend/internal/app/user/`)**
    * `model/user.go`: Определяет структуру модели `User` и `UserRole`.
        * [Link to code (Line X-Y)](monolith-backend/internal/app/user/model/user.go)
    * `repository/repository.go`: Интерфейс и реализация репозитория для работы с таблицей `users` в PostgreSQL (CRUD, друзья, сообщения, обновление статуса/роли).
        * `PGUserRepository.GetAllUsers`: [Link to code (Line X-Y)](monolith-backend/internal/app/user/repository/repository.go)
        * `PGUserRepository.UpdateUserStatus`: [Link to code (Line X-Y)](monolith-backend/internal/app/user/repository/repository.go)
        * `PGUserRepository.SetUserRole`: [Link to code (Line X-Y)](monolith-backend/internal/app/user/repository/repository.go)
    * `service/service.go`: Бизнес-логика для пользователей (регистрация, логин, получение/обновление профиля, управление друзьями, отправка сообщений, а также **админские методы BlockUser, UnblockUser, SetUserRole, GetAllUsers**).
        * [Link to code (Line X-Y)](monolith-backend/internal/app/user/service/service.go)
    * `api/handler.go`: HTTP-обработчики для всех пользовательских эндпоинтов, включая новые админские (`GetAllUsers`, `BlockUser`, `UnblockUser`, `SetUserRole`, `GetSystemStats`).
        * [Link to code (Line X-Y)](monolith-backend/internal/app/user/api/handler.go)
    * `dto/dto.go`: Структуры DTO для запросов и ответов (`UserResponse` с полем `IsOnline`, `CreateUserRequest` с валидацией).
        * [Link to code (Line X-Y)](monolith-backend/internal/app/user/dto/dto.go)
* **Модуль Задач (`monolith-backend/internal/app/task/`)**
    * `model/task.go`: Структура `Task`.
    * `repository/repository.go`: CRUD для задач.
    * `service/service.go`: Бизнес-логика для задач, включая методы модерации (`GetTasksForModeration`, `ApproveTask`, `RejectTask`).
    * `api/handler.go`: HTTP-обработчики для задач, включая модерацию.
* **Модуль Предложений (`monolith-backend/internal/app/proposal/`)**
    * `model/proposal.go`: Структура `Proposal`.
    * `repository/repository.go`: CRUD для предложений.
    * `service/service.go`: Бизнес-логика для предложений, включая методы модерации (`GetProposalsForModeration`, `ApproveProposal`, `RejectProposal`).
    * `api/handler.go`: HTTP-обработчики для предложений, включая модерацию.
* **Модуль Онлайн-статуса (`monolith-backend/internal/app/online_status/`)**
    * `redis.go`: Реализация `OnlineStore` для Redis, хранящая время последней активности пользователя.
        * [Link to code (Line X-Y)](monolith-backend/internal/app/online_status/redis.go)
    * `service.go`: Сервис для обновления и получения онлайн-статуса пользователя.
        * [Link to code (Line X-Y)](monolith-backend/internal/app/online_status/service.go)
* **Общие компоненты (`monolith-backend/internal/app/shared/`)**
    * `auth/`: Управление аутентификацией (JWT, роли).
    * `database/`: Инициализация пула соединений PostgreSQL.
    * `token/`: Управление CSRF-токенами.
    * `server/`: Общие утилиты для HTTP-сервера (CORS, Recovery, SendErrorResponse, SendJSONResponse).
        * `errors.go`: [Link to code (Line X-Y)](monolith-backend/internal/app/shared/server/errors.go) (Унифицированные структуры ошибок API).
    * `logger/`: Инициализация `logrus` для структурированного логирования (аналогично Gateway).
        * [Link to code (Line X-Y)](monolith-backend/internal/app/shared/logger/init.go)
    * `metrics/`: Определения Prometheus-метрик и middleware для их сбора (аналогично Gateway).
        * [Link to code (Line X-Y)](monolith-backend/internal/app/shared/metrics/metrics.go)
        * [Link to code (Line X-Y)](monolith-backend/internal/app/shared/metrics/middleware.go)

## Запуск проекта (Docker Compose)

Для удобства развертывания всех компонентов (PostgreSQL, Redis, Prometheus, Grafana, а также Public/Admin Gateways и Monolith Backend) используйте Docker Compose.

1.  **Создайте файлы `.env`** в корневых папках `public-gateway`, `admin-gateway` и `monolith-backend` на основе приведенных в предыдущих шагах. Убедитесь, что `JWT_SECRET` и `CSRF_SECRET` одинаковы во всех компонентах, и порты (`8080`, `8082`, `8081`) не конфликтуют.

2.  **Создайте файл `docker-compose.yml`** в **корневой директории проекта** (где находятся `public-gateway`, `admin-gateway`, `monolith-backend`):

    ```yaml
    # docker-compose.yml
    version: '3.8'

    services:
      db:
        image: postgres:15-alpine
        container_name: postgres_db
        environment:
          POSTGRES_DB: taskflow_db
          POSTGRES_USER: user
          POSTGRES_PASSWORD: password
        ports:
          - "5432:5432"
        volumes:
          - postgres_data:/var/lib/postgresql/data
        healthcheck:
          test: ["CMD-SHELL", "pg_isready -U user -d taskflow_db"]
          interval: 5s
          timeout: 5s
          retries: 5

      redis:
        image: redis/redis-stack-server:latest
        container_name: redis_cache
        ports:
          - "6379:6379"
        healthcheck:
          test: ["CMD", "redis-cli", "ping"]
          interval: 5s
          timeout: 5s
          retries: 5

      monolith-backend:
        build:
          context: ./monolith-backend
          dockerfile: Dockerfile
        container_name: monolith_backend
        ports:
          - "8081:8081"
        environment:
          DATABASE_URL: "postgresql://user:password@db:5432/taskflow_db?sslmode=disable"
          REDIS_URL: "redis://redis:6379/0"
          JWT_SECRET: "your_very_strong_and_secret_jwt_key_here" # !!! Убедитесь, что это тот же секрет, что и в Gateway !!!
          CSRF_SECRET: "your_very_strong_and_secret_csrf_key_here" # !!! Убедитесь, что это тот же секрет !!!
          LOG_LEVEL: "debug"
          APP_ENV: "development"
        depends_on:
          db:
            condition: service_healthy
          redis:
            condition: service_healthy

      public-gateway:
        build:
          context: ./public-gateway
          dockerfile: Dockerfile
        container_name: public_gateway
        ports:
          - "8080:8080"
        environment:
          GATEWAY_PORT: "8080"
          BACKEND_URL: "http://monolith-backend:8081"
          JWT_SECRET: "your_very_strong_and_secret_jwt_key_here" # !!! Должен совпадать с бэкендом !!!
          CSRF_SECRET: "your_very_strong_and_secret_csrf_key_here" # !!! Должен совпадать с бэкендом !!!
          SESSION_TYPE: "jwt"
          LOG_LEVEL: "debug"
          APP_ENV: "development"
        depends_on:
          monolith-backend:
            condition: service_started # or service_healthy

      admin-gateway:
        build:
          context: ./admin-gateway
          dockerfile: Dockerfile
        container_name: admin_gateway
        ports:
          - "8082:8082"
        environment:
          GATEWAY_PORT: "8082"
          BACKEND_URL: "http://monolith-backend:8081"
          JWT_SECRET: "your_very_strong_and_secret_jwt_key_here" # !!! Должен совпадать с бэкендом !!!
          CSRF_SECRET: "your_very_strong_and_secret_csrf_key_here" # !!! Должен совпадать с бэкендом !!!
          SESSION_TYPE: "jwt"
          LOG_LEVEL: "debug"
          APP_ENV: "development"
        depends_on:
          monolith-backend:
            condition: service_started # or service_healthy

      prometheus:
        image: prom/prometheus:latest
        container_name: prometheus
        ports:
          - "9090:9090"
        volumes:
          - ./prometheus.yml:/etc/prometheus/prometheus.yml
        command:
          - '--config.file=/etc/prometheus/prometheus.yml'
        depends_on:
          - public-gateway
          - admin-gateway
          - monolith-backend

      grafana:
        image: grafana/grafana:latest
        container_name: grafana
        ports:
          - "3000:3000"
        volumes:
          - grafana_data:/var/lib/grafana
        environment:
          - GF_SECURITY_ADMIN_USER=admin
          - GF_SECURITY_ADMIN_PASSWORD=admin
        depends_on:
          - prometheus

    volumes:
      postgres_data:
      grafana_data:
    ```

3.  **Создайте `Dockerfile`** в каждой из папок `public-gateway`, `admin-gateway` и `monolith-backend`. Они будут идентичны:

    ```dockerfile
    # Dockerfile (для public-gateway, admin-gateway, monolith-backend)
    FROM golang:1.22-alpine

    WORKDIR /app

    COPY go.mod ./
    COPY go.sum ./
    RUN go mod download

    COPY . .

    RUN go build -o /app/main ./cmd/main.go

    EXPOSE 8080 # (для public-gateway)
    EXPOSE 8082 # (для admin-gateway)
    EXPOSE 8081 # (для monolith-backend)

    CMD ["/app/main"]
    ```
    **Важно:** Убедитесь, что `EXPOSE` соответствует порту, указанному в `docker-compose.yml` и `config.go` для каждого сервиса.

4.  **Создайте `prometheus.yml`** в **корневой директории проекта** (рядом с `docker-compose.yml`):

    ```yaml
    # prometheus.yml
    global:
      scrape_interval: 15s

    scrape_configs:
      - job_name: 'public-gateway'
        static_configs:
          - targets: ['public-gateway:8080'] # Используем имена сервисов из docker-compose
      - job_name: 'admin-gateway'
        static_configs:
          - targets: ['admin-gateway:8082']
      - job_name: 'monolith-backend'
        static_configs:
          - targets: ['monolith-backend:8081']
    ```

5.  **Запуск всех сервисов:**
    Откройте терминал в корневой директории проекта и выполните:
    ```bash
    docker-compose up --build -d
    ```
    Ключ `--build` необходим для первоначальной сборки Go-приложений внутри Docker. `-d` запускает их в фоновом режиме.

6.  **Выполнение миграций БД:**
    После запуска контейнеров, вам нужно будет выполнить миграции базы данных. Если у вас есть скрипты миграций, вы можете запустить их командой:
    ```bash
    docker exec -it postgres_db psql -U user -d taskflow_db -f /path/to/your/migrations.sql
    ```
    Или, если у вас есть отдельный Go-скрипт для миграций:
    ```bash
    # Возможно, вам придется запустить его отдельно на хосте,
    # указав DATABASE_URL=postgresql://user:password@localhost:5432/taskflow_db?sslmode=disable
    # Или добавить отдельный сервис миграций в docker-compose.yml
    ```
    **Пример базовой миграции для PostgreSQL:**
    ```sql
    -- monolith-backend/migrations/001_initial_schema.sql
    CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role VARCHAR(50) DEFAULT 'user' NOT NULL, -- 'user', 'moderator', 'admin'
        is_active BOOLEAN DEFAULT TRUE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_relationships (
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        friend_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        status VARCHAR(50) NOT NULL, -- 'pending', 'accepted', 'rejected'
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        PRIMARY KEY (user_id, friend_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        receiver_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        sent_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS tasks (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title VARCHAR(255) NOT NULL,
        description TEXT,
        creator_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        assignee_id UUID REFERENCES users(id) ON DELETE SET NULL,
        status VARCHAR(50) DEFAULT 'open' NOT NULL, -- 'open', 'in_progress', 'completed', 'cancelled', 'pending_moderation', 'approved', 'rejected'
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS proposals (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title VARCHAR(255) NOT NULL,
        description TEXT,
        creator_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        status VARCHAR(50) DEFAULT 'open' NOT NULL, -- 'open', 'accepted', 'rejected', 'pending_moderation', 'approved', 'rejected'
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    -- Добавление начального администратора (опционально, только для разработки)
    INSERT INTO users (username, email, password_hash, role, is_active) VALUES
    ('admin', 'admin@example.com', '$2a$10$22n9j8S2.vGq1lA8fK9b7u.R0s8yX9.k5j.8k7j8o9p0q.r.s.t.u.v.w.x.y.z', 'admin', TRUE)
    ON CONFLICT (username) DO NOTHING;
    -- Замените '$2a$10$...' на хеш пароля 'password' (или любого другого)
    -- Используйте go run monolith-backend/cmd/main.go и в отладке получите хеш, или bcrypt.GenerateFromPassword
    ```
    **Как получить хеш пароля для админа:**
    В монолите, в `internal/app/shared/auth/password.go`, можно добавить временную функцию для генерации хеша:
    ```go
    // monolith-backend/internal/app/shared/auth/password.go
    package auth

    // ...
    import "fmt"

    func GeneratePasswordHashForMigration(password string) {
        hash, _ := HashPassword(password)
        fmt.Println("Hash for password '", password, "': ", hash)
    }
    ```
    И вызвать её в `main.go` перед запуском сервера, потом удалить:
    ```go
    // monolith-backend/cmd/main.go
    // ...
    func main() {
        // auth.GeneratePasswordHashForMigration("your_admin_password_here") // Временно, чтобы получить хеш
        // ...
    }
    ```
    Запустите монолит, скопируйте хеш и вставьте его в миграцию.

## Как использовать

1.  **Зарегистрируйте пользователя:**
    `POST http://localhost:8080/api/v1/register`
    ```json
    {
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123"
    }
    ```
2.  **Войдите в систему:**
    `POST http://localhost:8080/api/v1/login` (для обычных пользователей)
    `POST http://localhost:8082/api/v1/login` (для админов/модераторов)
    ```json
    {
        "email": "test@example.com",
        "password": "password123"
    }
    ```
    После успешного входа вы получите JWT-токены в HTTP-куках. Эти куки будут автоматически отправляться с последующими запросами.

3.  **Получите свой профиль (обычный пользователь):**
    `GET http://localhost:8080/api/v1/users/me`

4.  **Получите всех пользователей (администратор):**
    `GET http://localhost:8082/api/v1/admin/users`

5.  **Заблокируйте пользователя (администратор):**
    `POST http://localhost:8082/api/v1/admin/users/{user_id}/block`

6.  **Мониторинг:**
    * **Prometheus:** Откройте `http://localhost:9090` в браузере для просмотра метрик.
    * **Grafana:** Откройте `http://localhost:3000` (логин/пароль `admin/admin`) для создания дашбордов и визуализации метрик.

## Дальнейшее развитие

* **Расширение модулей:** Добавление более сложной логики в задачи и предложения (комментарии, вложения, дедлайны).
* **Уведомления:** Система уведомлений (внутриигровые, email, push).
* **Файловое хранилище:** Интеграция с облачным хранилищем для загрузки файлов.
* **Поиск:** Полнотекстовый поиск по задачам и предложениям.
* **WebSocket:** Реализация обмена сообщениями в реальном времени.
* **UI/UX:** Разработка пользовательского интерфейса.

