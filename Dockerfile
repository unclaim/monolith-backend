# Используем официальный образ Go
FROM golang:1.24-alpine as builder

# Создаем рабочую директорию
WORKDIR /app

# Копируем go-модуль и зависимости
COPY go.mod .
# COPY go.sum .

# Скачиваем зависимости
RUN go mod download

# Копируем исходники приложения
COPY cmd/server/*.go .

# Собираем бинарник
RUN CGO_ENABLED=0 GOOS=linux go build -o app

# Финальный этап сборки с минимальным образом
FROM alpine:latest

# Убедимся, что есть возможность скачивать библиотеки, если потребуется
RUN apk add --no-cache ca-certificates

# Скопируем собранный бинарник из этапа сборки
COPY --from=builder /app/app /app/

# Установим точку входа
ENTRYPOINT ["/app/app"]

# Экспортируем порт, если ваше приложение работает как сервис
EXPOSE 8080