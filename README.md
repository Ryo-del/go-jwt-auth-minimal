# go-jwt-auth-minimal

Минимальный пример REST API на Go с регистрацией и авторизацией пользователей через JWT.

## Описание

- Регистрация пользователя (`/singin`)
- Авторизация пользователя (`/login`)
- Хранение пользователей в файле `data.json`
- Пароли хранятся в виде bcrypt-хэшей
- JWT-токен устанавливается в cookie

## Запуск

1. Установите зависимости:
	```
	go mod tidy
	```
2. Запустите сервер:
	```
	go run main.go
	```
3. Сервер будет доступен на `http://localhost:8080`

## Эндпоинты

### POST /singin

Регистрация нового пользователя.

**Параметры формы:**
- `username` — имя пользователя
- `usermail` — email пользователя
- `password` — пароль

**Ответ:**
- 201 Created — успешная регистрация
- 409 Conflict — пользователь уже существует

### POST /login

Авторизация пользователя.

**Параметры формы:**
- `username` — имя пользователя или email
- `password` — пароль

**Ответ:**
- 200 OK — успешная авторизация, JWT-токен в cookie
- 401 Unauthorized — неверные данные

## Зависимости

- [github.com/golang-jwt/jwt/v5](https://github.com/golang-jwt/jwt)
- [github.com/google/uuid](https://github.com/google/uuid)
- [golang.org/x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt)

## Примечания

- Для продакшена используйте HTTPS и задайте сильный секретный ключ.
- Все данные пользователей хранятся в `data.json`.