package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	//"strings"
	"github.com/golang-jwt/jwt/v5" // token generation
	"github.com/google/uuid"       // UUID generation
	"golang.org/x/crypto/bcrypt"   // password hashing
)

type User struct {
	Id       string `json:"id"`
	Username string `json:"username"`
	Usermail string `json:"usermail"`
	Password string `json:"password"`
}

type CustomClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var dataFile string = "data.json"
var jwtSecretKey = []byte("YOUR_EXTREMELY_STRONG_SECRET_KEY") // Секретный ключ для подписи JWT

func LoadUser() ([]User, error) {
	data, err := ioutil.ReadFile(dataFile)
	if err != nil {
		fmt.Printf("Ошибка чтения файла %s: %v\n", dataFile, err)
		if os.IsNotExist(err) {
			return []User{}, nil // Файл не найден, возвращаем пустой список
		}
		return nil, fmt.Errorf("ошибка чтения файла: %w", err)
	}
	var users []User
	// Проверка на пустой файл перед парсингом
	if len(data) == 0 || string(data) == "null" {
		return []User{}, nil
	}

	err = json.Unmarshal(data, &users)
	if err != nil {
		fmt.Printf("Ошибка парсинга JSON: %v. Данные: %s\n", err, string(data))
		return nil, fmt.Errorf("ошибка парсинга JSON: %w", err)
	}

	return users, nil
}

// GenerateJWT создает подписанный токен
func GenerateJWT(userID, username string) (string, error) {
	// Устанавливаем срок действия (например, 24 часа)
	expirationTime := time.Now().Add(24 * time.Hour)

	// 1. Создание полезной нагрузки (Claims)
	claims := &CustomClaims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime), // 'exp' - время истечения
			IssuedAt:  jwt.NewNumericDate(time.Now()),     // 'iat' - время создания
			Subject:   userID,                             // 'sub' - тема (часто UserID)
		},
	}

	// 2. Создание токена с алгоритмом подписи HS256
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 3. Подписание токена Секретным Ключом
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Хеширует пароль и возвращает строку хэша
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	// Возвращаем хэш в виде строки
	return string(bytes), nil
}
func LoaginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	usernameOrMail := r.FormValue("username")
	password := r.FormValue("password")
	if usernameOrMail == "" || password == "" {
		http.Error(w, "Missing fields", http.StatusBadRequest)
		return
	}
	users, err := LoadUser()
	if err != nil {
		http.Error(w, "Error loading users", http.StatusInternalServerError)
		return
	}
	var authenticatedUser *User
	for i, user := range users {
		if user.Username == usernameOrMail || user.Usermail == usernameOrMail {
			if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err == nil {
				authenticatedUser = &users[i]
				break
			}
		}
	}

	if authenticatedUser == nil {
		// Если пользователь не найден ИЛИ пароль был неверен
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// 2. ГЕНЕРАЦИЯ НОВОГО ТОКЕНА (Правильно!)
	tokenString, err := GenerateJWT(authenticatedUser.Id, authenticatedUser.Username)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// 3. Установка Cookie с новым токеном
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token", // Используем более явное имя
		Value:    tokenString,
		HttpOnly: true,  // Защита от XSS
		Secure:   false, // !!! Использовать TRUE для продакшена (HTTPS)
		Expires:  time.Now().Add(24 * time.Hour),
		Path:     "/",
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Login successful. New token set."))
}

func SingInHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	username := r.FormValue("username")
	usermail := r.FormValue("usermail")
	password := r.FormValue("password")
	if username == "" || usermail == "" || password == "" {
		http.Error(w, "Missing fields", http.StatusBadRequest)
		return
	}

	users, err := LoadUser()
	if err != nil {
		http.Error(w, "Error loading users", http.StatusInternalServerError)
		return
	}
	for _, user := range users {
		if user.Username == username || user.Usermail == usermail {
			http.Error(w, "Username or email already exists", http.StatusConflict)
			return
		}
	}
	//если не найден пользователь:

	id := uuid.New().String()
	hashedPassword, err := HashPassword(password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Id:       id,
		Username: username,
		Usermail: usermail,
		Password: hashedPassword,
	}
	users = append(users, newUser)
	updatedData, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		http.Error(w, "Error encoding data", http.StatusInternalServerError)
		return
	}
	err = ioutil.WriteFile(dataFile, updatedData, 0644)
	if err != nil {
		http.Error(w, "Error writing data file", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User registered successfully"))
}
func main() {
	http.HandleFunc("/singin", SingInHandler)
	http.HandleFunc("/login", LoaginHandler)
	fmt.Println("Server starting on :8080")
	http.ListenAndServe(":8080", nil)
}
