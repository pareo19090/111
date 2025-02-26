package controller

import (
	"database/sql"
	"log"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

var db *sql.DB
var jwtSecret = []byte("your-secret-key")

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// 登出用黑名单
var blacklistedTokens sync.Map

// 初始化数据库连接
func InitDB(database *sql.DB) {
	db = database
}

// 生成 JWT Token
func GenerateToken(username string) (string, error) {
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// JWT 中间件
func JWTMiddleware(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).SendString("Missing Authorization header")
	}

	tokenString := authHeader[len("Bearer "):]

	if _, ok := blacklistedTokens.Load(tokenString); ok {
		return c.Status(fiber.StatusUnauthorized).SendString("Token has expired")
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid or expired token")
	}

	if claims, ok := token.Claims.(*Claims); ok {
		c.Locals("username", claims.Username)
		return c.Next()
	}

	return c.Status(fiber.StatusUnauthorized).SendString("Invalid token claims")
}

// 注册用户
func Register(c *fiber.Ctx) error {
	var u User
	if err := c.BodyParser(&u); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON"})
	}

	if u.Username == "" || u.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Username and password cannot be empty"})
	}

	_, err := db.Exec("INSERT INTO user (username, password) VALUES (?, ?)", u.Username, u.Password)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error registering user"})
	}

	log.Printf("User registered: %+v", u)
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "User registered successfully"})
}

// 用户登录
func Login(c *fiber.Ctx) error {
	var u User
	if err := c.BodyParser(&u); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON"})
	}

	var storedPassword string
	err := db.QueryRow("SELECT password FROM user WHERE username = ?", u.Username).Scan(&storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if storedPassword != u.Password {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"})
	}

	token, err := GenerateToken(u.Username)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate token"})
	}

	log.Printf("User logged in: %s", u.Username)
	return c.JSON(fiber.Map{"username": u.Username, "token": token})
}

// 用户登出
func Logout(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Missing Authorization header")
	}

	tokenString := authHeader[len("Bearer "):]

	// 将 token 添加到黑名单
	blacklistedTokens.Store(tokenString, true)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "You have been logged out"})
}

// 添加用户
func Add(c *fiber.Ctx) error {
	var u User
	if err := c.BodyParser(&u); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON"})
	}

	_, err := db.Exec("INSERT INTO user (username, password) VALUES (?, ?)", u.Username, u.Password)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error adding user"})
	}

	log.Printf("User added: %+v", u)
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "User added successfully"})
}

// 删除用户
func Delete(c *fiber.Ctx) error {
	username := c.FormValue("username")

	_, err := db.Exec("DELETE FROM user WHERE username = ?", username)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error deleting user"})
	}

	log.Printf("User deleted: %s", username)
	return c.JSON(fiber.Map{"message": "User deleted successfully"})
}

// 修改用户密码
func Modify(c *fiber.Ctx) error {
	username := c.FormValue("username")
	newPassword := c.FormValue("newpassword")

	_, err := db.Exec("UPDATE user SET password = ? WHERE username = ?", newPassword, username)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error modifying user"})
	}

	log.Printf("User modified: %s", username)
	return c.JSON(fiber.Map{"message": "User modified successfully"})
}

// 搜索用户
func Search(c *fiber.Ctx) error {
	rows, err := db.Query("SELECT username, password FROM user")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error querying the database"})
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Username, &u.Password); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error scanning rows"})
		}
		users = append(users, u)
	}

	return c.JSON(users)
}
