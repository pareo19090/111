package main

import (
	"database/sql"
	"log"

	"github.com/gofiber/fiber/v2"
	"go.mod/controller"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	// 连接数据库
	db, err := sql.Open("mysql", "username:password?@tcp(localhost:3306)/db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// 确保数据库连接正常
	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}

	// 初始化数据库到控制器
	controller.InitDB(db)

	// 创建 Fiber 应用
	app := fiber.New()

	// 用户相关路由
	userapi := app.Group("/user")
	userapi.Post("/register", controller.Register)
	userapi.Post("/login", controller.Login)
	userapi.Post("/logout", controller.Logout)

	// 功能相关路由（需要 JWT 验证）
	functionapi := app.Group("/function")
	functionapi.Use(controller.JWTMiddleware)

	functionapi.Post("/add", controller.Add)
	functionapi.Post("/delete", controller.Delete)
	functionapi.Post("/modify", controller.Modify)
	functionapi.Post("/search", controller.Search)

	// 启动服务器
	log.Fatal(app.Listen(":3000"))
}
