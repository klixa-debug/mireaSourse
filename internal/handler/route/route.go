package route

import (
	"mirea-qr/internal/handler"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
)

type RouteConfig struct {
	App                *fiber.App
	UserController     *handler.UserController
	MireaController    *handler.MireaController
	AdminController    *handler.AdminController
	ReviewController   *handler.ReviewController
	DebugMiddleware    fiber.Handler
	TelegramMiddleware fiber.Handler
	RegisterMiddleware fiber.Handler
	AdminMiddleware    fiber.Handler
}

func corsMiddleware() fiber.Handler {
	return cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"*"},
		AllowHeaders: []string{"*"},
	})
}

func (c *RouteConfig) Setup() {
	c.App.Use(corsMiddleware())
	c.App.Use(c.TelegramMiddleware)
	//c.App.Use(c.DebugMiddleware)

	c.SetupGuestRoute()
	c.SetupAuthRoute()
	c.SetupAdminRoute()
}

func (c *RouteConfig) SetupGuestRoute() {
	c.App.Use(corsMiddleware())

	c.App.Post("/v1/sign-up", c.UserController.Register)
}

func (c *RouteConfig) SetupAuthRoute() {
	c.App.Use(c.RegisterMiddleware)
	c.App.Use(corsMiddleware())

	c.App.Post("/v1/me", c.UserController.Me)
	c.App.Post("/v1/change-password", c.UserController.ChangePassword)
	c.App.Post("/v1/update-proxy", c.UserController.UpdateProxy)
	c.App.Post("/v1/totp-secret", c.UserController.GetTotpSecret)
	c.App.Post("/v1/update-totp-secret", c.UserController.UpdateTotpSecret)
	c.App.Post("/v1/delete-user", c.UserController.DeleteUser)
	c.App.Post("/v1/university-status", c.UserController.GetUniversityStatus)

	c.App.Post("/v1/disciplines", c.MireaController.Disciplines)
	c.App.Post("/v1/find-student", c.MireaController.FindStudent)

	c.App.Post("/v1/connect-student", c.UserController.ConnectStudent)
	c.App.Post("/v1/list-connected-student", c.UserController.ListConnectedStudent)
	c.App.Post("/v1/list-connected-to-user", c.UserController.ListConnectedToUser)
	c.App.Post("/v1/enabled-connected-student", c.UserController.EnabledConnectedStudent)
	c.App.Post("/v1/disconnect-student", c.UserController.DisconnectStudent)
	c.App.Post("/v1/disconnect-from-user", c.UserController.DisconnectFromUser)

	c.App.Post("/v1/scan-qr", c.MireaController.ScanQR)

	c.App.Post("/v1/status-of-bypass", c.MireaController.CheckStatusBypass)

	c.App.Post("/v1/lessons", c.MireaController.GetLessons)
	c.App.Post("/v1/attendance", c.MireaController.Attendance)
	c.App.Post("/v1/deadlines", c.MireaController.Deadlines)

	// Отзывы на преподавателей
	c.App.Post("/v1/reviews/teachers", c.ReviewController.ListTeachers)
	c.App.Post("/v1/reviews/search-teacher", c.ReviewController.SearchTeacher)
	c.App.Post("/v1/reviews/add-teacher", c.ReviewController.AddTeacher)
	c.App.Post("/v1/reviews/list", c.ReviewController.GetReviews)
	c.App.Post("/v1/reviews/create", c.ReviewController.CreateReview)
	c.App.Post("/v1/reviews/delete", c.ReviewController.DeleteReview)
}

func (c *RouteConfig) SetupAdminRoute() {
	c.App.Use(c.RegisterMiddleware)
	c.App.Use(c.AdminMiddleware)
	c.App.Use(corsMiddleware())

	c.App.Post("/v1/admin/stats", c.AdminController.GetStats)
}
