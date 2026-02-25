package middleware

import (
	"github.com/gofiber/fiber/v3"
)

type AdminConfig struct {
	AdminUserID int64
}

func NewAdminMiddleware(config *AdminConfig) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		user := GetUser(ctx)
		if user == nil {
			return fiber.NewError(403, "User not found")
		}

		if user.TelegramId != config.AdminUserID {
			return fiber.NewError(403, "Access denied")
		}

		return ctx.Next()
	}
}
