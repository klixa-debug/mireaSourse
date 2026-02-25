package app

import (
	"errors"
	"github.com/gofiber/fiber/v3"
)

func NewFiber(cfg Config) *fiber.App {
	return fiber.New(fiber.Config{
		ErrorHandler: errorHandler(),
		AppName:      cfg.Name,
	})
}

func errorHandler() fiber.ErrorHandler {
	return func(ctx fiber.Ctx, err error) error {
		code := fiber.StatusInternalServerError
		var e *fiber.Error
		if errors.As(err, &e) {
			code = e.Code
		}

		return ctx.Status(code).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
}
