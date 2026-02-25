package middleware

import (
	"mirea-qr/internal/entity"
	"mirea-qr/internal/usecase"

	"github.com/gofiber/fiber/v3"
)

func NewRegister(userUserCase *usecase.UserUseCase) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		telegramId := GetTelegramId(ctx)

		var user entity.User
		if err := userUserCase.UserRepository.FindByTelegramID(userUserCase.DB, &user, telegramId); err != nil {
			return fiber.NewError(403, "need registration")
		}

		userUserCase.Log.Debugf("User : %+v", user)

		ctx.Locals("user", &user)
		return ctx.Next()
	}
}

func GetUser(ctx fiber.Ctx) *entity.User {
	userInterface := ctx.Locals("user")
	if userInterface == nil {
		return nil
	}
	return userInterface.(*entity.User)
}
