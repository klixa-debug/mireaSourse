package handler

import (
	"context"
	"time"
	"mirea-qr/internal/model"
	"mirea-qr/internal/usecase"

	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
)

type AdminController struct {
	Log     *logrus.Logger
	UseCase *usecase.AdminUseCase
}

func NewAdminController(useCase *usecase.AdminUseCase, logger *logrus.Logger) *AdminController {
	return &AdminController{
		Log:     logger,
		UseCase: useCase,
	}
}



func (c *AdminController) GetStats(ctx fiber.Ctx) error {
    // Получаем существующую статистику
    response, err := c.UseCase.GetStats(ctx.Context())
    if err != nil {
        c.Log.Warnf("Failed to get admin stats : %+v", err)
        return err
    }

    // Получаем статистику бота из Redis
    ctxBg := context.Background()
    today := time.Now().Format("2006-01-02")
    botUsers, _ := c.UseCase.Redis.SCard(ctxBg, "bot:daily_users:"+today).Result()

    // Создаем расширенный ответ
    extendedResponse := struct {
        *model.AdminStatsResponse
        BotUniqueUsers int64 `json:"bot_unique_users"`
    }{
        AdminStatsResponse: response,
        BotUniqueUsers:     botUsers,
    }

    return ctx.JSON(model.WebResponse[interface{}]{Data: extendedResponse})
}
