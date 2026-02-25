package handler

import (
	"errors"
	"mirea-qr/internal/entity"
	"mirea-qr/internal/handler/middleware"
	"mirea-qr/internal/model"
	"mirea-qr/internal/model/converter"
	"mirea-qr/internal/usecase"

	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
)

type UserController struct {
	Log     *logrus.Logger
	UseCase *usecase.UserUseCase
}

func NewUserController(useCase *usecase.UserUseCase, logger *logrus.Logger) *UserController {
	return &UserController{
		Log:     logger,
		UseCase: useCase,
	}
}

func (c *UserController) Register(ctx fiber.Ctx) error {
	user := middleware.GetTelegramId(ctx)
	request := new(model.RegisterUserRequest)

	if err := ctx.Bind().JSON(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	request.TelegramId = user

	response, err := c.UseCase.Create(ctx.UserContext(), request)
	if err != nil {
		c.Log.Warnf("Failed to register user : %+v", err)
		return err
	}

	return ctx.JSON(model.WebResponse[*model.UserResponse]{Data: response})
}

func (c *UserController) Me(ctx fiber.Ctx) error {
	user := middleware.GetUser(ctx)

	if user == nil {
		return errors.New("user not found")
	}

	if user.Group == "" || string([]rune(user.Group)[:3]) == "ДПЗ" {
		err := c.UseCase.UpdateDataForUser(user)
		if err != nil {
			return err
		}
	}

	return ctx.JSON(model.WebResponse[*model.UserResponse]{Data: converter.UserToResponse(user)})
}

func (c *UserController) ConnectStudent(ctx fiber.Ctx) error {
	user := middleware.GetUser(ctx)
	request := new(model.ConnectStudentRequest)
	request.TelegramId = user.TelegramId

	if err := ctx.Bind().JSON(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	if err := c.UseCase.ConnectStudent(ctx.Context(), request); err != nil {
		return err
	}

	return ctx.JSON(model.WebResponse[string]{Data: "success"})
}

func (c *UserController) ListConnectedStudent(ctx fiber.Ctx) error {
	user := middleware.GetUser(ctx)

	var users []*entity.LinkUser
	if err := c.UseCase.LinkUserRepository.GetConnectedByUser(c.UseCase.DB, &users, user.ID); err != nil {
		return fiber.ErrInternalServerError
	}

	response := []model.ConnectedStudentResponse{}
	for _, user := range users {
		response = append(response, converter.LinkUserToResponse(user))
	}

	return ctx.JSON(model.WebResponse[[]model.ConnectedStudentResponse]{Data: response})
}

func (c *UserController) ListConnectedToUser(ctx fiber.Ctx) error {
	user := middleware.GetUser(ctx)

	var users []*entity.LinkUser
	if err := c.UseCase.LinkUserRepository.GetConnectedToUser(c.UseCase.DB, &users, user.ID); err != nil {
		return fiber.ErrInternalServerError
	}

	response := []model.ConnectedStudentResponse{}
	for _, linkUser := range users {
		response = append(response, converter.LinkUserToResponseReverse(linkUser))
	}

	return ctx.JSON(model.WebResponse[[]model.ConnectedStudentResponse]{Data: response})
}

func (c *UserController) EnabledConnectedStudent(ctx fiber.Ctx) error {
	user := middleware.GetUser(ctx)
	request := new(model.ConnectStudentRequest)
	request.TelegramId = user.TelegramId

	if err := ctx.Bind().JSON(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	if err := c.UseCase.ChangeEnabledConnectedStudent(ctx.Context(), request); err != nil {
		return err
	}

	return ctx.JSON(model.WebResponse[string]{Data: "success"})
}

func (c *UserController) ChangePassword(ctx fiber.Ctx) error {
	user := middleware.GetUser(ctx)
	request := new(model.ChangePasswordRequest)
	request.TelegramId = user.TelegramId

	if err := ctx.Bind().JSON(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	if err := c.UseCase.ChangePassword(ctx.Context(), request); err != nil {
		return err
	}

	return ctx.JSON(model.WebResponse[string]{Data: "success"})
}

func (c *UserController) GetUniversityStatus(ctx fiber.Ctx) error {
	user := middleware.GetUser(ctx)

	response, err := c.UseCase.GetUniversityStatus(ctx.Context(), user)
	if err != nil {
		c.Log.Warnf("Failed to get university status : %+v", err)
		return err
	}

	return ctx.JSON(model.WebResponse[*model.UniversityStatusResponse]{Data: response})
}

func (c *UserController) DeleteUser(ctx fiber.Ctx) error {
	user := middleware.GetUser(ctx)

	if err := c.UseCase.DeleteUser(ctx.Context(), user); err != nil {
		c.Log.Warnf("Failed to delete user : %+v", err)
		return err
	}

	return ctx.JSON(model.WebResponse[string]{Data: "success"})
}

func (c *UserController) DisconnectStudent(ctx fiber.Ctx) error {
	user := middleware.GetUser(ctx)
	request := new(model.ConnectStudentRequest)
	request.TelegramId = user.TelegramId

	if err := ctx.Bind().JSON(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	if err := c.UseCase.DisconnectStudent(ctx.Context(), request); err != nil {
		return err
	}

	return ctx.JSON(model.WebResponse[string]{Data: "success"})
}

func (c *UserController) DisconnectFromUser(ctx fiber.Ctx) error {
	user := middleware.GetUser(ctx)
	request := new(model.ConnectStudentRequest)
	request.TelegramId = user.TelegramId

	if err := ctx.Bind().JSON(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	if err := c.UseCase.DisconnectFromUser(ctx.Context(), request); err != nil {
		return err
	}

	return ctx.JSON(model.WebResponse[string]{Data: "success"})
}

func (c *UserController) UpdateProxy(ctx fiber.Ctx) error {
	user := middleware.GetUser(ctx)
	request := new(model.UpdateProxyRequest)
	request.TelegramId = user.TelegramId

	if err := ctx.Bind().JSON(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	if err := c.UseCase.UpdateProxy(ctx.Context(), request); err != nil {
		c.Log.Warnf("Failed to update proxy : %+v", err)
		return err
	}

	return ctx.JSON(model.WebResponse[string]{Data: "success"})
}

func (c *UserController) GetTotpSecret(ctx fiber.Ctx) error {
	user := middleware.GetUser(ctx)

	if user.TotpSecret == "" {
		return fiber.NewError(404, "TOTP secret not configured")
	}

	return ctx.JSON(model.WebResponse[string]{Data: user.TotpSecret})
}

func (c *UserController) UpdateTotpSecret(ctx fiber.Ctx) error {
	user := middleware.GetUser(ctx)
	request := new(model.UpdateTotpSecretRequest)
	request.TelegramId = user.TelegramId

	if err := ctx.Bind().JSON(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	if err := c.UseCase.UpdateTotpSecret(ctx.Context(), request); err != nil {
		c.Log.Warnf("Failed to update totp secret : %+v", err)
		return err
	}

	return ctx.JSON(model.WebResponse[string]{Data: "success"})
}
