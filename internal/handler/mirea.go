package handler

import (
	"mirea-qr/internal/entity"
	"mirea-qr/internal/handler/middleware"
	"mirea-qr/internal/model"
	"mirea-qr/internal/model/converter"
	"mirea-qr/internal/usecase"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
)

type MireaController struct {
	Log          *logrus.Logger
	UseCase      *usecase.MireaUseCase
	AdminUseCase *usecase.AdminUseCase
}

func NewMireaController(useCase *usecase.MireaUseCase, adminUseCase *usecase.AdminUseCase, logger *logrus.Logger) *MireaController {
	return &MireaController{
		Log:          logger,
		UseCase:      useCase,
		AdminUseCase: adminUseCase,
	}
}

func (c *MireaController) Disciplines(ctx fiber.Ctx) error {
	user := middleware.GetUser(ctx)

	response, err := c.UseCase.GetDisciplines(*user)
	if err != nil {
		return err
	}

	return ctx.JSON(model.WebResponse[*model.DisciplinesResponse]{Data: response})
}

func (c *MireaController) FindStudent(ctx fiber.Ctx) error {
	request := new(model.FindStudentRequest)

	if err := ctx.Bind().JSON(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	var user entity.User
	if err := c.UseCase.UserRepository.FindByEmail(c.UseCase.DB, &user, request.Email); err != nil {
		return fiber.NewError(400, "user not found")
	}

	return ctx.JSON(model.WebResponse[model.AnotherStudentResponse]{Data: converter.AnotherStudentToResponse(&user)})
}

func (c *MireaController) ScanQR(ctx fiber.Ctx) error {
	request := new(model.ScanQRRequest)
	user := middleware.GetUser(ctx)

	request.FromUserId = user.ID

	if err := ctx.Bind().JSON(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	response, err := c.UseCase.ScanQR(ctx.Context(), request, user)
	if err != nil {
		c.Log.Warnf("Failed scan QR : %+v", err)
		return err
	}

	// Записываем статистику QR скана
	if c.AdminUseCase != nil {
		total := int64(0)
		scanned := int64(0)
		for _, status := range response.Students {
			total++
			if status == usecase.STATUS_SUCCESS {
				scanned++
			}
		}

		if err := c.AdminUseCase.RecordQrScan(ctx.Context(), user.ID, response.Subject, total, scanned); err != nil {
			c.Log.Warnf("Failed to record QR scan: %+v", err)
			// Не возвращаем ошибку, так как основная операция прошла успешно
		}
	}

	return ctx.JSON(model.WebResponse[*model.ScanQRResponse]{Data: response})
}

func (c *MireaController) CheckStatusBypass(ctx fiber.Ctx) error {
	value := c.UseCase.Redis.Get(ctx.Context(), "check_student_univ")
	status, _ := value.Bool()
	checkTime, err := value.Time()
	if err != nil {
		checkTime = time.Now()
	}
	difHour := time.Now().Sub(checkTime).Hours()

	return ctx.JSON(model.WebResponse[model.StatusBypassResponse]{Data: model.StatusBypassResponse{
		Status: status,
		Time:   int(difHour) + 1,
	}})
}

func (c *MireaController) GetLessons(ctx fiber.Ctx) error {
	request := new(model.GetLessons)
	user := middleware.GetUser(ctx)

	if err := ctx.Bind().JSON(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	lessons, err := c.UseCase.GetLessons(*user, *request)
	if err != nil {
		c.Log.Warnf("Failed get lessons : %+v", err)
		return err
	}

	return ctx.JSON(model.WebResponse[[]model.LessonResponse]{Data: lessons})
}

func (c *MireaController) Attendance(ctx fiber.Ctx) error {
	request := new(model.AttendanceRequest)
	user := middleware.GetUser(ctx)

	if err := ctx.Bind().JSON(request); err != nil {
		c.Log.Warnf("Failed to parse request body : %+v", err)
		return fiber.ErrBadRequest
	}

	attendance, err := c.UseCase.Attendance(*user, *request)
	if err != nil {
		c.Log.Warnf("Failed get attendance : %+v", err)
		return err
	}

	return ctx.JSON(model.WebResponse[[]model.AttendanceStudentResponse]{Data: attendance})
}

func (c *MireaController) Deadlines(ctx fiber.Ctx) error {
	user := middleware.GetUser(ctx)

	deadlines, err := c.UseCase.GetDeadlines(*user)
	if err != nil {
		c.Log.Warnf("Failed get deadlines : %+v", err)
		return err
	}

	return ctx.JSON(model.WebResponse[[]model.DeadlineResponse]{Data: deadlines})
}
