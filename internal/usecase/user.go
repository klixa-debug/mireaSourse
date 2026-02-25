package usecase

import (
	"context"
	"errors"
	"fmt"
	entity "mirea-qr/internal/entity"
	"mirea-qr/internal/model"
	"mirea-qr/internal/model/converter"
	"mirea-qr/internal/repository"
	"mirea-qr/pkg/crypto"
	"mirea-qr/pkg/customerrors"
	"mirea-qr/pkg/mirea"
	"sort"
	"strconv"
	"strings"
	"time"

	browser "github.com/EDDYCJY/fake-useragent"
	"github.com/go-playground/validator/v10"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/gofiber/fiber/v3"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type UserUseCase struct {
	DB                 *gorm.DB
	Log                *logrus.Logger
	Validate           *validator.Validate
	UserRepository     *repository.UserRepository
	LinkUserRepository *repository.LinkUserRepository
	Redis              *redis.Client
	Bot                *tgbotapi.BotAPI
	Encryptor          *crypto.Encryptor
}

func NewUserUseCase(db *gorm.DB, logger *logrus.Logger, validate *validator.Validate, userRepository *repository.UserRepository, linkUserRepository *repository.LinkUserRepository, redis *redis.Client, bot *tgbotapi.BotAPI, encryptor *crypto.Encryptor) *UserUseCase {
	return &UserUseCase{
		DB:                 db,
		Log:                logger,
		Validate:           validate,
		UserRepository:     userRepository,
		LinkUserRepository: linkUserRepository,
		Redis:              redis,
		Bot:                bot,
		Encryptor:          encryptor,
	}
}

// createUserWithDecryptedPassword creates a user with decrypted password for API authorization
func (c *UserUseCase) createUserWithDecryptedPassword(user entity.User) (entity.User, error) {
	// Decrypt password
	decryptedPassword, err := c.Encryptor.Decrypt(user.Password)
	if err != nil {
		c.Log.Errorf("Failed to decrypt password for user %s: %+v", user.Email, err)
		return user, fiber.NewError(500, "Failed to decrypt password")
	}

	// Create user with decrypted password
	userWithDecryptedPassword := user
	userWithDecryptedPassword.Password = decryptedPassword

	return userWithDecryptedPassword, nil
}

func (c *UserUseCase) Create(ctx context.Context, request *model.RegisterUserRequest) (*model.UserResponse, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return nil, fiber.ErrBadRequest
	}

	// Проверяем, не зарегистрирован ли уже пользователь с таким Telegram ID
	user := new(entity.User)
	if err := c.UserRepository.FindByEmail(tx, user, request.Email); err == nil {
		c.Log.Warnf("User already exists with email %s : %+v", request.Email, err)
		//return nil, fiber.NewError(409, "В боте можно зарегистрироваться только с одного аккаунта Telegram")
	}

	attendance := mirea.NewAttendance(entity.User{
		Email:    request.Email,
		Password: request.Password,
	}, c.Redis)

	// ДОБАВЛЯЕМ ПЕРЕДАЧУ КОДА ИЗ ЗАПРОСА
	attendance.SetEmailOtpCode(request.OtpCode)

	if err := attendance.Authorization(); err != nil {
		c.Log.Warnf("Authorization error : %+v", err)

		// Проверяем тип ошибки авторизации
		if authErr, ok := err.(*customerrors.AuthError); ok {
			switch authErr.Type {
			case "invalid_credentials":
				return nil, fiber.NewError(403, "Неверный логин, пароль или код от MIREA")
			case "network_error":
				return nil, fiber.NewError(503, "Сайт MIREA не отвечает")
			case "site_unavailable":
				return nil, fiber.NewError(503, "Сайт MIREA недоступен")
			case "totp_secret_required":
				return nil, fiber.NewError(400, authErr.Message)
			case "email_otp_required": // <--- ЭТА ОШИБКА ДАЕТ ЗНАТЬ ФРОНТЕНДУ, ЧТО НУЖЕН КОД
				return nil, fiber.NewError(403, "email_otp_required")
			case "session_expired":
				return nil, fiber.NewError(400, authErr.Message)
			default:
				return nil, fiber.NewError(500, "Ошибка авторизации: "+authErr.Message)
			}
		}

		return nil, fiber.NewError(500, "Ошибка авторизации в системе MIREA")
	}

	student, err := attendance.GetMeInfo()
	if err != nil {
		c.Log.Errorf("Failed get me info : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	group, err := attendance.GetAvailableGroup()
	if err != nil {
		c.Log.Errorf("Failed get group : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	// Encrypt password before saving
	encryptedPassword, err := c.Encryptor.Encrypt(request.Password)
	if err != nil {
		c.Log.Errorf("Failed to encrypt password: %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	fullname := strings.Join([]string{student.GetFullname(), student.GetName(), student.GetMiddlename().GetValue()}, " ")
	if user.ID != "" {
		user.TelegramId = request.TelegramId
		user.Group = group.Title
		user.GroupID = group.UUID
		if err := c.UserRepository.Update(tx, user); err != nil {
			c.Log.Warnf("Failed update user to database : %+v", err)
			return nil, fiber.NewError(500, err.Error())
		}
	} else {
		user = &entity.User{
			ID:         student.Id,
			TelegramId: request.TelegramId,
			Email:      strings.ToLower(request.Email),
			Password:   encryptedPassword,
			Fullname:   fullname,
			Group:      group.Title,
			GroupID:    group.UUID,
			UserAgent:  browser.Mobile(),
		}

		if err := c.UserRepository.Create(tx, user); err != nil {
			c.Log.Warnf("Failed create user to database : %+v", err)
			return nil, fiber.NewError(500, err.Error())
		}
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	return converter.UserToResponse(user), nil
}

func (c *UserUseCase) UpdateDataForUser(user *entity.User) error {
	tx := c.DB.WithContext(context.Background()).Begin()
	defer tx.Rollback()

	userWithDecryptedPassword, err := c.createUserWithDecryptedPassword(*user)
	if err != nil {
		return errors.New("failed to decrypt password")
	}

	attendance := mirea.NewAttendance(userWithDecryptedPassword, c.Redis)
	if err := attendance.Authorization(); err != nil {
		c.Log.Warnf("Wrong login or password from mirea : %+v", err)
		return errors.New("wrong login or password")
	}

	student, err := attendance.GetMeInfo()
	if err != nil {
		return errors.New("failed get me info")
	}

	group, err := attendance.GetAvailableGroup()
	if err != nil {
		return errors.New("failed get group")
	}

	var middlename string
	if student.GetMiddlename() != nil {
		middlename = student.GetMiddlename().GetValue()
	}
	user.Fullname = strings.Join([]string{student.GetFullname(), student.GetName(), middlename}, " ")
	user.Group = group.Title
	user.GroupID = group.UUID

	if err := c.UserRepository.Update(tx, user); err != nil {
		return errors.New("failed update user")
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return errors.New("failed commit")
	}

	return nil
}

func (c *UserUseCase) ConnectStudent(ctx context.Context, request *model.ConnectStudentRequest) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return fiber.ErrBadRequest
	}

	var fromUser entity.User
	if err := c.UserRepository.FindByTelegramID(tx, &fromUser, request.TelegramId); err != nil {
		return fiber.ErrNotFound
	}

	var toUser entity.User
	if err := c.UserRepository.FindByEmail(tx, &toUser, request.Email); err != nil {
		return fiber.ErrNotFound
	}

	if fromUser.ID == toUser.ID {
		return fiber.NewError(400, "Вы не можете подключить самого себя")
	}

	var linkUserAlready entity.LinkUser
	if err := c.LinkUserRepository.FindLinkUser(tx, &linkUserAlready, fromUser.ID, toUser.ID); err == nil && linkUserAlready.FromUserID != "" {
		c.Log.Warnf("Link user already exists : %+v", linkUserAlready)
		return fiber.NewError(400, "Пользователь уже подключен")
	}

	linkUser := entity.LinkUser{
		FromUserID: fromUser.ID,
		ToUserID:   toUser.ID,
		Enabled:    true,
	}
	if err := c.LinkUserRepository.Create(tx, &linkUser); err != nil {
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	if c.Bot != nil {
		c.Bot.Send(tgbotapi.NewMessage(toUser.TelegramId, fmt.Sprintf("Вы были подключены к %s", fromUser.Fullname)))
	}

	return nil
}

func (c *UserUseCase) ChangeEnabledConnectedStudent(ctx context.Context, request *model.ConnectStudentRequest) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return fiber.ErrBadRequest
	}

	var fromUser entity.User
	if err := c.UserRepository.FindByTelegramID(tx, &fromUser, request.TelegramId); err != nil {
		return fiber.ErrNotFound
	}

	var toUser entity.User
	if err := c.UserRepository.FindByEmail(tx, &toUser, request.Email); err != nil {
		return fiber.ErrNotFound
	}

	var linkUser entity.LinkUser
	if err := c.LinkUserRepository.FindLinkUser(tx, &linkUser, fromUser.ID, toUser.ID); err != nil {
		return fiber.ErrNotFound
	}

	c.Log.Warnf("Link user : %+v", linkUser)
	linkUser.Enabled = !linkUser.Enabled

	if err := c.LinkUserRepository.UpdateLinkUser(tx, &linkUser); err != nil {
		c.Log.Warnf("Failed update link user : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}

func (c *UserUseCase) DisconnectStudent(ctx context.Context, request *model.ConnectStudentRequest) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return fiber.ErrBadRequest
	}

	var fromUser entity.User
	if err := c.UserRepository.FindByTelegramID(tx, &fromUser, request.TelegramId); err != nil {
		return fiber.ErrNotFound
	}

	var toUser entity.User
	if err := c.UserRepository.FindByEmail(tx, &toUser, request.Email); err != nil {
		return fiber.ErrNotFound
	}

	if err := c.LinkUserRepository.DeleteLinkUser(tx, fromUser.ID, toUser.ID); err != nil {
		c.Log.Warnf("Failed to delete link user : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}

func (c *UserUseCase) DisconnectFromUser(ctx context.Context, request *model.ConnectStudentRequest) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return fiber.ErrBadRequest
	}

	var toUser entity.User
	if err := c.UserRepository.FindByTelegramID(tx, &toUser, request.TelegramId); err != nil {
		return fiber.ErrNotFound
	}

	var fromUser entity.User
	if err := c.UserRepository.FindByEmail(tx, &fromUser, request.Email); err != nil {
		return fiber.ErrNotFound
	}

	if err := c.LinkUserRepository.DeleteLinkUser(tx, fromUser.ID, toUser.ID); err != nil {
		c.Log.Warnf("Failed to delete link user : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}

func (c *UserUseCase) ChangePassword(ctx context.Context, request *model.ChangePasswordRequest) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return fiber.ErrBadRequest
	}

	var user entity.User
	if err := c.UserRepository.FindByTelegramID(tx, &user, request.TelegramId); err != nil {
		return fiber.ErrNotFound
	}

	// Проверяем новый пароль
	user.Password = request.NewPassword

	newAttendance := mirea.NewAttendance(user, c.Redis)
	newAttendance.SetUseCase(false)
	if err := newAttendance.Authorization(); err != nil {
		c.Log.Warnf("Wrong new password : %+v", err)
		return fiber.NewError(403, "Неверный новый пароль")
	}

	// Encrypt new password before saving
	encryptedPassword, err := c.Encryptor.Encrypt(request.NewPassword)
	if err != nil {
		c.Log.Errorf("Failed to encrypt new password: %+v", err)
		return fiber.ErrInternalServerError
	}

	// Обновляем пароль в базе данных
	user.Password = encryptedPassword
	if err := c.UserRepository.Update(tx, &user); err != nil {
		c.Log.Warnf("Failed update user password : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}

func getCourseByGroup(code string) int {
	parts := strings.Split(code, "-")
	if len(parts) < 3 {
		return 0
	}

	// последние две цифры
	lastPart := parts[len(parts)-1]

	yearSuffix, err := strconv.Atoi(lastPart)
	if err != nil {
		return 0
	}

	// формула
	value := (25 - yearSuffix) + 1

	return value
}

func getMoscowDayBounds() (int64, int64) {
	moscowLoc, _ := time.LoadLocation("Europe/Moscow")
	now := time.Now().In(moscowLoc)

	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, moscowLoc)
	endOfDay := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 999999999, moscowLoc)

	return startOfDay.Unix(), endOfDay.Unix()
}

// getBuildingName преобразует код корпуса в читаемое название
func getBuildingName(locationTitle string) string {
	if locationTitle == "Неконтролируемая территория" {
		return "Улица"
	}

	// Берем только первое слово (код корпуса)
	parts := strings.Fields(locationTitle)
	if len(parts) == 0 {
		return locationTitle
	}

	code := parts[0]

	// Преобразуем известные коды корпусов
	switch code {
	case "С20":
		return "Стромынка"
	case "П1":
		return "Пироговка"
	case "В78":
		return "Вернадка"
	default:
		return code
	}
}

func (c *UserUseCase) GetUniversityStatus(ctx context.Context, user *entity.User) (*model.UniversityStatusResponse, error) {
	// Get user with decrypted password for authorization
	userWithDecryptedPassword, err := c.createUserWithDecryptedPassword(*user)
	if err != nil {
		c.Log.Errorf("Failed to decrypt password for user %s: %+v", user.Email, err)
		return nil, fiber.NewError(500, "Не удалось расшифровать пароль")
	}

	attendance := mirea.NewAttendance(userWithDecryptedPassword, c.Redis)

	if err := attendance.Authorization(); err != nil {
		c.Log.Warnf("Failed to authorize attendance : %+v", err)
		return nil, fiber.NewError(500, "Не удалось авторизоваться в системе посещаемости")
	}

	startTime, endTime := getMoscowDayBounds()

	events, err := attendance.GetHumanAcsEvents(startTime, endTime)
	if err != nil {
		c.Log.Errorf("Failed to get ACS events : %+v", err)
		if err != nil && err.Error() != "wrong base64" {
			return nil, fiber.NewError(500, "Не удалось получить данные о проходах")
		}
	}

	response := &model.UniversityStatusResponse{
		IsInUniversity: false,
		EntryTime:      0,
		ExitTime:       0,
		Events:         []model.UniversityEventDetail{},
	}

	if len(events) > 0 {
		sort.Slice(events, func(i, j int) bool {
			return events[i].GetTime().GetValue() < events[j].GetTime().GetValue()
		})

		response.EntryTime = events[0].GetTime().GetValue()

		// Создаем детальную информацию о событиях
		for i, event := range events {
			entryLocation := ""
			exitLocation := ""

			if event.GetEntryLocation() != nil {
				entryLocation = getBuildingName(event.GetEntryLocation().GetTitle())
			}
			if event.GetExitLocation() != nil {
				exitLocation = getBuildingName(event.GetExitLocation().GetTitle())
			}

			// Определяем, является ли событие входом или выходом
			// Если это первое событие или предыдущее событие было выходом, то это вход
			isEntry := i == 0
			if i > 0 {
				prevEvent := events[i-1]
				prevIsExit := false
				if prevEvent.GetExitLocation() != nil && prevEvent.GetExitLocation().GetTitle() != "Неконтролируемая территория" {
					prevIsExit = true
				}
				isEntry = prevIsExit
			}

			response.Events = append(response.Events, model.UniversityEventDetail{
				Time:          event.GetTime().GetValue(),
				EntryLocation: entryLocation,
				ExitLocation:  exitLocation,
				IsEntry:       isEntry,
			})
		}

		// Определяем, находится ли студент в университете
		// Возможные значение GetTitle()
		// С20 1эт ЦентральныйВход
		// С20 КПП2
		// П1 А 1эт ЦентральныйВход ДополнительныйВход
		// и т.д
		if events[len(events)-1].GetExitLocation().GetTitle() != "Неконтролируемая территория" {
			response.IsInUniversity = false
			response.ExitTime = events[len(events)-1].GetTime().GetValue()
		} else {
			response.IsInUniversity = true
		}
	}

	return response, nil
}

func (c *UserUseCase) DeleteUser(ctx context.Context, user *entity.User) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	if err := c.LinkUserRepository.DeleteByFromUser(tx, user.ID); err != nil {
		c.Log.Warnf("Failed to delete user connections as from_user : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := c.LinkUserRepository.DeleteByToUser(tx, user.ID); err != nil {
		c.Log.Warnf("Failed to delete user connections as to_user : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := c.UserRepository.Delete(tx, user); err != nil {
		c.Log.Warnf("Failed to delete user : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}

func (c *UserUseCase) UpdateProxy(ctx context.Context, request *model.UpdateProxyRequest) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return fiber.ErrBadRequest
	}

	var user entity.User
	if err := c.UserRepository.FindByTelegramID(tx, &user, request.TelegramId); err != nil {
		return fiber.ErrNotFound
	}

	user.CustomProxy = request.Proxy
	if err := c.UserRepository.Update(tx, &user); err != nil {
		c.Log.Warnf("Failed update user proxy : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}

func (c *UserUseCase) UpdateTotpSecret(ctx context.Context, request *model.UpdateTotpSecretRequest) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return fiber.ErrBadRequest
	}

	var user entity.User
	if err := c.UserRepository.FindByTelegramID(tx, &user, request.TelegramId); err != nil {
		return fiber.ErrNotFound
	}

	if user.Email == "" || user.Password == "" {
		c.Log.Warnf("User %d does not have email or password for authorization check", request.TelegramId)
		return fiber.NewError(400, "Для проверки TOTP secret требуется email и пароль пользователя")
	}

	userWithDecryptedPassword, err := c.createUserWithDecryptedPassword(user)
	if err != nil {
		c.Log.Warnf("Failed to decrypt password for user %d: %+v", request.TelegramId, err)
		return fiber.ErrInternalServerError
	}

	testUser := userWithDecryptedPassword
	testUser.TotpSecret = request.TotpSecret
	attendance := mirea.NewAttendance(testUser, c.Redis)
	attendance.SetUseCase(false)

	if err := attendance.Authorization(); err != nil {
		c.Log.Warnf("Authorization check failed with new TOTP secret for user %d: %+v", request.TelegramId, err)

		var authErr *customerrors.AuthError
		if errors.As(err, &authErr) {
			switch authErr.Type {
			case "invalid_credentials":
				return fiber.NewError(403, "Неверный TOTP secret. Проверьте правильность ввода")
			case "totp_secret_required":
				return fiber.NewError(400, authErr.Message)
			case "network_error":
				return fiber.NewError(503, "Сайт MIREA не отвечает. Попробуйте позже")
			case "site_unavailable":
				return fiber.NewError(503, "Сайт MIREA недоступен. Попробуйте позже")
			default:
				return fiber.NewError(500, "Ошибка проверки авторизации: "+authErr.Message)
			}
		}

		return fiber.NewError(500, "Ошибка проверки авторизации с новым secret")
	}

	user.TotpSecret = request.TotpSecret
	if err := c.UserRepository.Update(tx, &user); err != nil {
		c.Log.Warnf("Failed update user totp secret : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}
