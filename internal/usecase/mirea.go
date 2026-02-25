package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mirea-qr/internal/entity"
	"mirea-qr/internal/model"
	"mirea-qr/internal/repository"
	"mirea-qr/pkg/crypto"
	"mirea-qr/pkg/mirea"
	"strings"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/gofiber/fiber/v3"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type MireaUseCase struct {
	DB        *gorm.DB
	Log       *logrus.Logger
	Validate  *validator.Validate
	Redis     *redis.Client
	Bot       *tgbotapi.BotAPI
	Encryptor *crypto.Encryptor

	UserRepository              *repository.UserRepository
	LinkUserRepository          *repository.LinkUserRepository
	SubjectAttendanceRepository *repository.SubjectAttendanceRepository
}

type WorkerQR struct {
	users     []entity.User
	mutex     sync.Mutex
	wg        sync.WaitGroup
	redis     *redis.Client
	response  *model.ScanQRResponse
	uuid      string
	subject   string
	bot       *tgbotapi.BotAPI
	encryptor *crypto.Encryptor
}

const (
	STATUS_NOT_AUTHORIZED = iota
	STATUS_NOT_APPROVED
	STATUS_UNKNOWN
	STATUS_ERROR
	STATUS_SUCCESS
	STATUS_NOT_IN_UNIVERSITY
	STATUS_NOT_LESSON
)

func NewMireaUseCase(db *gorm.DB, logger *logrus.Logger, validate *validator.Validate, userRepository *repository.UserRepository, linkUserRepository *repository.LinkUserRepository, subjectAttendanceRepository *repository.SubjectAttendanceRepository, redis *redis.Client, bot *tgbotapi.BotAPI, encryptor *crypto.Encryptor) *MireaUseCase {
	return &MireaUseCase{
		DB:                          db,
		Log:                         logger,
		Validate:                    validate,
		UserRepository:              userRepository,
		LinkUserRepository:          linkUserRepository,
		SubjectAttendanceRepository: subjectAttendanceRepository,
		Redis:                       redis,
		Bot:                         bot,
		Encryptor:                   encryptor,
	}
}

// createUserWithDecryptedPassword creates a user with decrypted password for API authorization
func (c *MireaUseCase) createUserWithDecryptedPassword(user entity.User) (entity.User, error) {
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

func (c *MireaUseCase) GetDisciplines(user entity.User) (*model.DisciplinesResponse, error) {
	tx := c.DB.WithContext(context.Background()).Begin()
	defer tx.Rollback()
	data, err := c.Redis.Get(context.Background(), "disciplines_"+user.ID).Bytes()

	if err == nil {
		var response *model.DisciplinesResponse
		if err := json.Unmarshal(data, &response); err == nil {
			return response, nil
		}
	}

	userWithDecryptedPassword, err := c.createUserWithDecryptedPassword(user)
	if err != nil {
		return nil, err
	}

	attendance := mirea.NewAttendance(userWithDecryptedPassword, c.Redis)
	if err := attendance.Authorization(); err != nil {
		return nil, fiber.NewError(403, "failed authorization")
	}

	rating, err := attendance.GetLearnRatingScore()
	if err != nil {
		return nil, fiber.NewError(500, fmt.Sprintf("failed get disciplines : %+v", err))
	}

	valueDataRating := map[string]model.DisciplineScoreData{}
	for _, valueData := range rating.GetValueData() {
		for _, block := range valueData.GetBlock() {
			valueDataRating[block.GetUuid()] = model.DisciplineScoreData{
				Title: block.GetTitle(),
				Now:   0,
				Max:   float64(block.GetMax()),
			}
		}
	}

	var disciplinesResponse []model.DisciplineResponse
	for _, discipline := range rating.GetDiscipline() {
		title := discipline.GetTitle().GetValue()
		avg := c.SubjectAttendanceRepository.GetAvgForSubjectByGroup(tx, user.GroupID, title)

		disciplineScoreData := []model.DisciplineScoreData{}
		for _, scoreData := range discipline.GetScoreData() {
			disciplineScoreData = append(disciplineScoreData, model.DisciplineScoreData{
				Title: valueDataRating[scoreData.GetUuid()].Title,
				Now:   scoreData.GetNow(),
				Max:   valueDataRating[scoreData.GetUuid()].Max,
			})
		}

		disciplinesResponse = append(disciplinesResponse, model.DisciplineResponse{
			Title:     title,
			Total:     discipline.GetTotal(),
			AvgGroup:  avg,
			ScoreData: disciplineScoreData,
		})

		if c.SubjectAttendanceRepository.HasForUser(tx, user.ID, user.GroupID, title) == false {
			subjectAttendance := &entity.SubjectAttendance{
				StudentId: user.ID,
				GroupId:   user.GroupID,
				Subject:   title,
				Value:     discipline.GetTotal(),
			}

			if err := c.SubjectAttendanceRepository.Create(tx, subjectAttendance); err != nil {
				c.Log.Warnf("Failed insert subject attendance to database : %+v", err)
			}
		} else {
			// Обновляем баллы студента, если запись уже существует
			if err := c.SubjectAttendanceRepository.UpdateValueForUser(tx, user.ID, user.GroupID, title, discipline.GetTotal()); err != nil {
				c.Log.Warnf("Failed update subject attendance for user : %+v", err)
			}
		}
	}

	response := &model.DisciplinesResponse{
		CountStudents: c.SubjectAttendanceRepository.GetCountStudents(tx, user.GroupID),
		Disciplines:   disciplinesResponse,
	}

	tx.Commit()

	// Очищаем кеш для всех студентов группы, чтобы обновить средний балл группы
	// Получаем всех студентов группы и очищаем их кеш
	var groupUsers []entity.User
	if err := c.DB.Where("group_id = ?", user.GroupID).Find(&groupUsers).Error; err == nil {
		for _, groupUser := range groupUsers {
			c.Redis.Del(context.Background(), "disciplines_"+groupUser.ID)
		}
	}

	redisData, err := json.Marshal(response)
	if err == nil {
		c.Redis.Set(context.Background(), "disciplines_"+user.ID, redisData, time.Hour)
	}

	return response, nil
}

func (c *MireaUseCase) GetLessons(user entity.User, request model.GetLessons) ([]model.LessonResponse, error) {
	tx := c.DB.WithContext(context.Background()).Begin()
	defer tx.Rollback()

	today := time.Now()
	// Условие чтобы не кешировался текущий день, для обновления отметок на паре
	if int32(today.Year()) != request.Year || int32(today.Month()) != request.Month || int32(today.Day()) != request.Day {
		data, err := c.Redis.Get(context.Background(), fmt.Sprintf("lessons_%s_%d%d%d", user.GroupID, request.Year, request.Month, request.Day)).Bytes()

		if err == nil {
			var response []model.LessonResponse
			if err := json.Unmarshal(data, &response); err == nil {
				return response, nil
			}
		}
	}

	userWithDecryptedPassword, err := c.createUserWithDecryptedPassword(user)
	if err != nil {
		return nil, err
	}

	attendance := mirea.NewAttendance(userWithDecryptedPassword, c.Redis)
	if err := attendance.Authorization(); err != nil {
		return nil, fiber.NewError(403, "failed authorization")
	}

	lessons, err := attendance.GetLessons(request.Year, request.Month, request.Day)
	if err != nil {
		if err.Error() == "empty response" {
			// мб воскресенье, мб у школьников каникулы
			return []model.LessonResponse{}, nil
		}

		return nil, fiber.NewError(500, fmt.Sprintf("failed get lessons : %+v", err))
	}

	lessonsResponse := []model.LessonResponse{}
	for _, lesson := range lessons {
		data := lesson.GetLesson()
		teacherData := data.GetTeacher()
		var teacher string
		if teacherData != nil {
			var middleName string
			if teacherData.GetMiddleName() != nil {
				middleName = teacherData.GetMiddleName().GetValue()
			}
			teacher = teacherData.GetFamilyName() + " " + teacherData.GetName() + " " + middleName
		}

		//21.12.2025 убрали группы
		//var groups []string
		//if data.GetGroups() != nil {
		//	for _, group := range data.GetGroups() {
		//		groups = append(groups, group.GetTitle())
		//	}
		//}

		lessonsResponse = append(lessonsResponse, model.LessonResponse{
			Uuid:       data.GetUuid(),
			Auditorium: data.GetRoom().GetNumber(),
			Campus:     data.GetRoom().GetCampus(),
			Title:      data.GetSubject().GetValue(),
			Type:       data.GetType().GetValue(),
			Start:      int32(data.GetStart().GetValue()),
			End:        int32(data.GetEnd().GetValue()),
			Teacher:    teacher,
			Groups:     []string{},
			Attended:   0,
			Total:      0,
			Status:     lesson.GetAttended(),
		})
	}

	// small naser for update group id
	currentUser := attendance.GetCurrentUser()
	c.Log.Printf("Old group id : %s, current group id : %s", user.GroupID, currentUser.GroupID)
	if user.GroupID != currentUser.GroupID || user.Group != currentUser.Group {
		user.GroupID = currentUser.GroupID
		user.Group = currentUser.Group

		err := c.UserRepository.Update(tx, &user)
		if err != nil {
			c.Log.Warnf("Failed update group id : %+v", err)
		}
	}

	tx.Commit()

	redisData, err := json.Marshal(lessonsResponse)
	if err == nil {
		c.Redis.Set(context.Background(), fmt.Sprintf("lessons_%s_%d%d%d", user.GroupID, request.Year, request.Month, request.Day), redisData, time.Hour*24)
	}

	return lessonsResponse, nil
}

func (c *MireaUseCase) Attendance(user entity.User, request model.AttendanceRequest) ([]model.AttendanceStudentResponse, error) {
	tx := c.DB.WithContext(context.Background()).Begin()
	defer tx.Rollback()

	userWithDecryptedPassword, err := c.createUserWithDecryptedPassword(user)
	if err != nil {
		return nil, err
	}

	attendance := mirea.NewAttendance(userWithDecryptedPassword, c.Redis)
	if err := attendance.Authorization(); err != nil {
		return nil, fiber.NewError(403, "failed authorization")
	}

	r, err := attendance.GetAttendanceStudentForLesson(request.LessonUUID)
	if err != nil {
		return nil, fiber.NewError(500, fmt.Sprintf("failed get attendance for lesson %s : %+v", request.LessonUUID, err))
	}

	response := []model.AttendanceStudentResponse{}
	for _, student := range r {
		fullname := strings.Join([]string{student.GetLastName(), student.GetFirstName(), student.GetMiddleName().GetValue()}, " ")

		response = append(response, model.AttendanceStudentResponse{
			Fullname: fullname,
			Status:   student.GetGroup().GetNumber() * -1,
			IsElder:  student.GetHuesos() != -1,
		})
	}

	return response, nil
}

func (c *MireaUseCase) GetDeadlines(user entity.User) ([]model.DeadlineResponse, error) {
	data, err := c.Redis.Get(context.Background(), fmt.Sprintf("deadlines_group_%s", user.GroupID)).Bytes()

	if err == nil {
		var response []model.DeadlineResponse
		if err := json.Unmarshal(data, &response); err == nil {
			return response, nil
		}
	}

	userWithDecryptedPassword, err := c.createUserWithDecryptedPassword(user)
	if err != nil {
		return nil, err
	}

	online := mirea.NewOnlineEdu(userWithDecryptedPassword, c.Redis)
	if _, err := online.Authorization(); err != nil {
		return nil, fiber.NewError(403, "failed authorization")
	}

	deadlines, err := online.GetDeadlines()
	if err != nil {
		return nil, fiber.NewError(500, fmt.Sprintf("failed get deadlines : %+v", err))
	}

	out := make([]model.DeadlineResponse, 0, len(deadlines))
	for _, d := range deadlines {
		out = append(out, model.DeadlineResponse{
			Title:     d.Title,
			Timestamp: d.Timestamp,
			Subject:   d.Subject,
		})
	}

	redisData, err := json.Marshal(out)
	if err == nil {
		c.Redis.Set(context.Background(), fmt.Sprintf("deadlines_group_%s", user.GroupID), redisData, time.Hour*24)
	}

	return out, nil
}

func (c *MireaUseCase) ScanQR(ctx context.Context, request *model.ScanQRRequest, fromUser *entity.User) (*model.ScanQRResponse, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	worker := WorkerQR{
		users: []entity.User{},
		mutex: sync.Mutex{},
		wg:    sync.WaitGroup{},
		redis: c.Redis,
		response: &model.ScanQRResponse{
			Students: map[string]uint{},
		},
		bot:       c.Bot,
		encryptor: c.Encryptor,
	}

	parts := strings.Split(request.URL, "?token=")
	if len(parts) < 2 {
		return worker.response, fiber.NewError(400, "QR код не относится к МИРЭА")
	}
	worker.uuid = parts[1]

	var links []*entity.LinkUser
	if err := c.LinkUserRepository.GetConnectedByUser(tx, &links, request.FromUserId); err != nil {
		//return worker.response, fiber.NewError(500, "Не удалось получить студентов")
	}

	//if len(links) == 0 {
	//	return worker.response, fiber.NewError(400, "Нельзя отмечать только себя")
	//}

	for _, link := range links {
		if !link.Enabled {
			continue
		}
		worker.users = append(worker.users, link.ToUser)
	}

	worker.users = append(worker.users, *fromUser)
	worker.wg.Add(len(worker.users))
	worker.Start()
	worker.wg.Wait()

	return worker.response, nil
}

func (w *WorkerQR) Start() {
	for _, user := range w.users {
		go func(user entity.User) {
			defer w.wg.Done()

			telegramAlreadyNotificationErr := w.redis.Get(context.Background(), fmt.Sprintf("telegram_notification_%d", user.TelegramId)).Err()
			telegramSendNotification := errors.Is(telegramAlreadyNotificationErr, redis.Nil) // true - если ключа нет

			familyName := strings.Split(user.Fullname, " ")[0]

			// Проверяем, был ли пользователь отмечен в последние минуты
			attendanceStatusKey := fmt.Sprintf("attendance_status_%s", user.ID)
			cachedStatus := w.redis.Get(context.Background(), attendanceStatusKey)
			if cachedStatus.Err() == nil {
				// Если ключ существует, значит по пользователю был получен статус
				w.mutex.Lock()
				s, _ := cachedStatus.Int()
				w.response.Students[familyName] = uint(s)
				w.mutex.Unlock()
				return
			}

			// Decrypt password for authorization
			decryptedPassword, err := w.encryptor.Decrypt(user.Password)
			if err != nil {
				w.mutex.Lock()
				w.response.Students[familyName] = STATUS_ERROR
				w.mutex.Unlock()
				return
			}

			userWithDecryptedPassword := user
			userWithDecryptedPassword.Password = decryptedPassword

			attendance := mirea.NewAttendance(userWithDecryptedPassword, w.redis)
			if err := attendance.Authorization(); err != nil {
				// не удалось авторизоваться
				w.mutex.Lock()
				w.response.Students[familyName] = STATUS_NOT_AUTHORIZED
				w.mutex.Unlock()
				// Send notification about authorization failure
				// notificationMessage := "🔐 Не удалось отметить вас на паре. Проблемы с авторизацией в системе МИРЭА. Проверьте логин и пароль в настройках."
				// w.bot.Send(tgbotapi.NewMessage(user.TelegramId, notificationMessage))
				fmt.Printf("%s - failed authorization for scan: %v", familyName, err)
				return
			}
			msg, err := attendance.SelfApproveAttendance(w.uuid)
			w.mutex.Lock()
			if err != nil {
				// внутренняя ошибка
				w.response.Students[familyName] = STATUS_UNKNOWN
				// Сохраняем успешную отметку в кэш на 1 минуту
				//w.redis.Set(context.Background(), attendanceStatusKey, STATUS_UNKNOWN, time.Minute*1)
				//if telegramSendNotification {
				//	notificationMessage := "✅ Вас скорее всего отметили на паре, но возникла техническая ошибка при проверке статуса. Проверьте свою посещаемость в системе МИРЭА."
				//	w.bot.Send(tgbotapi.NewMessage(user.TelegramId, notificationMessage))
				//}
			} else {
				if msg != nil {
					if msg.GetSuccess() != nil {
						// блок success не нулевой значит жб удалось отметить
						w.response.Students[familyName] = STATUS_SUCCESS
						// Сохраняем успешную отметку в кэш на 15 минут
						w.redis.Set(context.Background(), attendanceStatusKey, STATUS_SUCCESS, time.Minute*15)
						w.response.Subject = msg.GetSuccess().GetSubject()
					} else {
						// блок success пустой, значит там ошибка
						if msg.GetFailed() != nil {
							errStatus := msg.GetFailed().GetError()
							switch errStatus {
							case 1:
								// QR просто устарел
								w.response.Students[familyName] = STATUS_NOT_APPROVED
								break
							case 3:
								// Сохраняем что пользователь не относится к паре в кэш на 1 минуту
								if telegramSendNotification {
									notificationMessage := "🏫 Вас пытались отметить на паре, к которой вы не закреплены"
									w.bot.Send(tgbotapi.NewMessage(user.TelegramId, notificationMessage))
								}
								w.redis.Set(context.Background(), attendanceStatusKey, STATUS_NOT_LESSON, time.Minute*1)
								w.response.Students[familyName] = STATUS_NOT_LESSON
								break
							case 5:
								w.redis.Set(context.Background(), "check_student_univ", true, time.Hour*48)
								w.response.Students[familyName] = STATUS_NOT_IN_UNIVERSITY
								// Send notification about university check
								if telegramSendNotification {
									notificationMessage := "🏫 Не удалось отметить вас на паре, вы не находитесь в университете."
									w.bot.Send(tgbotapi.NewMessage(user.TelegramId, notificationMessage))
								}
								// Сохраняем что студент не в вузе в кэш на 2 минуты
								w.redis.Set(context.Background(), attendanceStatusKey, STATUS_NOT_IN_UNIVERSITY, time.Minute*2)
								break
							default:
								w.response.Students[familyName] = STATUS_NOT_APPROVED
								break
							}

						} else {
							w.response.Students[familyName] = STATUS_NOT_APPROVED
						}
					}
				} else {
					// не удалось декодировать ответ
					w.response.Students[familyName] = STATUS_ERROR
				}
			}

			w.redis.Set(context.Background(), fmt.Sprintf("telegram_notification_%d", user.TelegramId), true, time.Minute*10)
			w.mutex.Unlock()
		}(user)
	}
}
