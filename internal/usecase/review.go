package usecase

import (
	"context"
	"mirea-qr/internal/entity"
	"mirea-qr/internal/model"
	"mirea-qr/internal/model/converter"
	"mirea-qr/internal/repository"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type ReviewUseCase struct {
	DB                      *gorm.DB
	Log                     *logrus.Logger
	Validate                *validator.Validate
	UserRepository          *repository.UserRepository
	TeacherRepository       *repository.TeacherRepository
	TeacherReviewRepository *repository.TeacherReviewRepository
}

func NewReviewUseCase(
	db *gorm.DB,
	log *logrus.Logger,
	validate *validator.Validate,
	userRepo *repository.UserRepository,
	teacherRepo *repository.TeacherRepository,
	reviewRepo *repository.TeacherReviewRepository,
) *ReviewUseCase {
	return &ReviewUseCase{
		DB:                      db,
		Log:                     log,
		Validate:                validate,
		UserRepository:          userRepo,
		TeacherRepository:       teacherRepo,
		TeacherReviewRepository: reviewRepo,
	}
}

// ListAllTeachers возвращает всех преподавателей с количеством отзывов.
func (uc *ReviewUseCase) ListAllTeachers(ctx context.Context) ([]model.TeacherResponse, error) {
	var teachers []entity.Teacher
	if err := uc.TeacherRepository.FindAll(uc.DB.WithContext(ctx), &teachers); err != nil {
		uc.Log.Errorf("Failed to list all teachers : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	result := make([]model.TeacherResponse, 0, len(teachers))
	for i := range teachers {
		count, _ := uc.TeacherRepository.CountReviews(uc.DB.WithContext(ctx), teachers[i].ID)
		result = append(result, converter.TeacherToResponse(&teachers[i], count))
	}

	return result, nil
}

// SearchTeachers ищет преподавателей по подстроке имени.
func (uc *ReviewUseCase) SearchTeachers(ctx context.Context, request *model.SearchTeacherRequest) ([]model.TeacherResponse, error) {
	if err := uc.Validate.Struct(request); err != nil {
		uc.Log.Warnf("Invalid search request : %+v", err)
		return nil, fiber.ErrBadRequest
	}

	var teachers []entity.Teacher
	if err := uc.TeacherRepository.SearchByName(uc.DB.WithContext(ctx), &teachers, request.Query); err != nil {
		uc.Log.Errorf("Failed to search teachers : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	result := make([]model.TeacherResponse, 0, len(teachers))
	for i := range teachers {
		count, _ := uc.TeacherRepository.CountReviews(uc.DB.WithContext(ctx), teachers[i].ID)
		result = append(result, converter.TeacherToResponse(&teachers[i], count))
	}

	return result, nil
}

// AddTeacher создаёт нового преподавателя. Если преподаватель с таким именем уже есть — возвращает его.
func (uc *ReviewUseCase) AddTeacher(ctx context.Context, request *model.AddTeacherRequest) (*model.TeacherResponse, error) {
	if err := uc.Validate.Struct(request); err != nil {
		uc.Log.Warnf("Invalid add teacher request : %+v", err)
		return nil, fiber.ErrBadRequest
	}

	name := strings.TrimSpace(request.Name)

	// Проверяем, существует ли уже такой преподаватель
	var existing entity.Teacher
	if err := uc.TeacherRepository.FindByName(uc.DB.WithContext(ctx), &existing, name); err == nil {
		count, _ := uc.TeacherRepository.CountReviews(uc.DB.WithContext(ctx), existing.ID)
		resp := converter.TeacherToResponse(&existing, count)
		return &resp, nil
	}

	tx := uc.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	teacher := entity.Teacher{Name: name}
	if err := uc.TeacherRepository.Create(tx, &teacher); err != nil {
		uc.Log.Errorf("Failed to create teacher : %+v", err)
		return nil, fiber.NewError(500, "Не удалось добавить преподавателя")
	}

	if err := tx.Commit().Error; err != nil {
		uc.Log.Errorf("Failed to commit : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	resp := converter.TeacherToResponse(&teacher, 0)
	return &resp, nil
}

// GetReviews возвращает преподавателя и список отзывов по нему.
func (uc *ReviewUseCase) GetReviews(ctx context.Context, request *model.GetReviewsRequest, currentUserID string) (*model.TeacherReviewsResponse, error) {
	if err := uc.Validate.Struct(request); err != nil {
		uc.Log.Warnf("Invalid get reviews request : %+v", err)
		return nil, fiber.ErrBadRequest
	}

	var teacher entity.Teacher
	if err := uc.TeacherRepository.FindById(uc.DB.WithContext(ctx), &teacher, request.TeacherID); err != nil {
		return nil, fiber.NewError(404, "Преподаватель не найден")
	}

	var reviews []entity.TeacherReview
	if err := uc.TeacherReviewRepository.FindByTeacherID(uc.DB.WithContext(ctx), &reviews, request.TeacherID); err != nil {
		uc.Log.Errorf("Failed to get reviews : %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	reviewResponses := make([]model.ReviewResponse, 0, len(reviews))
	for i := range reviews {
		reviewResponses = append(reviewResponses, converter.ReviewToResponse(&reviews[i], currentUserID))
	}

	return &model.TeacherReviewsResponse{
		Teacher: converter.TeacherToResponse(&teacher, int64(len(reviews))),
		Reviews: reviewResponses,
	}, nil
}

// CreateReview оставляет анонимный отзыв. Один пользователь — один отзыв на преподавателя.
func (uc *ReviewUseCase) CreateReview(ctx context.Context, request *model.CreateReviewRequest) error {
	if err := uc.Validate.Struct(request); err != nil {
		uc.Log.Warnf("Invalid create review request : %+v", err)
		return fiber.ErrBadRequest
	}

	// Проверяем, существует ли преподаватель
	var teacher entity.Teacher
	if err := uc.TeacherRepository.FindById(uc.DB.WithContext(ctx), &teacher, request.TeacherID); err != nil {
		return fiber.NewError(404, "Преподаватель не найден")
	}

	// Проверяем, нет ли уже отзыва от этого пользователя
	var existing entity.TeacherReview
	if err := uc.TeacherReviewRepository.FindByTeacherAndUser(uc.DB.WithContext(ctx), &existing, request.TeacherID, request.UserID); err == nil {
		return fiber.NewError(409, "Вы уже оставили отзыв на этого преподавателя")
	}

	tx := uc.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	// Определяем курс пользователя по его группе
	var user entity.User
	course := 0
	if err := uc.UserRepository.FindById(uc.DB.WithContext(ctx), &user, request.UserID); err == nil {
		course = getCourseByGroup(user.Group)
	}

	review := entity.TeacherReview{
		TeacherID: request.TeacherID,
		UserID:    request.UserID,
		Comment:   strings.TrimSpace(request.Comment),
		Course:    course,
	}
	if err := uc.TeacherReviewRepository.Create(tx, &review); err != nil {
		uc.Log.Errorf("Failed to create review : %+v", err)
		return fiber.NewError(500, "Не удалось создать отзыв")
	}

	if err := tx.Commit().Error; err != nil {
		uc.Log.Errorf("Failed to commit : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}

// DeleteReview удаляет собственный отзыв пользователя.
func (uc *ReviewUseCase) DeleteReview(ctx context.Context, request *model.DeleteReviewRequest) error {
	if err := uc.Validate.Struct(request); err != nil {
		uc.Log.Warnf("Invalid delete review request : %+v", err)
		return fiber.ErrBadRequest
	}

	// Проверяем, существует ли отзыв
	var review entity.TeacherReview
	if err := uc.TeacherReviewRepository.FindByTeacherAndUser(uc.DB.WithContext(ctx), &review, request.TeacherID, request.UserID); err != nil {
		return fiber.NewError(404, "Отзыв не найден")
	}

	tx := uc.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	if err := uc.TeacherReviewRepository.DeleteByTeacherAndUser(tx, request.TeacherID, request.UserID); err != nil {
		uc.Log.Errorf("Failed to delete review : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		uc.Log.Errorf("Failed to commit : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}
