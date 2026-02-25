package repository

import (
	"mirea-qr/internal/entity"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type TeacherReviewRepository struct {
	Repository[entity.TeacherReview]
	Log *logrus.Logger
}

func NewTeacherReviewRepository(log *logrus.Logger) *TeacherReviewRepository {
	return &TeacherReviewRepository{
		Log: log,
	}
}

// FindByTeacherID возвращает все отзывы для преподавателя, отсортированные по дате.
func (r *TeacherReviewRepository) FindByTeacherID(db *gorm.DB, reviews *[]entity.TeacherReview, teacherID uint) error {
	return db.Where("teacher_id = ?", teacherID).
		Order("created_at DESC").
		Find(reviews).Error
}

// FindByTeacherAndUser проверяет, оставлял ли пользователь отзыв на преподавателя.
func (r *TeacherReviewRepository) FindByTeacherAndUser(db *gorm.DB, review *entity.TeacherReview, teacherID uint, userID string) error {
	return db.Where("teacher_id = ? AND user_id = ?", teacherID, userID).Take(review).Error
}

// DeleteByTeacherAndUser удаляет отзыв пользователя на преподавателя.
func (r *TeacherReviewRepository) DeleteByTeacherAndUser(db *gorm.DB, teacherID uint, userID string) error {
	return db.Where("teacher_id = ? AND user_id = ?", teacherID, userID).
		Delete(&entity.TeacherReview{}).Error
}
