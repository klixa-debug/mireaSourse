package repository

import (
	"mirea-qr/internal/entity"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type TeacherRepository struct {
	Repository[entity.Teacher]
	Log *logrus.Logger
}

func NewTeacherRepository(log *logrus.Logger) *TeacherRepository {
	return &TeacherRepository{
		Log: log,
	}
}

// SearchByName ищет преподавателей по подстроке имени (ILIKE).
func (r *TeacherRepository) SearchByName(db *gorm.DB, teachers *[]entity.Teacher, query string) error {
	return db.Where("name ILIKE ?", "%"+query+"%").
		Order("name ASC").
		Limit(20).
		Find(teachers).Error
}

// FindByName находит преподавателя по точному имени (case-insensitive).
func (r *TeacherRepository) FindByName(db *gorm.DB, teacher *entity.Teacher, name string) error {
	return db.Where("LOWER(name) = LOWER(?)", name).Take(teacher).Error
}

// FindAll возвращает всех преподавателей, отсортированных по имени.
func (r *TeacherRepository) FindAll(db *gorm.DB, teachers *[]entity.Teacher) error {
	return db.Order("name ASC").Find(teachers).Error
}

// CountReviews возвращает количество отзывов для преподавателя.
func (r *TeacherRepository) CountReviews(db *gorm.DB, teacherID uint) (int64, error) {
	var count int64
	err := db.Model(&entity.TeacherReview{}).Where("teacher_id = ?", teacherID).Count(&count).Error
	return count, err
}
