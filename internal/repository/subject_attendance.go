package repository

import (
	"mirea-qr/internal/entity"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type SubjectAttendanceRepository struct {
	Repository[entity.SubjectAttendance]
	Log *logrus.Logger
}

func NewSubjectAttendanceRepository(log *logrus.Logger) *SubjectAttendanceRepository {
	return &SubjectAttendanceRepository{
		Log: log,
	}
}

func (r *SubjectAttendanceRepository) HasForUser(db *gorm.DB, studentId string, groupId string, subject string) bool {
	var subjectAttendance *entity.SubjectAttendance

	if err := db.Where("student_id = ? AND group_id = ? AND subject = ?", studentId, groupId, subject).First(&subjectAttendance).Error; err != nil {
		return false
	}

	if subjectAttendance == nil {
		return false
	}

	return true
}

func (r *SubjectAttendanceRepository) GetAvgForSubjectByGroup(db *gorm.DB, groupId string, subject string) float64 {
	var avg float64

	row := db.Model(&entity.SubjectAttendance{}).Where("group_id = ? AND subject = ?", groupId, subject).Select("AVG(value)").Row()
	err := row.Scan(&avg)
	if err != nil {
		return -1
	}

	return avg
}

func (r *SubjectAttendanceRepository) GetCountStudents(db *gorm.DB, groupId string) int64 {
	var count int64

	db.Model(&entity.SubjectAttendance{}).Where("group_id = ?", groupId).Select("COUNT(DISTINCT student_id)").Count(&count)

	return count
}

func (r *SubjectAttendanceRepository) UpdateValueForUser(db *gorm.DB, studentId string, groupId string, subject string, value float64) error {
	return db.Model(&entity.SubjectAttendance{}).
		Where("student_id = ? AND group_id = ? AND subject = ?", studentId, groupId, subject).
		Update("value", value).Error
}
