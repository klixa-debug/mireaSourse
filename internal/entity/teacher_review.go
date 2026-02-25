package entity

// TeacherReview — анонимный отзыв пользователя на преподавателя.
// Один пользователь может оставить не более одного отзыва на преподавателя.
type TeacherReview struct {
	ID        uint   `gorm:"column:id;primaryKey;autoIncrement"`
	TeacherID uint   `gorm:"column:teacher_id;not null;uniqueIndex:idx_teacher_user"`
	UserID    string `gorm:"column:user_id;size:255;not null;uniqueIndex:idx_teacher_user"`
	Comment   string `gorm:"column:comment;size:255;not null"`
	Course    int    `gorm:"column:course;not null;default:0"`
	CreatedAt int64  `gorm:"column:created_at;autoCreateTime:milli"`

	Teacher Teacher `gorm:"foreignKey:TeacherID"`
}
