package entity

// Teacher представляет преподавателя, на которого можно оставить отзыв.
type Teacher struct {
	ID        uint   `gorm:"column:id;primaryKey;autoIncrement"`
	Name      string `gorm:"column:name;uniqueIndex;size:255;not null"`
	CreatedAt int64  `gorm:"column:created_at;autoCreateTime:milli"`
}
