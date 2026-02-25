package entity

// SubjectAttendance is a struct that represents an attendance of subject entity
type SubjectAttendance struct {
	StudentId string  `gorm:"column:student_id"`
	GroupId   string  `gorm:"column:group_id"`
	Subject   string  `gorm:"column:subject"`
	Value     float64 `gorm:"column:value"`
}
