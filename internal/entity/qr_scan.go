package entity

// QrScan is a struct that represents a QR scan entity
type QrScan struct {
	ID        uint   `gorm:"column:id;primaryKey;autoIncrement"`
	UserID    string `gorm:"column:user_id;not null"`
	Subject   string `gorm:"column:subject;not null"`
	Total     int64  `gorm:"column:total"`
	Scanned   int64  `gorm:"column:scanned"`
	ScannedAt int64  `gorm:"column:scanned_at;autoCreateTime:milli"`
}
