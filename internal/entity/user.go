package entity

// User is a struct that represents a user entity
type User struct {
	ID          string `gorm:"column:id;primaryKey"`
	TelegramId  int64  `gorm:"column:telegram_id;unique"`
	Email       string `gorm:"column:email;unique"`
	Password    string `gorm:"column:password"`
	Fullname    string `gorm:"column:fullname"`
	Group       string `gorm:"column:group"`
	GroupID     string `gorm:"column:group_id"`
	UserAgent   string `gorm:"column:user_agent"`
	CustomProxy string `gorm:"column:custom_proxy"`
	TotpSecret  string `gorm:"column:totp_secret"`
	CreatedAt   int64  `gorm:"column:created_at;autoCreateTime:milli"`
	UpdatedAt   int64  `gorm:"column:updated_at;autoCreateTime:milli;autoUpdateTime:milli"`
}
