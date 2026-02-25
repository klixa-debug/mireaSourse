package entity

type LinkUser struct {
	FromUserID  string `gorm:"column:from_user_id"`
	ToUserID    string `gorm:"column:to_user_id"`
	ConnectedAt int64  `gorm:"column:connected_at;autoCreateTime:milli"`
	Enabled     bool   `gorm:"column:enabled"`

	FromUser User `gorm:"foreignKey:FromUserID"`
	ToUser   User `gorm:"foreignKey:ToUserID"`
}
