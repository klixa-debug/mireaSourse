package repository

import (
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"mirea-qr/internal/entity"
)

type UserRepository struct {
	Repository[entity.User]
	Log *logrus.Logger
}

func NewUserRepository(log *logrus.Logger) *UserRepository {
	return &UserRepository{
		Log: log,
	}
}

func (r *UserRepository) FindByUsername(db *gorm.DB, user *entity.User, username string) error {
	return db.Where("username = ?", username).First(user).Error
}

func (r *UserRepository) FindByTelegramID(db *gorm.DB, user *entity.User, telegramId int64) error {
	return db.Where("telegram_id = ?", telegramId).First(user).Error
}

func (r *UserRepository) FindByEmail(db *gorm.DB, user *entity.User, email string) error {
	return db.Where("email = ?", email).First(user).Error
}

func (r *UserRepository) UpdateTelegramId(db *gorm.DB, user entity.User, telegramId int64) error {
	return db.Model(&user).Update("telegram_id", telegramId).Error
}
