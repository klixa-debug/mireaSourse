package repository

import (
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"mirea-qr/internal/entity"
)

type LinkUserRepository struct {
	Repository[entity.LinkUser]
	Log *logrus.Logger
}

func NewLinkUserRepository(log *logrus.Logger) *LinkUserRepository {
	return &LinkUserRepository{
		Log: log,
	}
}

func (r *LinkUserRepository) GetConnectedByUser(db *gorm.DB, entity *[]*entity.LinkUser, id any) error {
	return db.Preload("FromUser").Preload("ToUser").Where("from_user_id = ?", id).Find(entity).Error
}

func (r *LinkUserRepository) GetConnectedToUser(db *gorm.DB, entity *[]*entity.LinkUser, id any) error {
	return db.Preload("FromUser").Preload("ToUser").Where("to_user_id = ?", id).Find(entity).Error
}

func (r *LinkUserRepository) FindLinkUser(db *gorm.DB, entity *entity.LinkUser, fromUser string, toUser string) error {
	return db.Preload("FromUser").Preload("ToUser").Where("from_user_id = ? AND to_user_id = ?", fromUser, toUser).Find(entity).Error
}

func (r *LinkUserRepository) UpdateLinkUser(db *gorm.DB, entity *entity.LinkUser) error {
	return db.Model(&entity).Where("from_user_id = ? AND to_user_id = ?", entity.FromUserID, entity.ToUserID).Update("enabled", entity.Enabled).Error
}

func (r *LinkUserRepository) DeleteLinkUser(db *gorm.DB, fromUserID string, toUserID string) error {
	return db.Where("from_user_id = ? AND to_user_id = ?", fromUserID, toUserID).Delete(&entity.LinkUser{}).Error
}

func (r *LinkUserRepository) DeleteByFromUser(db *gorm.DB, fromUserID string) error {
	return db.Where("from_user_id = ?", fromUserID).Delete(&entity.LinkUser{}).Error
}

func (r *LinkUserRepository) DeleteByToUser(db *gorm.DB, toUserID string) error {
	return db.Where("to_user_id = ?", toUserID).Delete(&entity.LinkUser{}).Error
}
