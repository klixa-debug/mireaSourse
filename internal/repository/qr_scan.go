package repository

import (
	"mirea-qr/internal/entity"
	"time"

	"gorm.io/gorm"
)

type QrScanRepository struct {
	*Repository[entity.QrScan]
}

func NewQrScanRepository(db *gorm.DB) *QrScanRepository {
	return &QrScanRepository{
		Repository: &Repository[entity.QrScan]{DB: db},
	}
}

func (r *QrScanRepository) CreateScan(db *gorm.DB, userID string, subject string, total int64, scanned int64) error {
	scan := &entity.QrScan{
		UserID:  userID,
		Subject: subject,
		Total:   total,
		Scanned: scanned,
	}
	return r.Create(db, scan)
}

func (r *QrScanRepository) GetTotalScans(db *gorm.DB) (int64, error) {
	var total int64
	err := db.Model(&entity.QrScan{}).Count(&total).Error
	return total, err
}

func (r *QrScanRepository) GetTodayScans(db *gorm.DB) (int64, error) {
	var total int64
	today := time.Now().Truncate(24 * time.Hour).UnixMilli()
	err := db.Model(&entity.QrScan{}).Where("scanned_at >= ?", today).Count(&total).Error
	return total, err
}

func (r *QrScanRepository) GetUniqueGroups(db *gorm.DB) (int64, error) {
	var total int64
	err := db.Model(&entity.User{}).Distinct("group").Count(&total).Error
	return total, err
}

func (r *QrScanRepository) GetUsersToday(db *gorm.DB) (int64, error) {
	var total int64
	today := time.Now().Truncate(24 * time.Hour).UnixMilli()
	err := db.Model(&entity.User{}).Where("created_at >= ?", today).Count(&total).Error
	return total, err
}

func (r *QrScanRepository) GetTotalUsers(db *gorm.DB) (int64, error) {
	var total int64
	err := db.Model(&entity.User{}).Count(&total).Error
	return total, err
}
