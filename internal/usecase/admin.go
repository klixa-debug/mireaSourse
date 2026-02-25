package usecase

import (
        "github.com/redis/go-redis/v9"
        "context"
        "mirea-qr/internal/model"
        "mirea-qr/internal/repository"

        "github.com/gofiber/fiber/v3"
        "github.com/sirupsen/logrus"
        "gorm.io/gorm"
)

type AdminUseCase struct {
        DB               *gorm.DB
        Log              *logrus.Logger
        QrScanRepository *repository.QrScanRepository
        Redis            *redis.Client
}

func NewAdminUseCase(db *gorm.DB, logger *logrus.Logger, qrScanRepository *repository.QrScanRepository, redis *redis.Client) *AdminUseCase {
        return &AdminUseCase{
                DB:               db,
                Log:              logger,
                QrScanRepository: qrScanRepository,
                Redis:            redis,
        }
}

func (c *AdminUseCase) GetStats(ctx context.Context) (*model.AdminStatsResponse, error) {
	totalUsers, err := c.QrScanRepository.GetTotalUsers(c.DB)
	if err != nil {
		c.Log.Errorf("Failed to get total users: %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	usersToday, err := c.QrScanRepository.GetUsersToday(c.DB)
	if err != nil {
		c.Log.Errorf("Failed to get users today: %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	totalQrScans, err := c.QrScanRepository.GetTotalScans(c.DB)
	if err != nil {
		c.Log.Errorf("Failed to get total QR scans: %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	todayQrScans, err := c.QrScanRepository.GetTodayScans(c.DB)
	if err != nil {
		c.Log.Errorf("Failed to get today QR scans: %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	uniqueGroups, err := c.QrScanRepository.GetUniqueGroups(c.DB)
	if err != nil {
		c.Log.Errorf("Failed to get unique groups: %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	return &model.AdminStatsResponse{
		TotalUsers:   totalUsers,
		UsersToday:   usersToday,
		TotalQrScans: totalQrScans,
		TodayQrScans: todayQrScans,
		UniqueGroups: uniqueGroups,
	}, nil
}

func (c *AdminUseCase) RecordQrScan(ctx context.Context, userID string, subject string, total int64, scanned int64) error {
	if err := c.QrScanRepository.CreateScan(c.DB, userID, subject, total, scanned); err != nil {
		c.Log.Errorf("Failed to record QR scan: %+v", err)
		return fiber.ErrInternalServerError
	}
	return nil
}
