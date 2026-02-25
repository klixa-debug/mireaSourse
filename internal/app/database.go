package app

import (
	"fmt"
	"mirea-qr/internal/entity"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func NewDatabase(cfg Config, log *logrus.Logger) *gorm.DB {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable TimeZone=Europe/Moscow",
		cfg.DatabaseHost,
		cfg.DatabaseUser,
		cfg.DatabasePassword,
		cfg.DatabaseDb,
		cfg.DatabasePort,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.New(&logrusWriter{Logger: log}, logger.Config{
			SlowThreshold:             time.Second * 5,
			Colorful:                  false,
			IgnoreRecordNotFoundError: true,
			ParameterizedQueries:      true,
			LogLevel:                  logger.Info,
		}),
	})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	if err := db.AutoMigrate(&entity.User{}, &entity.LinkUser{}, &entity.SubjectAttendance{}, &entity.QrScan{}, &entity.Teacher{}, &entity.TeacherReview{}); err != nil {
		log.Fatalf("failed auto migration : %v", err)
	}

	return db
}

func TruncateAllTables(db *gorm.DB) error {
	var tables []string
	db.Raw("SELECT tablename FROM pg_tables WHERE schemaname = 'public'").Scan(&tables)

	for _, table := range tables {
		if err := db.Exec("TRUNCATE TABLE " + table + " CASCADE").Error; err != nil {
			return err
		}
	}

	return nil
}

type logrusWriter struct {
	Logger *logrus.Logger
}

func (l *logrusWriter) Printf(message string, args ...interface{}) {
	l.Logger.Tracef(message, args...)
}
