package main

import (
	"fmt"
	"mirea-qr/internal/app"
	"mirea-qr/pkg/crypto"
)

func main() {
	cfg := app.NewConfig()
	logger := app.NewLogger(cfg)
	db := app.NewDatabase(cfg, logger)
	fiber := app.NewFiber(cfg)
	redis := app.NewRedis(cfg)
	validator := app.NewValidator(cfg)
	bot := app.NewBot(cfg, redis)

	// Initialize encryption
	encryptor, err := crypto.NewEncryptor(cfg.EncryptionKey)
	if err != nil {
		logger.Fatalf("Failed to initialize encryption: %v", err)
	}

	app.Bootstrap(app.BootstrapConfig{
		DB:        db,
		App:       fiber,
		Log:       logger,
		Cfg:       cfg,
		Redis:     redis,
		Validator: validator,
		Bot:       bot,
		Encryptor: encryptor,
	})
	if err := fiber.Listen(fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)); err != nil {
		logger.Fatalf("Failed to start server: %v", err)
	}
}
