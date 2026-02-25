package app

import (
	"log"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Name  string
	Debug bool

	Host string
	Port int

	DatabaseUser     string `envconfig:"POSTGRES_USER"`
	DatabasePassword string `envconfig:"POSTGRES_PASSWORD"`
	DatabaseHost     string `envconfig:"POSTGRES_HOST"`
	DatabasePort     int    `envconfig:"POSTGRES_PORT"`
	DatabaseDb       string `envconfig:"POSTGRES_DB"`

	RedisHost     string `envconfig:"REDIS_HOST"`
	RedisPort     int    `envconfig:"REDIS_PORT"`
	RedisPassword string `envconfig:"REDIS_PASSWORD"`

	JwtSecret        []byte `envconfig:"JWT_SECRET"`
	EncryptionKey    []byte `envconfig:"ENCRYPTION_KEY"`
	TelegramBotToken string `envconfig:"TELEGRAM_BOT_TOKEN"`
	TelegramWebUrl   string `envconfig:"TELEGRAM_WEB_URL"`
	AdminUserID      int64  `envconfig:"ADMIN_USER_ID"`
}

func NewConfig() Config {
	var cfg Config

	err := godotenv.Load()
	if err != nil {
		log.Fatal(err.Error())
	}

	err = envconfig.Process("APP", &cfg)
	if err != nil {
		log.Fatal(err.Error())
	}

	return cfg
}
