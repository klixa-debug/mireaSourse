package app

import (
	"fmt"
	"github.com/redis/go-redis/v9"
)

func NewRedis(cfg Config) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.RedisHost, cfg.RedisPort),
		Password: cfg.RedisPassword,
		DB:       0,
	})
}
