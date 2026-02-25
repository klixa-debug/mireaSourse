package proxy

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	proxies    []string
	proxyIndex uint64
	once       sync.Once
	loadMutex  sync.Mutex
)

func loadProxies() error {
	filePath := "storage/proxy.txt"

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var lines []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if len(lines) == 0 {
		return os.ErrNotExist
	}

	proxies = lines
	return nil
}

func GetRandomProxy() (string, error) {
	var loadErr error
	once.Do(func() {
		loadMutex.Lock()
		defer loadMutex.Unlock()
		if len(proxies) == 0 {
			loadErr = loadProxies()
		}
	})

	if loadErr != nil {
		return "", loadErr
	}

	if len(proxies) == 0 {
		return "", os.ErrNotExist
	}

	index := atomic.AddUint64(&proxyIndex, 1) - 1
	selectedIndex := int(index) % len(proxies)

	return proxies[selectedIndex], nil
}

// BlockProxy блокирует прокси на указанное время
func BlockProxy(redis *redis.Client, proxyAddr string, duration time.Duration) error {
	if redis == nil {
		return nil // Если Redis недоступен, просто пропускаем блокировку
	}
	if duration == 0 {
		duration = 2 * time.Minute
	}
	ctx := context.Background()
	key := fmt.Sprintf("proxy_blocked_%s", proxyAddr)
	return redis.Set(ctx, key, true, duration).Err()
}

// IsProxyBlocked проверяет, заблокирован ли прокси
func IsProxyBlocked(redis *redis.Client, proxyAddr string) bool {
	if redis == nil {
		return false
	}
	ctx := context.Background()
	key := fmt.Sprintf("proxy_blocked_%s", proxyAddr)
	return redis.Get(ctx, key).Err() == nil
}

// GetRandomProxyWithRedis получает случайный прокси, пропуская заблокированные
func GetRandomProxyWithRedis(redis *redis.Client) (string, error) {
	var loadErr error
	once.Do(func() {
		loadMutex.Lock()
		defer loadMutex.Unlock()
		if len(proxies) == 0 {
			loadErr = loadProxies()
		}
	})

	if loadErr != nil {
		return "", loadErr
	}

	if len(proxies) == 0 {
		return "", os.ErrNotExist
	}

	if redis == nil {
		return GetRandomProxy()
	}

	maxAttempts := len(proxies)

	for i := 0; i < maxAttempts; i++ {
		index := atomic.AddUint64(&proxyIndex, 1) - 1
		selectedIndex := int(index) % len(proxies)
		selectedProxy := proxies[selectedIndex]

		if !IsProxyBlocked(redis, selectedProxy) {
			return selectedProxy, nil
		}
	}

	return proxies[0], nil
}

// GetUserProxy возвращает пользовательский прокси, если он указан, иначе использует GetRandomProxyWithRedis
func GetUserProxy(userProxy string, redis *redis.Client) (string, error) {
	if userProxy != "" {
		return userProxy, nil
	}

	return GetRandomProxyWithRedis(redis)
}
