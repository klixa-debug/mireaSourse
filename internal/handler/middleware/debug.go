package middleware

import (
	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
	"runtime"
	"strings"
	"time"
)

func NewDebug() fiber.Handler {
	return func(ctx fiber.Ctx) error {
		start := time.Now()
		next := ctx.Next()
		duration := time.Since(start)

		stackTrace := getStackTrace()

		logrus.Println(duration, stackTrace)

		return next
	}
}

func getStackTrace() string {
	var sb strings.Builder
	stackBuf := make([]byte, 1<<16) // 64KB
	n := runtime.Stack(stackBuf, false)
	sb.Write(stackBuf[:n])
	return sb.String()
}
