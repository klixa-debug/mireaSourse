package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v3"
	initdata "github.com/telegram-mini-apps/init-data-golang"
	"mirea-qr/internal/usecase"
	"sort"
	"strconv"
	"strings"
	"time"
)

func NewTelegram(telegramBotToken string, userUserCase *usecase.UserUseCase) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		var data map[string]interface{}

		if err := ctx.Bind().JSON(&data); err != nil {
			userUserCase.Log.Debugf("Request is not json")
			return fiber.ErrBadRequest
		}

		miniAppHash, miniAppExists := data["miniAppUser"].(string)
		webAppHash, webAppExists := data["webAppUser"].(map[string]interface{})
		if !miniAppExists && !webAppExists {
			userUserCase.Log.Debugf("Request without user field")
			return fiber.ErrBadRequest
		}

		if miniAppExists && miniAppHash != "" {
			userUserCase.Log.Debugf("User mini app field before handler: %s", miniAppHash)

			if err := initdata.Validate(miniAppHash, telegramBotToken, 24*time.Hour); err != nil {
				userUserCase.Log.Warnf("Failed validate user telegram : %s", err.Error())
				return fiber.NewError(403, err.Error())
			}

			parse, err := initdata.Parse(miniAppHash)
			if err != nil {
				return fiber.NewError(500, err.Error())
			}

			userUserCase.Log.Debugf("User TG : %+v", parse.User)

			ctx.Locals("telegram_id", parse.User.ID)
		}

		if webAppExists {
			userUserCase.Log.Debugf("User web app field before handler: %s", webAppHash)
			userId, err := validateWebAppUser(telegramBotToken, webAppHash)
			if err != nil {
				userUserCase.Log.Warnf("Failed validate user web telegram : %s", err.Error())
				return fiber.NewError(403, err.Error())
			}

			userUserCase.Log.Debugf("User TG : %+v", userId)

			ctx.Locals("telegram_id", userId)
		}

		return ctx.Next()
	}
}

func GetTelegramId(ctx fiber.Ctx) int64 {
	telegramId := ctx.Locals("telegram_id")
	if telegramId == nil {
		return -1
	}

	return telegramId.(int64)
}

func validateWebAppUser(telegramBotToken string, data map[string]interface{}) (int64, error) {
	id, ok := data["id"].(float64)
	if !ok {
		return 0, errors.New("missed or invalid 'id' field")
	}

	hash, ok := data["hash"].(string)
	if !ok || hash == "" {
		return 0, errors.New("missed or invalid 'hash' field")
	}

	delete(data, "hash")

	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var dataCheckString strings.Builder
	for _, key := range keys {
		value := data[key]
		var strValue string

		switch v := value.(type) {
		case string:
			strValue = v
		case float64:
			strValue = strconv.Itoa(int(v))
		case bool:
			strValue = strconv.FormatBool(v)
		default:
			return 0, fmt.Errorf("unsupported type for key %s", key)
		}

		dataCheckString.WriteString(fmt.Sprintf("%s=%s\n", key, strValue))
	}

	dataCheckStr := strings.Trim(dataCheckString.String(), "\n")

	sha256hash := sha256.Sum256([]byte(telegramBotToken))
	hmachash := hmac.New(sha256.New, sha256hash[:])
	hmachash.Write([]byte(dataCheckStr))
	expectedHash := hex.EncodeToString(hmachash.Sum(nil))

	if hash != expectedHash {
		return 0, errors.New("wrong hash")
	}

	return int64(id), nil
}
