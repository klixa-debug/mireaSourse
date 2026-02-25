package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/redis/go-redis/v9"
	"log"
	"net/http"
	"strconv"
	"time"
)

func NewBot(cfg Config, redisClient *redis.Client) *tgbotapi.BotAPI {
	bot, err := tgbotapi.NewBotAPI(cfg.TelegramBotToken)
	if err != nil {
		log.Panic(err)
	}

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := bot.GetUpdatesChan(u)

	go func(updates tgbotapi.UpdatesChannel) {
		for update := range updates {
			if update.Message != nil && update.Message.IsCommand() {
				if update.Message.Command() == "start" {
					url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.TelegramBotToken)

					payload := map[string]interface{}{
						"chat_id":    update.Message.Chat.ID,
						"parse_mode": "HTML",
						"text":       "<b>👋 Добро пожаловать в MIREA TOOLS!</b>\n\nДанный бот предназначен для помощи студентам в системе БРС.\n\n<b>📌 Что умеет данный бот?\n📷 Сканировать QR:</b> \nСтудент может одним QR кодом отметить несколько других студентов.\n\n<b>🏅 Узнать баллы:</b> \nПолучение баллов сразу о всех дисциплинах.\n\n<b>🪪 Расчет посещаемости:</b> \nПосмотреть, сколько баллов можно потерять за пропуск дисциплины.\n\n❗️ Канал с новостями и обновлениями @mirea_tools",
						"reply_markup": map[string]interface{}{
							"inline_keyboard": [][]map[string]interface{}{
								{
									{
										"text": "🖥 Открыть MIREA TOOLS",
										"web_app": map[string]string{
											"url": cfg.TelegramWebUrl,
										},
									},
								},
							},
						},
					}

					jsonData, err := json.Marshal(payload)
					if err != nil {
						log.Printf("Error marshal JSON for bot : %+v", err)
					}

					_, err = http.Post(url, "application/json", bytes.NewBuffer(jsonData))
					if err != nil {
						log.Printf("Error request for bot : %+v", err)
					}

					redisClient.SAdd(context.Background(),
						"bot:daily_users:"+time.Now().Format("2006-01-02"),
						strconv.FormatInt(update.Message.From.ID, 10))
				}
				
				if update.CallbackQuery != nil {
				    redisClient.SAdd(context.Background(),
				        "bot:daily_users:"+time.Now().Format("2006-01-02"),
					strconv.FormatInt(update.CallbackQuery.From.ID, 10))
				} 
			}
		}
	}(updates)

	return bot
}
