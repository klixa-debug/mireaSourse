package mirea

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mirea-qr/internal/entity"
	"mirea-qr/pkg/customerrors"
	"mirea-qr/pkg/proxy"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"resty.dev/v3"
)

type OnlineEdu struct {
	user    entity.User
	client  *resty.Client
	redis   *redis.Client
	sessKey string
}

type OnlineEduSession struct {
	Cookies []*http.Cookie `json:"cookies"`
	SessKey string         `json:"sess_key"`
}

type Course struct {
	ID    int     `json:"id"`
	Title string  `json:"title"`
	Ball  float64 `json:"ball"`
}

type CourseResponse struct {
	Data struct {
		Courses []struct {
			ID       int    `json:"id"`
			Fullname string `json:"fullname"`
		} `json:"courses"`
	} `json:"data"`
}

type Deadline struct {
	Title     string `json:"title"`
	Timestamp int64  `json:"timestamp"`
	Subject   string `json:"subject"`
}

func NewOnlineEdu(user entity.User, redis *redis.Client) *OnlineEdu {
	client := resty.New()

	randProxy, err := proxy.GetUserProxy(user.CustomProxy, redis)
	if err != nil {
		log.Fatalf("failed load proxy : %+v", err)
	}

	client.SetHeader("User-Agent", user.UserAgent)
	client.SetProxy(randProxy)

	return &OnlineEdu{
		user:   user,
		client: client,
		redis:  redis,
	}
}

func (o *OnlineEdu) GetCurrentUser() entity.User {
	return o.user
}

func (o *OnlineEdu) saveSessionToRedis() error {
	ctx := context.Background()
	u, _ := url.Parse("https://online-edu.mirea.ru")
	cookies := o.client.CookieJar().Cookies(u)

	session := OnlineEduSession{
		Cookies: cookies,
		SessKey: o.sessKey,
	}

	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	return o.redis.Set(ctx, o.getSessionKeyToRedis(), data, 7*24*time.Hour).Err()
}

func (o *OnlineEdu) loadSessionFromRedis() error {
	ctx := context.Background()
	data, err := o.redis.Get(ctx, o.getSessionKeyToRedis()).Bytes()

	if err != nil {
		return err
	}

	var session OnlineEduSession
	if err := json.Unmarshal(data, &session); err != nil {
		return err
	}

	o.client.SetCookies(session.Cookies)
	o.sessKey = session.SessKey
	return nil
}

func (o *OnlineEdu) getSessionKeyToRedis() string {
	return "sess_edu_" + o.user.Email
}

func (o *OnlineEdu) getSessKey() (string, error) {
	resp, err := o.client.R().
		Get("https://online-edu.mirea.ru/login/index.php")
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`sesskey=(.*?)"`)
	matches := re.FindStringSubmatch(resp.String())
	if len(matches) < 2 {
		return "", errors.New("sesskey not found")
	}

	return matches[1], nil
}

// Authorization in online-edu.mirea.ru
func (o *OnlineEdu) Authorization() (string, error) {
	if err := o.loadSessionFromRedis(); err == nil {
		if _, err := o.GetDeadlines(); err == nil {
			return "Кэшированная сессия", nil
		}
	}

	sessKey, err := o.getSessKey()
	if err != nil {
		return "", err
	}

	// Первый запрос для получения CSRF токена
	resp, err := o.client.R().
		Get(fmt.Sprintf("https://online-edu.mirea.ru/auth/oauth2/login.php?id=3&wantsurl=%%2F&sesskey=%s", sessKey))
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`"loginAction": "(.*?)"`)
	match := re.FindStringSubmatch(resp.String())
	if len(match) < 2 {
		return "", customerrors.NewAuthError("site_error", "Ошибка получения cсылки авторизации с сайта MIREA", errors.New("login action not found"))
	}

	loginResp, err := o.client.R().
		SetFormData(map[string]string{
			"username":     o.user.Email,
			"password":     o.user.Password,
			"rememberMe":   "on",
			"credentialId": "",
		}).
		SetHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7").
		SetHeader("Origin", "null").
		Post(match[1])
	if err != nil {
		return "", customerrors.NewAuthError("site_unavailable", "Сайт MIREA недоступен", err)
	}

	redirects := loginResp.RedirectHistory()
	if len(redirects) == 0 {
		return "", customerrors.NewAuthError("invalid_credentials", "Неверный логин или пароль от MIREA", errors.New("not redirected after authorization"))
	}

	// Проверяем, успешна ли авторизация по редиректу
	if redirects[0].URL != "https://online-edu.mirea.ru/my/" {
		// Если редирект не на ожидаемую страницу, скорее всего неверные данные
		return "", customerrors.NewAuthError("invalid_credentials", "Неверный логин или пароль от MIREA", errors.New("last redirect is "+redirects[0].URL))
	}

	// Проверяем успешность авторизации по наличию приветствия
	fioRe := regexp.MustCompile(`Здравствуйте, (.*?)!`)
	fioMatches := fioRe.FindStringSubmatch(loginResp.String())
	if len(fioMatches) != 2 {
		return "", errors.New("authorization failed - welcome message not found")
	}

	// Извлекаем новый sesskey
	sessKeyRe := regexp.MustCompile(`sesskey=(.*?)"`)
	sessKeyMatches := sessKeyRe.FindStringSubmatch(loginResp.String())
	if len(sessKeyMatches) < 2 {
		return "", errors.New("sesskey not found after authorization")
	}

	o.sessKey = sessKeyMatches[1]

	// Сохраняем сессию в Redis
	if err := o.saveSessionToRedis(); err != nil {
		return "", err
	}

	return fioMatches[1], nil
}

func (o *OnlineEdu) GetDeadlines() ([]Deadline, error) {
	resp, err := o.client.R().Get("https://online-edu.mirea.ru/calendar/view.php?view=upcoming")
	if err != nil {
		return nil, err
	}

	html := resp.String()
	// найти старт каждого блока события
	startRe := regexp.MustCompile(`(?i)<div[^>]*\bdata-type=["']event["'][^>]*>`)
	starts := startRe.FindAllStringIndex(html, -1)
	if len(starts) == 0 {
		return nil, nil
	}

	// разбить на блоки (каждый блок — от текущего start до следующего start)
	var blocks []string
	for i, s := range starts {
		start := s[0]
		var end int
		if i+1 < len(starts) {
			end = starts[i+1][0]
		} else {
			end = len(html)
		}
		blocks = append(blocks, html[start:end])
	}

	// подрегулярки для извлечения полей внутри блока
	titleRe := regexp.MustCompile(`data-event-title=["']([^"']+)["']`)
	h3Re := regexp.MustCompile(`(?i)<h3[^>]*>([^<]+)</h3>`)
	timeRe := regexp.MustCompile(`time=(\d+)`)
	courseLinkRe := regexp.MustCompile(`href="[^"]*course\/view\.php\?id=\d+[^"]*"[^>]*>([^<]+)</a>`)
	spanEventCourseRe := regexp.MustCompile(`(?i)<span[^>]*class=["'][^"']*event-course[^"']*["'][^>]*>([^<]+)</span>`)
	col11LinkRe := regexp.MustCompile(`(?i)<div[^>]*class=["'][^"']*col-11[^"']*["'][^>]*>\s*<a[^>]*>([^<]+)</a>`)

	var out []Deadline
	for _, block := range blocks {
		// title (data-event-title preferred, fallback h3)
		title := ""
		if m := titleRe.FindStringSubmatch(block); m != nil {
			title = strings.TrimSpace(m[1])
		} else if m := h3Re.FindStringSubmatch(block); m != nil {
			title = strings.TrimSpace(m[1])
		}

		lower := strings.ToLower(title)
		if !strings.Contains(lower, "закрывается") && !strings.Contains(lower, "срок сдачи") {
			continue
		}
		title = strings.Split(title, "-")[0]

		// timestamp
		var ts int64
		if m := timeRe.FindStringSubmatch(block); m != nil {
			if v, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				ts = v
			}
		}

		// subject: пытаем несколько вариантов
		subject := ""
		if m := courseLinkRe.FindStringSubmatch(block); m != nil {
			subject = strings.TrimSpace(m[1])
		}
		if subject == "" {
			if m := spanEventCourseRe.FindStringSubmatch(block); m != nil {
				subject = strings.TrimSpace(m[1])
			}
		}
		if subject == "" {
			if m := col11LinkRe.FindStringSubmatch(block); m != nil {
				subject = strings.TrimSpace(m[1])
			}
		}
		// обрезаем часть в скобках
		if i := strings.IndexAny(subject, "(["); i != -1 {
			subject = strings.TrimSpace(subject[:i])
		}

		out = append(out, Deadline{
			Subject:   subject,
			Title:     title,
			Timestamp: ts,
		})
	}

	return out, nil
}
