package model

type UserResponse struct {
	ID            string `json:"id,omitempty"`
	TelegramID    int64  `json:"telegram_id"`
	Email         string `json:"email"`
	Fullname      string `json:"fullname,omitempty"`
	Group         string `json:"group,omitempty"`
	CustomProxy   string `json:"custom_proxy,omitempty"`
	HasTotpSecret bool   `json:"has_totp_secret,omitempty"`
	CreatedAt     int64  `json:"created_at,omitempty"`
	UpdatedAt     int64  `json:"updated_at,omitempty"`
}

type AnotherStudentResponse struct {
	Email    string `json:"email"`
	Fullname string `json:"fullname,omitempty"`
	Group    string `json:"group,omitempty"`
}

type ConnectedStudentResponse struct {
	Email    string `json:"email"`
	Fullname string `json:"fullname"`
	Group    string `json:"group"`
	Enabled  bool   `json:"enabled"`
}

type RegisterUserRequest struct {
	TelegramId int64  `json:"-"`
	Email      string `json:"email" validate:"required,email,mireaDomain"`
	Password   string `json:"password" validate:"required,max=100"`
	OtpCode    string `json:"otp_code,omitempty" validate:"omitempty"` // Добавлено поле для 2FA кода
}

type LoginUserRequest struct {
	Username string `json:"username" validate:"required,max=100"`
	Password string `json:"password" validate:"required,max=100"`
}

type ConnectStudentRequest struct {
	TelegramId int64  `json:"-"`
	Email      string `json:"email" validate:"required,email,mireaDomain"`
}

type ChangePasswordRequest struct {
	TelegramId  int64  `json:"-"`
	NewPassword string `json:"new_password" validate:"required,max=100"`
}

type UpdateProxyRequest struct {
	TelegramId int64  `json:"-"`
	Proxy      string `json:"proxy" validate:"omitempty,max=500"`
}

type UpdateTotpSecretRequest struct {
	TelegramId int64  `json:"-"`
	TotpSecret string `json:"totp_secret" validate:"required,max=100"`
}

type UniversityStatusResponse struct {
	IsInUniversity bool                    `json:"is_in_university"`
	EntryTime      int64                   `json:"entry_time,omitempty"`
	ExitTime       int64                   `json:"exit_time,omitempty"`
	Events         []UniversityEventDetail `json:"events,omitempty"`
}

type UniversityEventDetail struct {
	Time          int64  `json:"time"`
	EntryLocation string `json:"entry_location"`
	ExitLocation  string `json:"exit_location"`
	IsEntry       bool   `json:"is_entry"`
}
