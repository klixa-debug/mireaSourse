package model

// SearchTeacherRequest — запрос на поиск преподавателя по имени (подстрока).
type SearchTeacherRequest struct {
	Query string `json:"query" validate:"required,min=2,max=255"`
}

// AddTeacherRequest — запрос на добавление нового преподавателя.
type AddTeacherRequest struct {
	Name string `json:"name" validate:"required,min=2,max=255"`
}

// CreateReviewRequest — запрос на создание отзыва.
type CreateReviewRequest struct {
	UserID    string `json:"-"`
	TeacherID uint   `json:"teacher_id" validate:"required"`
	Comment   string `json:"comment" validate:"required,min=1,max=255"`
}

// DeleteReviewRequest — запрос на удаление своего отзыва.
type DeleteReviewRequest struct {
	UserID    string `json:"-"`
	TeacherID uint   `json:"teacher_id" validate:"required"`
}

// GetReviewsRequest — запрос на получение отзывов по преподавателю.
type GetReviewsRequest struct {
	TeacherID uint `json:"teacher_id" validate:"required"`
}

// TeacherResponse — ответ с данными преподавателя.
type TeacherResponse struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	ReviewCount int64  `json:"review_count"`
}

// ReviewResponse — ответ с данными отзыва (анонимный, без user_id).
type ReviewResponse struct {
	ID        uint   `json:"id"`
	Comment   string `json:"comment"`
	Course    int    `json:"course"`
	CreatedAt int64  `json:"created_at"`
	IsMine    bool   `json:"is_mine"`
}

// TeacherReviewsResponse — преподаватель + список отзывов.
type TeacherReviewsResponse struct {
	Teacher TeacherResponse  `json:"teacher"`
	Reviews []ReviewResponse `json:"reviews"`
}
