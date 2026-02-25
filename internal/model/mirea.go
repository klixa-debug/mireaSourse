package model

type DisciplinesResponse struct {
	CountStudents int64                `json:"count_students"`
	Disciplines   []DisciplineResponse `json:"disciplines"`
}

type DisciplineScoreData struct {
	Title string  `json:"title"`
	Now   float64 `json:"now"`
	Max   float64 `json:"max"`
}

type DisciplineResponse struct {
	Title     string                `json:"title"`
	Total     float64               `json:"total"`
	AvgGroup  float64               `json:"avg_group"`
	ScoreData []DisciplineScoreData `json:"score_data,omitempty"`
}

type LessonResponse struct {
	Uuid       string   `json:"uuid"`
	Auditorium string   `json:"auditorium"`
	Campus     string   `json:"campus"`
	Title      string   `json:"title"`
	Type       string   `json:"type"`
	Start      int32    `json:"start"`
	End        int32    `json:"end"`
	Teacher    string   `json:"teacher"`
	Groups     []string `json:"groups"`
	Attended   int32    `json:"attended"`
	Total      int32    `json:"total"`
	Status     int32    `json:"status"`
}

type FindStudentRequest struct {
	Email string `json:"email" validate:"required,email,mireaDomain"`
}

type ScanQRRequest struct {
	FromUserId string `json:"-"`
	URL        string `json:"url"`
}

type ScanQRResponse struct {
	Students map[string]uint `json:"students"`
	Subject  string          `json:"subject"`
}

type StatusBypassResponse struct {
	Status bool `json:"status"`
	Time   int  `json:"time"`
}

type GetLessons struct {
	Year  int32 `json:"year"`
	Month int32 `json:"month"`
	Day   int32 `json:"day"`
}

type AttendanceRequest struct {
	LessonUUID string `json:"lesson_uuid"`
}

type AttendanceStudentResponse struct {
	Fullname string `json:"fullname"`
	Status   int32  `json:"status"`
	IsElder  bool   `json:"is_elder"`
}

type DeadlineResponse struct {
	Title     string `json:"title"`
	Timestamp int64  `json:"timestamp"`
	Subject   string `json:"subject"`
}
