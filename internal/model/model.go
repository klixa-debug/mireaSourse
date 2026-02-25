package model

type WebResponse[T any] struct {
	Data   T             `json:"data"`
	Paging *PageMetadata `json:"paging,omitempty"`
	Errors string        `json:"errors,omitempty"`
}

type PageResponse[T any] struct {
	Data         []T          `json:"data,omitempty"`
	PageMetadata PageMetadata `json:"paging,omitempty"`
}

type PageMetadata struct {
	Page      int   `json:"page"`
	Size      int   `json:"size"`
	TotalItem int64 `json:"total_item"`
	TotalPage int64 `json:"total_page"`
}

// Admin Statistics Models
type AdminStatsResponse struct {
	TotalUsers   int64 `json:"total_users"`
	UsersToday   int64 `json:"users_today"`
	TotalQrScans int64 `json:"total_qr_scans"`
	TodayQrScans int64 `json:"today_qr_scans"`
	UniqueGroups int64 `json:"unique_groups"`
}

type QrScanStats struct {
	TotalScans int64 `json:"total_scans"`
	TodayScans int64 `json:"today_scans"`
}
