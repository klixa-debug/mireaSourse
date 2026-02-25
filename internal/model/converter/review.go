package converter

import (
	"mirea-qr/internal/entity"
	"mirea-qr/internal/model"
)

func TeacherToResponse(teacher *entity.Teacher, reviewCount int64) model.TeacherResponse {
	return model.TeacherResponse{
		ID:          teacher.ID,
		Name:        teacher.Name,
		ReviewCount: reviewCount,
	}
}

func ReviewToResponse(review *entity.TeacherReview, currentUserID string) model.ReviewResponse {
	return model.ReviewResponse{
		ID:        review.ID,
		Comment:   review.Comment,
		Course:    review.Course,
		CreatedAt: review.CreatedAt,
		IsMine:    review.UserID == currentUserID,
	}
}
