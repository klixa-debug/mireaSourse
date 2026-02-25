package converter

import (
	"mirea-qr/internal/entity"
	"mirea-qr/internal/model"
)

func UserToResponse(user *entity.User) *model.UserResponse {
	return &model.UserResponse{
		ID:            user.ID,
		TelegramID:    user.TelegramId,
		Email:         user.Email,
		Fullname:      user.Fullname,
		Group:         user.Group,
		CustomProxy:   user.CustomProxy,
		HasTotpSecret: user.TotpSecret != "",
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
	}
}

func AnotherStudentToResponse(user *entity.User) model.AnotherStudentResponse {
	return model.AnotherStudentResponse{
		Email:    user.Email,
		Fullname: user.Fullname,
		Group:    user.Group,
	}
}

func LinkUserToResponse(user *entity.LinkUser) model.ConnectedStudentResponse {
	return model.ConnectedStudentResponse{
		Email:    user.ToUser.Email,
		Fullname: user.ToUser.Fullname,
		Group:    user.ToUser.Group,
		Enabled:  user.Enabled,
	}
}

func LinkUserToResponseReverse(user *entity.LinkUser) model.ConnectedStudentResponse {
	return model.ConnectedStudentResponse{
		Email:    user.FromUser.Email,
		Fullname: user.FromUser.Fullname,
		Group:    user.FromUser.Group,
		Enabled:  user.Enabled,
	}
}
