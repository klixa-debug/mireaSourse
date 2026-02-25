package model

type SignInResponse struct {
	Token string        `json:"token"`
	User  *UserResponse `json:"user"`
}
