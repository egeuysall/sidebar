package models

type AuthToken struct {
	HashedToken string `json:"hashed_token"`
	Exp   int64  `json:"exp"`
	Type  string `json:"type"`
}

type SignupRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type ConfirmEmailTokenRequest struct {
	Token string `json:"token"`
}
