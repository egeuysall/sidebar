package models

import (
	"time"

	"github.com/google/uuid"
)

type CreateUserRequest struct {
	Email          string `json:"email"`
	HashedPassword string `json:"hashed_password"`
}

type UpdateUserRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type UpdateUserEmailRequest struct {
	Email string `json:"email"`
}

type User struct {
	ID        uuid.UUID   `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	FirstName string      `gorm:"" json:"first_name"`
	LastName  string      `gorm:"" json:"last_name"`
	Email     string      `gorm:"unique;not null" json:"email"`
	UpdatedEmail string    `gorm:"" json:"updated_email"`
	CreatedAt time.Time   `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time   `gorm:"autoUpdateTime" json:"updated_at"`
	HashedPassword string `gorm:"" json:"hashed_password"`
	UpdatedEmailAt *time.Time `gorm:"default:null" json:"updated_email_at"`
	UpdatedEmailConfirmedAt *time.Time `gorm:"default:null" json:"updated_email_confirmed_at"`
	EmailConfirmedAt *time.Time `gorm:"default:null" json:"email_confirmed_at"`
	IsAdmin        bool   `gorm:"default:false" json:"is_admin"`
	AvatarUrl      string `gorm:"default:null" json:"avatar_url"`
}

func NewUser(req *CreateUserRequest) *User {
	return &User{
		Email:          req.Email,
		HashedPassword: req.HashedPassword,
	}
}

func ValidateUser(u *User) bool { return true }
