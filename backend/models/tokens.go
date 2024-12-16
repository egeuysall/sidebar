package models

import (
	"time"

	"github.com/google/uuid"
)

type ApiToken struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	HashedToken string    `gorm:"" json:"hashed_token"`
	UserID      uuid.UUID `gorm:"" json:"user_id"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime" json:"updated_at"`
	Name        string    `gorm:"" json:"name"`
}
