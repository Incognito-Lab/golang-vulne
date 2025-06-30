package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	Username  string         `json:"username" gorm:"unique;not null"`
	Email     string         `json:"email" gorm:"unique;not null"`
	Password  string         `json:"password" gorm:"not null"`
	Role      string         `json:"role" gorm:"default:'user'"`
	IsActive  bool           `json:"is_active" gorm:"default:true"`
	Balance   float64        `json:"balance" gorm:"default:0"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// Transaction represents a financial transaction
type Transaction struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	UserID      uint      `json:"user_id" gorm:"not null"`
	Amount      float64   `json:"amount" gorm:"not null"`
	Type        string    `json:"type" gorm:"not null"` // deposit, withdraw, transfer
	Description string    `json:"description"`
	ToUserID    *uint     `json:"to_user_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	User        User      `json:"user" gorm:"foreignKey:UserID"`
	ToUser      *User     `json:"to_user,omitempty" gorm:"foreignKey:ToUserID"`
}

// LoginRequest represents login credentials
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RegisterRequest represents registration data
type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

// TransferRequest represents money transfer data
type TransferRequest struct {
	ToUserID uint    `json:"to_user_id" binding:"required"`
	Amount   float64 `json:"amount" binding:"required,gt=0"`
}
