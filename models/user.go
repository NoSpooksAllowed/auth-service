package models

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Username  string    `gorm:"uniqueIndex;not null"                           json:"username"`
	Password  string    `gorm:"not null"                                       json:"-"`
	Email     string    `gorm:"uniqueIndex;not null"                           json:"email"`
	CreatedAt time.Time `                                                      json:"createdAt"`
	UpdatedAt time.Time `                                                      json:"updatedAt"`
}

// BeforeCreate hook to generate UUID and hash password
func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	u.ID = uuid.New()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.Password = string(hashedPassword)

	return nil
}
