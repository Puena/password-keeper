package models

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// TODO: Logic shoud be in repository!

// defaultSaltCost represents default cost factor for bcrypt hashing.
const defaultSaltCost = 13

// UserModel represents user data.
type UserModel struct {
	Id           uuid.UUID
	Login        string
	PasswordHash string
	CreatedAt    time.Time
}

// ValidatePassword compare user model password hash with password, return error if not equals.
func (u *UserModel) ValidatePassword(password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	if err != nil {
		return newErrUserModelPassword("failed when compare hash and password", err)
	}
	return nil
}

// NewUserModel creates new user by login and password,
// password will be hashed or return error.
func NewUserModel(login string, password string) (*UserModel, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), defaultSaltCost)
	if err != nil {
		return nil, newErrUserModelPassword("failed when generate hash from password", err)
	}

	return &UserModel{
		Id:           uuid.New(),
		Login:        login,
		PasswordHash: string(hash),
		CreatedAt:    time.Now(),
	}, nil
}
