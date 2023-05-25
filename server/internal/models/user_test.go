package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// $go test -v -run "^TestNewUserModel"
func TestNewUserModel(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		login := "mail@mail.ru"
		password := "asdf82asdf2"

		newUser, err := NewUserModel(login, password)
		assert.NoError(t, err, "not expected error while creating new user model")
		assert.NotNil(t, newUser, "not expected nil while creating new user model")

		err = newUser.ValidatePassword(password)
		assert.NoError(t, err, "not expected error while validating password")
	})

	t.Run("passoword_validating_fail", func(t *testing.T) {
		login := "mail@mail.ru"
		password := "asdf82asdf2"
		anotherPassword := "adfanadnj2222"

		newUser, err := NewUserModel(login, password)
		assert.NoError(t, err, "not expected error while creating new user model")
		assert.NotNil(t, newUser, "not expected nil while creating new user model")

		err = newUser.ValidatePassword(anotherPassword)
		assert.Error(t, err, "expecting error while validating with wrong password")

		var ErrUserPassword *ErrUserModelPassword
		assert.ErrorAs(t, err, &ErrUserPassword, "expecting right error type")
		assert.NotEmpty(t, ErrUserPassword.Error(), "not expected empty error message")
		assert.NotNil(t, ErrUserPassword.Unwrap(), "not expecting nil while unwrap")
	})
}
