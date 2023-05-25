package repository

import (
	"errors"
	"testing"

	"github.com/Puena/password-keeper/client/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestEncrypDecryptMessage(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	logger, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	cryptoRepo := NewEncriptionRepository(cfg, logger)
	masterPassword := "masterPassword"
	message := "abra kadabra"

	t.Run("encrypt_decrypt_message", func(t *testing.T) {
		salt, _ := cryptoRepo.GenerateSalt()
		lock := cryptoRepo.GenerateLock(salt, masterPassword)
		encrypt, err := cryptoRepo.LockData([]byte(message), lock)
		assert.NoError(t, err, "failed while encrypt message")
		assert.NotNil(t, encrypt, "encrypt message is nil")

		decrypt, err := cryptoRepo.UnlockData(encrypt, lock)
		assert.NoError(t, err, "failed while decrypt message")
		assert.Equal(t, message, string(decrypt), "message and decrypt message are not equal")
	})

	t.Run("encrypt_decrypt_message_with_wrong_password", func(t *testing.T) {
		salt, _ := cryptoRepo.GenerateSalt()
		lock := cryptoRepo.GenerateLock(salt, masterPassword)
		encrypt, err := cryptoRepo.LockData([]byte(message), lock)
		assert.NoError(t, err, "failed while encrypt message")
		assert.NotNil(t, encrypt, "encrypt message is nil")

		decryptLock := cryptoRepo.GenerateLock(salt, "wrongPassword")
		_, err = cryptoRepo.UnlockData(decryptLock, lock)
		assert.Error(t, err, "failed while expecting error while decrypting with wrong password")
	})

	t.Run("encrypt_decrypt_message_with_wrong_salt", func(t *testing.T) {
		salt, _ := cryptoRepo.GenerateSalt()
		lock := cryptoRepo.GenerateLock(salt, masterPassword)
		encrypt, err := cryptoRepo.LockData([]byte(message), lock)
		assert.NoError(t, err, "failed while encrypt message")
		assert.NotNil(t, encrypt, "encrypt message is nil")

		wrongSalt, _ := cryptoRepo.GenerateSalt()
		decryptLock := cryptoRepo.GenerateLock(wrongSalt, masterPassword)
		_, err = cryptoRepo.UnlockData(decryptLock, lock)
		assert.Error(t, err, "failed while expecting error while decrypting with wrong salt")
	})
}

func TestEncryptionErrors(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")
	cryptoRepo := NewEncriptionRepository(cfg, lg)

	t.Run("bad_user_data_error", func(t *testing.T) {
		budErr := ErrBadAuthData
		assert.True(t, cryptoRepo.IsBadUserData(budErr), "failed while expecting bad user data error")
		assert.False(t, cryptoRepo.IsBadUserData(errors.New("some error")), "failed while expecting not bad user data error")
	})

	t.Run("encription_repository_error", func(t *testing.T) {
		nerErr := newEncriptionRepositoryError("some error", errors.New("some error"))
		assert.True(t, cryptoRepo.IsEncryptionRepositoryError(nerErr), "failed while expecting new encription repository error")
		assert.False(t, cryptoRepo.IsEncryptionRepositoryError(errors.New("some error")), "failed while expecting not new encription repository error")
	})

	t.Run("internal_repository_error", func(t *testing.T) {
		nerErr := newEncriptionRepositoryError("some error", errors.New("some error"))
		assert.True(t, cryptoRepo.IsInternalRepositoryError(nerErr), "failed while expecting new encription repository error")
		assert.False(t, cryptoRepo.IsInternalRepositoryError(errors.New("some error")), "failed while expecting not new encription repository error")
		assert.NotEmpty(t, nerErr.Error(), "failed while expecting not empty error")
	})
}
