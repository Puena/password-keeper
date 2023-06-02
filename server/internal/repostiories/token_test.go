package repositories

import (
	"context"
	"errors"
	"testing"

	"github.com/Puena/password-keeper/server/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// $go test -v -run "^TestTokenGeneration"
func TestTokenGeneration(t *testing.T) {
	cfg := &config.Config{
		JWTSecretKey: "some-secret-key",
	}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed when init zap logger")

	t.Run("success", func(t *testing.T) {
		tokenRepo := NewTokenRepository(cfg, lg)
		someUserID := uuid.New()

		token, err := tokenRepo.GenerateToken(context.Background(), someUserID)
		assert.NoError(t, err, "failed when generate token")

		id, err := tokenRepo.ValidateToken(context.Background(), token)
		assert.NoError(t, err, "failed when validate token")
		assert.Equal(t, someUserID, *id, "failed not equal id")
	})

	t.Run("validation_fail_without_userID", func(t *testing.T) {
		tokenRepo := NewTokenRepository(cfg, lg)

		token := jwt.New(defaultJWTSignedMethod)
		signedToken, err := token.SignedString(prepareJWT256Key(cfg.JWTSecretKey))
		require.NoError(t, err, "failed when signed token")

		_, err = tokenRepo.ValidateToken(context.Background(), signedToken)
		assert.Error(t, err, "failed we are expect error")
		assert.NotNil(t, tokenRepo.RepositoryError(err), "failed when expecting token repository error")
	})
}

func Test_tokenRepository_Errors(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	t.Run("reposiotory_error", func(t *testing.T) {
		require.NoError(t, err, "failed while initializing pgxmock")
		tokenRepo := NewTokenRepository(cfg, lg)

		cErr := newErrTokenRepository("some error", errors.New("some error"))
		statusErr := tokenRepo.RepositoryError(cErr)
		assert.Error(t, statusErr, "failed while waiting repository error, got nil instead")
		assert.NotEmpty(t, statusErr.Error(), "failed while waiting repository error, got nil instead")

		sErr := errors.New("some error")
		statusErr = tokenRepo.RepositoryError(sErr)
		assert.NoError(t, statusErr, "failed while waiting repository error, got %v instead", statusErr)
	})
}
