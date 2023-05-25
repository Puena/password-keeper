package repositories

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/Puena/password-keeper/server/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// default values for jwt repository.
var (
	defaultJWTSignedMethod = jwt.SigningMethodHS256
	defaultJWTExpiredTime  = 2 * time.Hour
)

// claims represent jwt claims.
type claims struct {
	UserID *uuid.UUID `json:"user_id"`
	jwt.RegisteredClaims
}

// tokenRepository represent token methods.
type tokenRepository struct {
	repository
	jwtKey256 []byte
}

// NewTokenRepository create token repository.
func NewTokenRepository(config *config.Config, logger *zap.Logger) *tokenRepository {
	return &tokenRepository{
		repository: newRepository(config, logger),
		jwtKey256:  prepareJWT256Key(config.JWTSecretKey),
	}
}

// GenerateToken handle token generation, returns jwt token or error.
func (r *tokenRepository) GenerateToken(ctx context.Context, userID uuid.UUID) (string, error) {
	claims := &claims{
		UserID: &userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(defaultJWTExpiredTime)),
		},
	}
	token := jwt.NewWithClaims(defaultJWTSignedMethod, claims)

	signedToken, err := token.SignedString(r.jwtKey256)
	if err != nil {
		return "", newErrTokenRepository("failed when signed token", err)
	}

	return signedToken, nil
}

// ValidateToken handle token validation, return userID or error.
func (r *tokenRepository) ValidateToken(ctx context.Context, token string) (*uuid.UUID, error) {
	claims := &claims{}
	tn, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		return r.jwtKey256, nil
	})
	if err != nil {
		return nil, newErrTokenRepository("failed when parse token", err)
	}
	if !tn.Valid || claims.UserID == nil {
		return nil, newErrTokenRepository("token not valid", err)
	}

	return claims.UserID, nil
}

// prepareJWT256Key represent jwt key from config as 256 bit string.
func prepareJWT256Key(key string) []byte {
	hash := sha256.New()
	hash.Write([]byte(key))
	return hash.Sum(nil)
}
