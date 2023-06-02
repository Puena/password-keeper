package repository

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/Puena/password-keeper/client/config"
	"go.uber.org/zap"
	"golang.org/x/crypto/pbkdf2"
)

var ErrBadAuthData = errors.New("bad auth data")

type encryptionRepository struct {
	logger *zap.Logger
	config *config.Config
}

// NewEncriptionRepository create repository for encryption operation.
func NewEncriptionRepository(config *config.Config, logger *zap.Logger) *encryptionRepository {
	return &encryptionRepository{
		logger: logger,
		config: config,
	}
}

// GenerateSalt generate 128 byte salt with crypt/rand.
func (r *encryptionRepository) GenerateSalt() ([]byte, error) {
	salt := make([]byte, 128)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, newEncriptionRepositoryError("failed while generate crypto salt", err)
	}
	return salt, nil
}

// GenerateLock generate 32 byte key from salt and password with pbkdf2.
func (r *encryptionRepository) GenerateLock(salt []byte, password string) []byte {
	return pbkdf2.Key([]byte(password), salt, 4096, 32, sha1.New)
}

// LockData encrypt data with aes256.
func (r *encryptionRepository) LockData(data []byte, lock []byte) ([]byte, error) {
	block, err := aes.NewCipher(lock)
	if err != nil {
		return nil, newEncriptionRepositoryError("failed while create cipher for aes encryption", err)
	}

	sum := sha256.Sum256(data)
	out := make([]byte, aes.BlockSize+len(data))
	iv := out[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, newEncriptionRepositoryError("failed while fill data blocks", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(out[aes.BlockSize:], data)

	out = append(out, sum[:]...)

	return out, nil
}

// UnlockData decrypt data with aes256.
func (r *encryptionRepository) UnlockData(data []byte, lock []byte) ([]byte, error) {
	block, err := aes.NewCipher(lock)
	if err != nil {
		return nil, newEncriptionRepositoryError("failed while create cipher for aes decryption", err)
	}

	if len(data) < aes.BlockSize+sha256.Size {
		return nil, newEncriptionRepositoryError("failed while trying to unlock data, wrong block size", err)
	}

	expectedSum := data[len(data)-sha256.Size:]
	data = data[:len(data)-sha256.Size]
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	out := make([]byte, len(data))

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(out, data)

	sum := sha256.Sum256(out)
	if !bytes.Equal(expectedSum, sum[:]) {
		return nil, newEncriptionRepositoryError("failed while comparing sum of files", ErrBadAuthData)
	}

	return out, nil
}

type encryptionRepositoryError struct {
	*baseRepositoryError
}

func (re *encryptionRepositoryError) Error() string {
	return fmt.Sprintf("encryption repository error: %s %s", re.message, re.err)
}

// newEncriptionRepositoryError create encryption repository error.
func newEncriptionRepositoryError(message string, err error) *encryptionRepositoryError {
	return &encryptionRepositoryError{
		newBaseRepositoryError(message, err),
	}
}

// IsBadUserData check if error is bad user data.
func (r *encryptionRepository) IsBadUserData(err error) bool {
	return errors.Is(err, ErrBadAuthData)
}

// IsEncryptionRepositoryError check that is it encryption repository error, then return it or return nil.
func (r *encryptionRepository) IsEncryptionRepositoryError(err error) bool {
	var erferr *encryptionRepositoryError
	return errors.As(err, &erferr)
}

// Useless
func (r *encryptionRepository) IsInternalRepositoryError(err error) bool {
	return r.IsEncryptionRepositoryError(err)
}
