package usecases

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Puena/password-keeper/server/config"
	"github.com/Puena/password-keeper/server/internal/dto"
	"github.com/Puena/password-keeper/server/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	mock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type repositoryMock struct {
	user    *MockUsersRepository
	token   *MockTokenRepository
	chests  *MockChestRepository
	history *MockHistoryRepository
}

func (r *repositoryMock) Users() UsersRepository {
	return r.user
}

func (r *repositoryMock) Token() TokenRepository {
	return r.token
}

func (r *repositoryMock) Chests() ChestRepository {
	return r.chests
}

func (r *repositoryMock) History() HistoryRepository {
	return r.history
}

func newMock(t *testing.T) *repositoryMock {
	user := NewMockUsersRepository(t)
	token := NewMockTokenRepository(t)
	history := NewMockHistoryRepository(t)
	chests := NewMockChestRepository(t)
	return &repositoryMock{
		user:    user,
		token:   token,
		history: history,
		chests:  chests,
	}
}

func TestSignUp(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")
	someAuthData := &dto.AuthDataDto{
		Login:    "some@mail.ru",
		Password: "some-password",
	}
	someUser := &models.UserModel{
		Id:           uuid.New(),
		Login:        someAuthData.Login,
		PasswordHash: someAuthData.Password,
		CreatedAt:    time.Now(),
	}
	type testArgs struct {
		data      *dto.AuthDataDto
		userModel *models.UserModel
	}

	type testExpected struct {
		token           string
		userModelError  error
		validationError error
		selectUserError error
		insertUserError error
		tokenError      error
	}

	data := []struct {
		name     string
		args     testArgs
		expected testExpected
	}{
		{
			name: "success",
			args: testArgs{
				data:      someAuthData,
				userModel: someUser,
			},
			expected: testExpected{
				token:           uuid.NewString(),
				userModelError:  nil,
				validationError: nil,
				selectUserError: errors.New("not found"),
				insertUserError: nil,
				tokenError:      nil,
			},
		},
		{
			name: "bad_login_validation_erro",
			args: testArgs{
				data: &dto.AuthDataDto{
					Login:    "some",
					Password: "very-strong-password",
				},
				userModel: someUser,
			},
			expected: testExpected{
				token:           "",
				userModelError:  nil,
				validationError: errors.New("login must be a valid email"),
				selectUserError: errors.New("not found"),
				insertUserError: nil,
				tokenError:      nil,
			},
		},
		{
			name: "bad_password_small_validation_erro",
			args: testArgs{
				data: &dto.AuthDataDto{
					Login:    "some@mail.ru",
					Password: "ver",
				},
				userModel: someUser,
			},
			expected: testExpected{
				token:           "",
				userModelError:  nil,
				validationError: errors.New("password must be at least 8 characters long"),
				selectUserError: errors.New("not found"),
				insertUserError: nil,
				tokenError:      nil,
			},
		},
		{
			name: "bad_password_large_validation_error",
			args: testArgs{
				data: &dto.AuthDataDto{
					Login:    "some@mail.ru",
					Password: strings.Repeat("a", 25),
				},
				userModel: someUser,
			},
			expected: testExpected{
				token:           "",
				userModelError:  nil,
				validationError: errors.New("password must be at most 24 characters long"),
				selectUserError: errors.New("not found"),
				insertUserError: nil,
				tokenError:      nil,
			},
		},
		{
			name: "user_already_exists_error",
			args: testArgs{
				data: &dto.AuthDataDto{
					Login:    "some@mail.ru",
					Password: "very-strong-password",
				},
				userModel: someUser,
			},
			expected: testExpected{
				token:           "",
				userModelError:  nil,
				validationError: nil,
				selectUserError: nil,
				insertUserError: nil,
				tokenError:      nil,
			},
		},
		{
			name: "conflict_when_insert_user_error",
			args: testArgs{
				data: &dto.AuthDataDto{
					Login:    "some@mail.ru",
					Password: "very-strong-password",
				},
				userModel: someUser,
			},
			expected: testExpected{
				token:           "",
				userModelError:  nil,
				validationError: nil,
				selectUserError: errors.New("not found"),
				insertUserError: errors.New("conflict"),
				tokenError:      nil,
			},
		},
		{
			name: "internal_when_insert_user_error",
			args: testArgs{
				data: &dto.AuthDataDto{
					Login:    "some@mail.ru",
					Password: "very-strong-password",
				},
				userModel: someUser,
			},
			expected: testExpected{
				token:           "",
				userModelError:  nil,
				validationError: nil,
				selectUserError: errors.New("not found"),
				insertUserError: errors.New("internal"),
				tokenError:      nil,
			},
		},
		{
			name: "internal_when_generate_token_error",
			args: testArgs{
				data: &dto.AuthDataDto{
					Login:    "some@mail.ru",
					Password: "very-strong-password",
				},
				userModel: someUser,
			},
			expected: testExpected{
				token:           "",
				userModelError:  nil,
				validationError: nil,
				selectUserError: errors.New("not found"),
				insertUserError: nil,
				tokenError:      errors.New("internal"),
			},
		},
	}

	for _, test := range data {
		t.Run(test.name, func(t *testing.T) {
			mocks := newMock(t)
			userRepo := mocks.Users().(*MockUsersRepository)
			tokenRepo := mocks.Token().(*MockTokenRepository)
			usecase := New(mocks, cfg, lg)

			// mock methods
			if test.expected.userModelError == nil && test.expected.validationError == nil {
				userRepo.EXPECT().SelectUserByLogin(mock.Anything, test.args.data.Login).Return(test.args.userModel, test.expected.selectUserError)
			}

			if test.expected.userModelError == nil && test.expected.validationError == nil && test.expected.selectUserError != nil {
				userRepo.EXPECT().InsertUser(mock.Anything, mock.AnythingOfType("*models.UserModel")).Return(&test.args.userModel.Id, test.expected.insertUserError)
			}

			if test.expected.userModelError == nil && test.expected.validationError == nil && test.expected.selectUserError != nil && test.expected.insertUserError == nil {
				tokenRepo.EXPECT().GenerateToken(mock.Anything, test.args.userModel.Id).Return(test.expected.token, test.expected.tokenError)
			}

			// mock errors
			if test.expected.selectUserError != nil &&
				test.expected.validationError == nil &&
				test.expected.userModelError == nil {
				if test.expected.selectUserError.Error() == "not found" {
					userRepo.EXPECT().NotFoundError(test.expected.selectUserError).Return(test.expected.selectUserError)
				} else {
					userRepo.EXPECT().NotFoundError(test.expected.selectUserError).Return(nil)
				}
			}

			if test.expected.insertUserError != nil &&
				test.expected.validationError == nil &&
				test.expected.userModelError == nil {
				if test.expected.insertUserError.Error() == "conflict" {
					userRepo.EXPECT().ConflictError(test.expected.insertUserError).Return(test.expected.insertUserError)
				} else {
					userRepo.EXPECT().ConflictError(test.expected.insertUserError).Return(nil)
				}
			}

			// call
			token, err := usecase.SignUp(context.Background(), *test.args.data)
			if test.expected.userModelError != nil ||
				test.expected.validationError != nil ||
				test.expected.selectUserError == nil ||
				test.expected.insertUserError != nil ||
				test.expected.tokenError != nil {
				assert.Error(t, err, "expected error but got nil")
				return
			}

			assert.NoError(t, err, "expected no error but got %v", err)
			assert.NotEmpty(t, token, "expected token but got empty string")
		})
	}
}

func TestSignIn(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")
	someAuthData := &dto.AuthDataDto{
		Login:    "some@mail.ru",
		Password: "some-password",
	}
	someUser, err := models.NewUserModel(someAuthData.Login, someAuthData.Password)
	require.NoError(t, err, "failed while creating user model")
	type testArgs struct {
		data      *dto.AuthDataDto
		userModel *models.UserModel
	}

	type testExpected struct {
		token                   string
		validationError         error
		selectUserError         error
		passwordValidationError error
		tokenError              error
	}

	data := []struct {
		name     string
		args     testArgs
		expected testExpected
	}{
		{
			name: "success",
			args: testArgs{
				data:      someAuthData,
				userModel: someUser,
			},
			expected: testExpected{
				token:                   uuid.NewString(),
				validationError:         nil,
				selectUserError:         nil,
				passwordValidationError: nil,
				tokenError:              nil,
			},
		},
		{
			name: "bad_login_validation_erro",
			args: testArgs{
				data: &dto.AuthDataDto{
					Login:    "some",
					Password: "very-strong-password",
				},
				userModel: someUser,
			},
			expected: testExpected{
				token:                   "",
				validationError:         errors.New("login must be a valid email"),
				selectUserError:         nil,
				passwordValidationError: nil,
				tokenError:              nil,
			},
		},
		{
			name: "bad_password_small_validation_erro",
			args: testArgs{
				data: &dto.AuthDataDto{
					Login:    "some@mail.ru",
					Password: "ver",
				},
				userModel: someUser,
			},
			expected: testExpected{
				token:                   "",
				validationError:         errors.New("password must be at least 8 characters long"),
				selectUserError:         nil,
				passwordValidationError: nil,
				tokenError:              nil,
			},
		},
		{
			name: "bad_password_large_validation_error",
			args: testArgs{
				data: &dto.AuthDataDto{
					Login:    "some@mail.ru",
					Password: strings.Repeat("a", 25),
				},
				userModel: someUser,
			},
			expected: testExpected{
				token:                   "",
				validationError:         errors.New("password must be at most 24 characters long"),
				selectUserError:         nil,
				passwordValidationError: nil,
				tokenError:              nil,
			},
		},
		{
			name: "bad_password_validation_error",
			args: testArgs{
				data: &dto.AuthDataDto{
					Login:    "some@mail.ru",
					Password: "not-user-password",
				},
				userModel: someUser,
			},
			expected: testExpected{
				token:                   "",
				validationError:         nil,
				selectUserError:         nil,
				passwordValidationError: errors.New("password is incorrect"),
				tokenError:              nil,
			},
		},
		{
			name: "not_found_user_error",
			args: testArgs{
				data: &dto.AuthDataDto{
					Login:    "some@mail.ru",
					Password: "very-strong-password",
				},
				userModel: someUser,
			},
			expected: testExpected{
				token:                   "",
				validationError:         nil,
				selectUserError:         errors.New("not found"),
				passwordValidationError: nil,
				tokenError:              nil,
			},
		},
		{
			name: "internal_user_error",
			args: testArgs{
				data: &dto.AuthDataDto{
					Login:    "some@mail.ru",
					Password: "very-strong-password",
				},
				userModel: someUser,
			},
			expected: testExpected{
				token:                   "",
				validationError:         nil,
				selectUserError:         errors.New("internal"),
				passwordValidationError: nil,
				tokenError:              nil,
			},
		},
		{
			name: "internal_when_generate_token_error",
			args: testArgs{
				data:      someAuthData,
				userModel: someUser,
			},
			expected: testExpected{
				token:                   "",
				validationError:         nil,
				selectUserError:         nil,
				passwordValidationError: nil,
				tokenError:              errors.New("internal"),
			},
		},
	}

	for _, test := range data {
		t.Run(test.name, func(t *testing.T) {
			mocks := newMock(t)
			userRepo := mocks.Users().(*MockUsersRepository)
			tokenRepo := mocks.Token().(*MockTokenRepository)
			usecase := New(mocks, cfg, lg)

			// mock methods
			if test.expected.validationError == nil {
				userRepo.EXPECT().SelectUserByLogin(context.Background(), test.args.data.Login).Return(test.args.userModel, test.expected.selectUserError)
			}

			if test.expected.validationError == nil && test.expected.selectUserError != nil {
				if test.expected.selectUserError.Error() == "not found" {
					userRepo.EXPECT().NotFoundError(test.expected.selectUserError).Return(test.expected.selectUserError)
				} else {
					userRepo.EXPECT().NotFoundError(test.expected.selectUserError).Return(nil)
				}
			}

			if test.expected.validationError == nil && test.expected.selectUserError == nil && test.expected.passwordValidationError == nil {
				tokenRepo.EXPECT().GenerateToken(mock.Anything, test.args.userModel.Id).Return(test.expected.token, test.expected.tokenError)
			}

			// call
			token, err := usecase.SignIn(context.Background(), *test.args.data)
			if test.expected.validationError != nil ||
				test.expected.selectUserError != nil ||
				test.expected.passwordValidationError != nil ||
				test.expected.tokenError != nil {
				assert.Error(t, err, "expected error but got nil")
				return
			}

			assert.NoError(t, err, "expected no error but got %v", err)
			assert.NotEmpty(t, token, "expected token but got empty string")
		})
	}
}

func TestAuth(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")
	someUserID := uuid.New()

	t.Run("success", func(t *testing.T) {

		mocks := newMock(t)
		tokenRepo := mocks.Token().(*MockTokenRepository)
		usecase := New(mocks, cfg, lg)

		tokenRepo.EXPECT().ValidateToken(mock.Anything, mock.Anything).Return(&someUserID, nil)

		res, err := usecase.Auth(context.Background(), "some-token")
		assert.NoError(t, err, "expected no error but got %v", err)
		assert.NotNil(t, res, "expected user id but got nil")
	})

	t.Run("token validation error", func(t *testing.T) {
		mocks := newMock(t)
		tokenRepo := mocks.Token().(*MockTokenRepository)
		usecase := New(mocks, cfg, lg)

		tokenRepo.EXPECT().ValidateToken(mock.Anything, mock.Anything).Return(nil, errors.New("some error"))

		res, err := usecase.Auth(context.Background(), "some-token")
		assert.Error(t, err, "expected error but got nil")
		assert.Nil(t, res, "expected nil but got %v", res)
	})
}

func TestGetChestByID(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")
	someUserID := uuid.New()
	someChestID := uuid.New()

	someChest := &models.Chest{
		ID:       someChestID.String(),
		UserID:   someUserID,
		Salt:     sha256.New().Sum([]byte("some-salt")),
		Name:     "some-name",
		Data:     sha256.New().Sum([]byte("some-data")),
		DataType: 1,
	}

	someHistory := &models.History{
		ID:            uuid.NewString(),
		UserID:        someUserID,
		ChestID:       someChestID.String(),
		OperationType: 0,
		OperationTime: time.Now(),
		SyncingTime:   time.Now(),
		DeviceName:    "android",
		DeviceIP:      "10.0.0.1",
	}

	type testArgs struct {
		userID  uuid.UUID
		chestID uuid.UUID
	}

	type testExpected struct {
		repositoryError error
		chestModel      *models.Chest
		historyModel    *models.History
	}

	type testData struct {
		name     string
		args     testArgs
		expected testExpected
	}

	data := []testData{
		{
			name: "success",
			args: testArgs{
				userID:  someUserID,
				chestID: someChestID,
			},
			expected: testExpected{
				repositoryError: nil,
				chestModel:      someChest,
				historyModel:    someHistory,
			},
		},
		{
			name: "chest_not_found_error",
			args: testArgs{
				userID:  someUserID,
				chestID: someChestID,
			},
			expected: testExpected{
				repositoryError: errors.New("not found"),
				chestModel:      someChest,
				historyModel:    someHistory,
			},
		},
		{
			name: "internal_repository_error",
			args: testArgs{
				userID:  someUserID,
				chestID: someChestID,
			},
			expected: testExpected{
				repositoryError: errors.New("some error"),
				chestModel:      someChest,
				historyModel:    someHistory,
			},
		}}

	for _, test := range data {
		t.Run(test.name, func(t *testing.T) {
			mocks := newMock(t)
			chestRepo := mocks.Chests().(*MockChestRepository)
			usecase := New(mocks, cfg, lg)

			// mock methods
			chestRepo.EXPECT().SelectChestByID(context.Background(), test.args.chestID.String(), test.args.userID).Return(test.expected.chestModel, test.expected.historyModel, test.expected.repositoryError)

			if test.expected.repositoryError != nil {
				if test.expected.repositoryError.Error() == "not found" {
					chestRepo.EXPECT().NotFoundError(test.expected.repositoryError).Return(test.expected.repositoryError)
				} else {
					chestRepo.EXPECT().NotFoundError(test.expected.repositoryError).Return(nil)
				}
			}

			// call
			chest, history, err := usecase.GetChestByID(context.Background(), test.args.chestID.String(), test.args.userID)
			if test.expected.repositoryError != nil {
				assert.Error(t, err, "expected error but got nil")
				return
			}
			assert.NoError(t, err, "expected no error but got %v", err)
			assert.NotNil(t, chest, "expected chest but got nil")
			assert.NotNil(t, history, "expected history but got nil")
		})
	}
}

func TestAddChest(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")
	someUserID := uuid.New()
	someChestID := uuid.New()

	someChestDto := &dto.Chest{
		ID:       someChestID.String(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("some-salt")),
		Name:     "some-name",
		Data:     sha256.New().Sum([]byte("some-data")),
		DataType: 1,
	}

	someHistoryDto := &dto.History{
		ID:            uuid.NewString(),
		UserID:        someUserID,
		ChestID:       someChestID.String(),
		OperationType: 0,
		OperationTime: time.Now(),
		SyncingTime:   nil,
		DeviceName:    "android",
		DeviceIP:      "10.0.0.1",
	}

	someChestModel := &models.Chest{
		ID:       someChestDto.ID,
		UserID:   someUserID,
		Salt:     someChestDto.Salt,
		Name:     someChestDto.Name,
		Data:     someChestDto.Data,
		DataType: someChestDto.DataType,
	}

	someHistoryModel := &models.History{
		ID:            someHistoryDto.ID,
		UserID:        someUserID,
		ChestID:       someChestModel.ID,
		OperationType: 0,
		OperationTime: someHistoryDto.OperationTime,
		SyncingTime:   time.Now(),
		DeviceName:    someHistoryDto.DeviceName,
		DeviceIP:      someHistoryDto.DeviceIP,
	}

	type testArgs struct {
		chestDto   *dto.Chest
		historyDto *dto.History
	}

	type testExpected struct {
		validationError error
		repositoryError error
		chestModel      *models.Chest
		historyModel    *models.History
	}

	type testData struct {
		name     string
		args     testArgs
		expected testExpected
	}

	data := []testData{
		{
			name: "success",
			args: testArgs{
				chestDto:   someChestDto,
				historyDto: someHistoryDto,
			},
			expected: testExpected{
				chestModel:      someChestModel,
				historyModel:    someHistoryModel,
				validationError: nil,
				repositoryError: nil,
			},
		},
		{
			name: "chest_validation_error",
			args: testArgs{
				chestDto: &dto.Chest{
					ID:       uuid.NewString(),
					UserID:   nil,
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-name",
					Data:     sha256.New().Sum([]byte("some-data")),
					DataType: -2, // validation error
				},
				historyDto: someHistoryDto,
			},
			expected: testExpected{
				validationError: errors.New("some error"),
				repositoryError: nil,
				chestModel:      someChestModel,
				historyModel:    someHistoryModel,
			},
		},
		{
			name: "history_validation_error",
			args: testArgs{
				chestDto: someChestDto,
				historyDto: &dto.History{
					ID:            uuid.NewString(),
					UserID:        someUserID,
					ChestID:       someChestDto.ID,
					OperationType: -1, // validation error
					OperationTime: time.Now(),
					SyncingTime:   nil,
					DeviceName:    "",
					DeviceIP:      "",
				},
			},
			expected: testExpected{
				validationError: errors.New("some error"),
				repositoryError: nil,
				chestModel:      someChestModel,
				historyModel:    someHistoryModel,
			},
		},
		{
			name: "conflict_error",
			args: testArgs{
				chestDto:   someChestDto,
				historyDto: someHistoryDto,
			},
			expected: testExpected{
				chestModel:      someChestModel,
				historyModel:    someHistoryModel,
				validationError: nil,
				repositoryError: errors.New("conflict"),
			},
		},
		{
			name: "internal_error",
			args: testArgs{
				chestDto:   someChestDto,
				historyDto: someHistoryDto,
			},
			expected: testExpected{
				chestModel:      someChestModel,
				historyModel:    someHistoryModel,
				validationError: nil,
				repositoryError: errors.New("internal"),
			},
		},
	}

	for _, test := range data {
		t.Run(test.name, func(t *testing.T) {
			mocks := newMock(t)
			chestRepo := mocks.Chests().(*MockChestRepository)
			usecase := New(mocks, cfg, lg)

			// mock methods
			if test.expected.validationError == nil {
				chestRepo.EXPECT().UpsertChest(mock.Anything, mock.AnythingOfType("*models.Chest"), mock.AnythingOfType("*models.History")).Return(test.expected.repositoryError)
			}

			if test.expected.repositoryError != nil && test.expected.validationError == nil {
				if test.expected.repositoryError.Error() == "conflict" {
					chestRepo.EXPECT().ConflictError(test.expected.repositoryError).Return(test.expected.repositoryError)
				} else {
					chestRepo.EXPECT().ConflictError(test.expected.repositoryError).Return(nil)
				}
			}

			// call
			history, err := usecase.AddChest(context.Background(), test.args.chestDto, test.args.historyDto)
			if test.expected.repositoryError != nil || test.expected.validationError != nil {
				assert.Error(t, err, "expected error but got nil")
				return
			}
			assert.NoError(t, err, "expected no error but got %v", err)
			assert.NotNil(t, history, "expected history but got nil")
		})
	}
}

func TestUpdateChest(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")
	someUserID := uuid.New()
	someChestID := uuid.New()

	someChestDto := &dto.Chest{
		ID:       someChestID.String(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("some-salt")),
		Name:     "some-name",
		Data:     sha256.New().Sum([]byte("some-data")),
		DataType: 1,
	}

	someHistoryDto := &dto.History{
		ID:            uuid.NewString(),
		UserID:        someUserID,
		ChestID:       someChestID.String(),
		OperationType: 0,
		OperationTime: time.Now(),
		SyncingTime:   nil,
		DeviceName:    "android",
		DeviceIP:      "10.0.0.1",
	}

	someChestModel := &models.Chest{
		ID:       someChestDto.ID,
		UserID:   someUserID,
		Salt:     someChestDto.Salt,
		Name:     someChestDto.Name,
		Data:     someChestDto.Data,
		DataType: someChestDto.DataType,
	}

	someHistoryModel := &models.History{
		ID:            someHistoryDto.ID,
		UserID:        someUserID,
		ChestID:       someChestModel.ID,
		OperationType: 0,
		OperationTime: someHistoryDto.OperationTime,
		SyncingTime:   time.Now(),
		DeviceName:    someHistoryDto.DeviceName,
		DeviceIP:      someHistoryDto.DeviceIP,
	}

	type testArgs struct {
		chestDto   *dto.Chest
		historyDto *dto.History
	}

	type testExpected struct {
		validationError error
		repositoryError error
		chestModel      *models.Chest
		historyModel    *models.History
	}

	type testData struct {
		name     string
		args     testArgs
		expected testExpected
	}

	data := []testData{
		{
			name: "success",
			args: testArgs{
				chestDto:   someChestDto,
				historyDto: someHistoryDto,
			},
			expected: testExpected{
				chestModel:      someChestModel,
				historyModel:    someHistoryModel,
				validationError: nil,
				repositoryError: nil,
			},
		},
		{
			name: "chest_validation_error",
			args: testArgs{
				chestDto: &dto.Chest{
					ID:       uuid.NewString(),
					UserID:   nil,
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-name",
					Data:     sha256.New().Sum([]byte("some-data")),
					DataType: -2, // validation error
				},
				historyDto: someHistoryDto,
			},
			expected: testExpected{
				validationError: errors.New("some error"),
				repositoryError: nil,
				chestModel:      someChestModel,
				historyModel:    someHistoryModel,
			},
		},
		{
			name: "history_validation_error",
			args: testArgs{
				chestDto: someChestDto,
				historyDto: &dto.History{
					ID:            uuid.NewString(),
					UserID:        someUserID,
					ChestID:       someChestDto.ID,
					OperationType: -1, // validation error
					OperationTime: time.Now(),
					SyncingTime:   nil,
					DeviceName:    "",
					DeviceIP:      "",
				},
			},
			expected: testExpected{
				validationError: errors.New("some error"),
				repositoryError: nil,
				chestModel:      someChestModel,
				historyModel:    someHistoryModel,
			},
		},
		{
			name: "conflict_error",
			args: testArgs{
				chestDto:   someChestDto,
				historyDto: someHistoryDto,
			},
			expected: testExpected{
				chestModel:      someChestModel,
				historyModel:    someHistoryModel,
				validationError: nil,
				repositoryError: errors.New("conflict"),
			},
		},
		{
			name: "internal_error",
			args: testArgs{
				chestDto:   someChestDto,
				historyDto: someHistoryDto,
			},
			expected: testExpected{
				chestModel:      someChestModel,
				historyModel:    someHistoryModel,
				validationError: nil,
				repositoryError: errors.New("internal"),
			},
		},
	}

	for _, test := range data {
		t.Run(test.name, func(t *testing.T) {
			mocks := newMock(t)
			chestRepo := mocks.Chests().(*MockChestRepository)
			usecase := New(mocks, cfg, lg)

			// mock methods
			if test.expected.validationError == nil {
				chestRepo.EXPECT().UpsertChest(mock.Anything, mock.AnythingOfType("*models.Chest"), mock.AnythingOfType("*models.History")).Return(test.expected.repositoryError)
			}

			// call
			history, err := usecase.UpsertChest(context.Background(), test.args.chestDto, test.args.historyDto)
			if test.expected.repositoryError != nil || test.expected.validationError != nil {
				assert.Error(t, err, "expected error but got nil")
				return
			}
			assert.NoError(t, err, "expected no error but got %v", err)
			assert.NotNil(t, history, "expected history but got nil")
		})
	}
}

func TestDeleteChest(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")
	someUserID := uuid.New()
	someChestID := uuid.New()

	someHistoryDto := &dto.History{
		ID:            uuid.NewString(),
		UserID:        someUserID,
		ChestID:       someChestID.String(),
		OperationType: 2,
		OperationTime: time.Now(),
		SyncingTime:   nil,
		DeviceName:    "android",
		DeviceIP:      "10.0.0.1",
	}

	someHistoryModel := &models.History{
		ID:            someHistoryDto.ID,
		UserID:        someUserID,
		ChestID:       someChestID.String(),
		OperationType: 2,
		OperationTime: someHistoryDto.OperationTime,
		SyncingTime:   time.Now(),
		DeviceName:    someHistoryDto.DeviceName,
		DeviceIP:      someHistoryDto.DeviceIP,
	}

	type testArgs struct {
		historyDto *dto.History
	}

	type testExpected struct {
		validationError error
		repositoryError error
		historyModel    *models.History
	}

	type testData struct {
		name     string
		args     testArgs
		expected testExpected
	}

	data := []testData{
		{
			name: "success",
			args: testArgs{
				historyDto: someHistoryDto,
			},
			expected: testExpected{
				historyModel:    someHistoryModel,
				validationError: nil,
				repositoryError: nil,
			},
		},
		{
			name: "history_validation_error",
			args: testArgs{
				historyDto: &dto.History{
					ID:            uuid.NewString(),
					UserID:        someUserID,
					ChestID:       someChestID.String(),
					OperationType: -1, // validation error
					OperationTime: time.Now(),
					SyncingTime:   nil,
					DeviceName:    "",
					DeviceIP:      "",
				},
			},
			expected: testExpected{
				validationError: errors.New("some error"),
				repositoryError: nil,
				historyModel:    someHistoryModel,
			},
		},
		{
			name: "internal_error",
			args: testArgs{
				historyDto: someHistoryDto,
			},
			expected: testExpected{
				historyModel:    someHistoryModel,
				validationError: nil,
				repositoryError: errors.New("internal"),
			},
		},
	}

	for _, test := range data {
		t.Run(test.name, func(t *testing.T) {
			mocks := newMock(t)
			chestRepo := mocks.Chests().(*MockChestRepository)
			usecase := New(mocks, cfg, lg)

			// mock methods
			if test.expected.validationError == nil {
				chestRepo.EXPECT().DeleteChest(mock.Anything, mock.AnythingOfType("*models.History")).Return(test.expected.repositoryError)
			}

			// call
			history, err := usecase.DeleteChest(context.Background(), test.args.historyDto)
			if test.expected.repositoryError != nil || test.expected.validationError != nil {
				assert.Error(t, err, "expected error but got nil")
				return
			}
			assert.NoError(t, err, "expected no error but got %v", err)
			assert.NotNil(t, history, "expected history but got nil")
		})
	}
}

func TestSync(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")
	someUserID := uuid.New()
	historyDto := []*dto.History{
		{ // 0 not syncronized
			ID:            uuid.NewString(),
			UserID:        someUserID,
			ChestID:       uuid.NewString(),
			OperationType: 0,
			OperationTime: time.Now(),
			SyncingTime:   nil,
			DeviceName:    "android",
			DeviceIP:      "10.0.0.1",
		},
		{ // 1 same as server
			ID:            uuid.NewString(),
			UserID:        someUserID,
			ChestID:       uuid.NewString(),
			OperationType: 2,
			OperationTime: time.Now().Add(-2 * time.Hour),
			SyncingTime:   func() *time.Time { t := time.Now().Add(-1 * time.Hour); return &t }(),
			DeviceName:    "android",
			DeviceIP:      "10.0.0.1",
		},
		{ // 2 local version newer than server
			ID:            uuid.NewString(),
			UserID:        someUserID,
			ChestID:       uuid.NewString(),
			OperationType: 2,
			OperationTime: time.Now().Add(-2 * time.Hour),
			SyncingTime:   func() *time.Time { t := time.Now().Add(-1 * time.Hour); return &t }(),
			DeviceName:    "android",
			DeviceIP:      "10.0.0.1",
		},
		{ // 3 local older than server
			ID:            uuid.NewString(),
			UserID:        someUserID,
			ChestID:       uuid.NewString(),
			OperationType: 2,
			OperationTime: time.Now().Add(-2 * time.Hour),
			SyncingTime:   func() *time.Time { t := time.Now().Add(-3 * time.Hour); return &t }(),
			DeviceName:    "android",
			DeviceIP:      "10.0.0.1",
		},
	}

	historyModels := []*models.History{
		// dont have 0 history because it not synchronized.
		{ // 1 history same as synchronized version.
			ID:            historyDto[1].ID,
			UserID:        someUserID,
			ChestID:       historyDto[1].ChestID,
			OperationType: historyDto[1].OperationType,
			OperationTime: historyDto[1].OperationTime,
			SyncingTime:   *historyDto[1].SyncingTime,
			DeviceName:    historyDto[1].DeviceName,
			DeviceIP:      historyDto[1].DeviceIP,
		},
		{ // 2 history syncronized version older than user one.
			ID:            historyDto[2].ID,
			UserID:        someUserID,
			ChestID:       historyDto[2].ChestID,
			OperationType: historyDto[2].OperationType,
			OperationTime: historyDto[2].OperationTime.Add(-1 * time.Hour),
			SyncingTime:   (*historyDto[2].SyncingTime).Add(-1 * time.Hour),
			DeviceName:    historyDto[2].DeviceName,
			DeviceIP:      historyDto[2].DeviceIP,
		},
		{ // 3 history syncronized version newer than user one.
			ID:            historyDto[3].ID,
			UserID:        someUserID,
			ChestID:       historyDto[3].ChestID,
			OperationType: historyDto[3].OperationType,
			OperationTime: historyDto[3].OperationTime.Add(3 * time.Hour),
			SyncingTime:   (*historyDto[3].SyncingTime).Add(3 * time.Hour),
			DeviceName:    historyDto[3].DeviceName,
			DeviceIP:      historyDto[3].DeviceIP,
		},
		{ // 4 history that this client dont have.
			ID:            uuid.NewString(),
			UserID:        someUserID,
			ChestID:       uuid.NewString(),
			OperationType: 1,
			OperationTime: time.Now().Add(-2 * time.Hour),
			SyncingTime:   time.Now().Add(-1 * time.Hour),
			DeviceName:    "android",
			DeviceIP:      "10.0.0.1",
		},
	}

	expectedHistory := []string{
		historyDto[0].ID,
		historyDto[2].ID,
		historyDto[3].ID,
		historyModels[3].ID,
	}

	type testArgs struct {
		historyDto []*dto.History
		userID     uuid.UUID
	}

	type testExpected struct {
		validationError error
		repostioryError error
		expectedHistory []string
	}

	type testData struct {
		name     string
		args     testArgs
		expected testExpected
	}

	data := []testData{
		{
			name: "success",
			args: testArgs{
				historyDto: historyDto,
				userID:     someUserID,
			},
			expected: testExpected{
				validationError: nil,
				repostioryError: nil,
				expectedHistory: expectedHistory,
			},
		},
		{
			name: "validation_error",
			args: testArgs{
				historyDto: []*dto.History{
					{
						ID:            "",
						UserID:        someUserID,
						ChestID:       "",
						OperationType: 0,
						OperationTime: time.Time{},
						SyncingTime:   &time.Time{},
						DeviceName:    "",
						DeviceIP:      "",
					},
				},
				userID: someUserID,
			},
			expected: testExpected{
				validationError: errors.New("validation error"),
				repostioryError: nil,
				expectedHistory: expectedHistory,
			},
		},
		{
			name: "not_found_error",
			args: testArgs{
				historyDto: historyDto,
				userID:     someUserID,
			},
			expected: testExpected{
				validationError: nil,
				repostioryError: errors.New("not found"),
				expectedHistory: expectedHistory,
			},
		},
		{
			name: "internal_error",
			args: testArgs{
				historyDto: historyDto,
				userID:     someUserID,
			},
			expected: testExpected{
				validationError: nil,
				repostioryError: errors.New("internal"),
				expectedHistory: expectedHistory,
			},
		},
	}

	for _, test := range data {
		t.Run(test.name, func(t *testing.T) {
			mocks := newMock(t)
			hisoryRepo := mocks.history
			usecase := New(mocks, cfg, lg)

			if test.expected.validationError == nil {
				hisoryRepo.EXPECT().SelectUserChestsLastHistory(mock.Anything, test.args.userID).Return(historyModels, test.expected.repostioryError)
			}

			if test.expected.repostioryError != nil {
				if test.expected.repostioryError.Error() == "not found" {
					hisoryRepo.EXPECT().NotFoundError(test.expected.repostioryError).Return(test.expected.repostioryError)
				} else {
					hisoryRepo.EXPECT().NotFoundError(test.expected.repostioryError).Return(nil)
				}
			}

			history, err := usecase.Sync(context.Background(), test.args.historyDto, test.args.userID)
			if test.expected.validationError != nil ||
				test.expected.repostioryError != nil {
				assert.Error(t, err, "expected error got nil")
				return
			}

			assert.NoError(t, err, "expected no error got error")
			assert.NotNil(t, history, "expected history got nil")
			assert.Equal(t, len(test.expected.expectedHistory), len(history), "expected history length %d got %d", len(test.expected.expectedHistory), len(history))
			resultHistoryID := make([]string, len(history))
			for i, h := range history {
				resultHistoryID[i] = h.ID
			}
			assert.ElementsMatch(t, test.expected.expectedHistory, resultHistoryID, "expected history %v got %v", test.expected.expectedHistory, resultHistoryID)
		})
	}
}

func TestValidationError(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	mocks := newMock(t)
	usecase := New(mocks, cfg, lg)

	type testArgs struct {
		err error
	}

	type testExpected struct {
		is     func(err error) bool
		status bool
	}

	type testData struct {
		name     string
		args     testArgs
		expected testExpected
	}

	data := []testData{
		{
			name: "validation_error_true",
			args: testArgs{
				err: newErrKeeperUseCases("validation error", errKeeperUseCasesValidation, errors.New("some validation error")),
			},
			expected: testExpected{
				is:     usecase.ValidationError,
				status: true,
			},
		},
		{
			name: "validation_error_false",
			args: testArgs{
				err: errors.New("some validation error"),
			},
			expected: testExpected{
				is:     usecase.ValidationError,
				status: false,
			},
		},
		{
			name: "not_found_error_true",
			args: testArgs{
				err: newErrKeeperUseCases("not found error", errKeeperUseCasesNotFound, errors.New("some not found error")),
			},
			expected: testExpected{
				is:     usecase.NotFoundError,
				status: true,
			},
		},
		{
			name: "not_found_error_false",
			args: testArgs{
				err: errors.New("some error"),
			},
			expected: testExpected{
				is:     usecase.NotFoundError,
				status: false,
			},
		},
		{
			name: "internal_error_true",
			args: testArgs{
				err: newErrKeeperUseCases("internal error", errKeeperUseCasesInternal, errors.New("some internal error")),
			},
			expected: testExpected{
				is:     usecase.InternalError,
				status: true,
			},
		},
		{
			name: "not_found_error_false",
			args: testArgs{
				err: errors.New("some error"),
			},
			expected: testExpected{
				is:     usecase.InternalError,
				status: false,
			},
		},
		{
			name: "authentification_error_true",
			args: testArgs{
				err: newErrKeeperUseCases("authentification error", errKeeperUseCasesAuthentification, errors.New("some authentification error")),
			},
			expected: testExpected{
				is:     usecase.AuthentificationError,
				status: true,
			},
		},
		{
			name: "authentification_error_false",
			args: testArgs{
				err: errors.New("some error"),
			},
			expected: testExpected{
				is:     usecase.AuthentificationError,
				status: false,
			},
		},
		{
			name: "conflict_error_true",
			args: testArgs{
				err: newErrKeeperUseCases("conflict error", errKeeperUseCasesConflict, errors.New("some conflict error")),
			},
			expected: testExpected{
				is:     usecase.ConflictError,
				status: true,
			},
		},
		{
			name: "conflict_error_false",
			args: testArgs{
				err: errors.New("some error"),
			},
			expected: testExpected{
				is:     usecase.ConflictError,
				status: false,
			},
		},
	}

	for _, test := range data {
		t.Run(test.name, func(t *testing.T) {
			res := test.expected.is(test.args.err)
			assert.Equal(t, test.expected.status, res, "expected %v got %v", test.expected.is, res)
		})
	}

}

func TestExtractUserErrorMessage(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	mocks := newMock(t)
	usecase := New(mocks, cfg, lg)

	t.Run("usecase_error", func(t *testing.T) {
		expectedMessage := "some message"
		someError := newErrKeeperUseCases(expectedMessage, errKeeperUseCasesInternal, errors.New("some internal error"))

		actualMessage := usecase.ExtractUserErrorMessage(someError)
		assert.Equal(t, expectedMessage, actualMessage, "expected %s got %s", expectedMessage, actualMessage)
	})

	t.Run("casual_error", func(t *testing.T) {
		expectedMessage := "some message"
		someError := errors.New(expectedMessage)

		actualMessage := usecase.ExtractUserErrorMessage(someError)
		assert.Equal(t, expectedMessage, actualMessage, "expected %s got %s", expectedMessage, actualMessage)
	})
}
