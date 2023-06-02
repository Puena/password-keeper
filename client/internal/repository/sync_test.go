package repository

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/models"
	pb "github.com/Puena/password-keeper/proto"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthentification(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	type testArgs struct {
		authData *models.AuthData
	}

	type testExpected struct {
		syncRepositoryError error
		result              *pb.AuthTokenResponse
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
				authData: &models.AuthData{
					Login:    "some@login.ru",
					Password: "somePassword",
				},
			},
			expected: testExpected{
				result: &pb.AuthTokenResponse{
					Token: "someToken",
				},
			},
		},
		{
			name: "signin_error",
			args: testArgs{
				authData: &models.AuthData{
					Login:    "somewrongloggin",
					Password: "somePassword",
				},
			},
			expected: testExpected{
				syncRepositoryError: errors.New("some error"),
				result: &pb.AuthTokenResponse{
					Token: "",
				},
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockSyncClient(t)
			syncRepo := NewSyncRepository(cfg, lg)
			syncRepo.SetClient(mockClient)

			mockClient.EXPECT().SignIn(context.Background(), &pb.AuthDataRequest{
				Login:    tt.args.authData.Login,
				Password: tt.args.authData.Password,
			}).Return(tt.expected.result, tt.expected.syncRepositoryError)

			res, err := syncRepo.Authentification(context.Background(), tt.args.authData)
			if tt.expected.syncRepositoryError != nil {
				assert.Error(t, err, "expected error while executing syncRepo.Authentification()")
				return
			}

			assert.NoError(t, err, "failed while executing syncRepo.Authentification()")
			assert.NotEmpty(t, res, "expected not empty result while executing syncRepo.Authentification()")
		})
	}
}

func TestRegistration(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	type testArgs struct {
		authData *models.AuthData
	}

	type testExpected struct {
		syncRepositoryError error
		result              *pb.AuthTokenResponse
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
				authData: &models.AuthData{
					Login:    "some@login.ru",
					Password: "somePassword",
				},
			},
			expected: testExpected{
				result: &pb.AuthTokenResponse{
					Token: "someToken",
				},
			},
		},
		{
			name: "signin_error",
			args: testArgs{
				authData: &models.AuthData{
					Login:    "somewrongloggin",
					Password: "somePassword",
				},
			},
			expected: testExpected{
				syncRepositoryError: errors.New("some error"),
				result: &pb.AuthTokenResponse{
					Token: "",
				},
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockSyncClient(t)
			syncRepo := NewSyncRepository(cfg, lg)
			syncRepo.SetClient(mockClient)

			mockClient.EXPECT().SignUp(context.Background(), &pb.AuthDataRequest{
				Login:    tt.args.authData.Login,
				Password: tt.args.authData.Password,
			}).Return(tt.expected.result, tt.expected.syncRepositoryError)

			res, err := syncRepo.Registration(context.Background(), tt.args.authData)
			if tt.expected.syncRepositoryError != nil {
				assert.Error(t, err, "expected error while executing syncRepo.Authentification()")
				return
			}

			assert.NoError(t, err, "failed while executing syncRepo.Registration()")
			assert.NotEmpty(t, res, "expected not empty result while executing syncRepo.Registration()")
		})
	}
}

func TestGetChestByID(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")
	somePbChest := &pb.Chest{
		Id:        "someChestID",
		UserId:    nil,
		Salt:      sha256.New().Sum([]byte("someSalt")),
		Name:      "some chest",
		Data:      sha256.New().Sum([]byte("someData")),
		DatatType: 0,
	}
	somePbHistory := &pb.History{
		Id:            uuid.NewString(),
		ChestId:       somePbChest.Id,
		UserId:        nil,
		OperationType: 0,
		OperationTime: time.Now().Unix(),
		SyncingTime:   nil,
		DeviceName:    "android",
		DeviceIp:      nil,
	}
	someRequest := &pb.ChestRequest{
		Chest:   somePbChest,
		History: somePbHistory,
	}

	type testArgs struct {
		chestID string
		request *pb.ChestRequest
	}

	type testExpected struct {
		syncRepositoryError error
		chestResult         *models.Chest
		historyResult       *models.History
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
				chestID: "someChestID",
				request: someRequest,
			},
			expected: testExpected{
				chestResult:   composeChestModel(somePbChest),
				historyResult: composeHistoryModel(somePbHistory),
			},
		},
		{
			name: "get_error",
			args: testArgs{
				chestID: "someChestID",
				request: someRequest,
			},
			expected: testExpected{
				chestResult:         composeChestModel(somePbChest),
				historyResult:       composeHistoryModel(somePbHistory),
				syncRepositoryError: errors.New("some error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockSyncClient(t)
			syncRepo := NewSyncRepository(cfg, lg)
			syncRepo.SetClient(mockClient)

			mockClient.EXPECT().GetChestByID(context.Background(), &pb.ChestIDRequest{
				ChestId: tt.args.chestID,
			}).Return(&pb.ChestResponse{
				Chest:   tt.args.request.Chest,
				History: tt.args.request.History,
			}, tt.expected.syncRepositoryError)

			chest, history, err := syncRepo.GetChestByID(context.Background(), tt.args.chestID)
			if tt.expected.syncRepositoryError != nil {
				assert.Error(t, err, "expected error while executing syncRepo.Authentification()")
				return
			}

			assert.NoError(t, err, "failed while executing syncRepo.Registration()")
			assert.NotNil(t, chest, "expected not empty chest while executing syncRepo.GetChestByID()")
			assert.NotNil(t, history, "expected not empty history while executing syncRepo.GetChestByID()")
			assert.Equal(t, tt.expected.chestResult, chest, "expected equal chest while executing syncRepo.GetChestByID()")
			assert.Equal(t, tt.expected.historyResult, history, "expected equal history while executing syncRepo.GetChestByID()")
		})
	}
}

func TestAddChest(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")
	somePbChest := &pb.Chest{
		Id:        "someChestID",
		UserId:    nil,
		Salt:      sha256.New().Sum([]byte("someSalt")),
		Name:      "some chest",
		Data:      sha256.New().Sum([]byte("someData")),
		DatatType: 0,
	}
	somePbHistory := &pb.History{
		Id:            uuid.NewString(),
		ChestId:       somePbChest.Id,
		UserId:        nil,
		OperationType: 0,
		OperationTime: time.Now().Unix(),
		SyncingTime:   nil,
		DeviceName:    "android",
		DeviceIp:      nil,
	}

	type testArgs struct {
		chest   *models.Chest
		history *models.History
	}

	type testExpected struct {
		syncRepositoryError error
		chestResult         *models.Chest
		historyResult       *models.History
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
				chest:   composeChestModel(somePbChest),
				history: composeHistoryModel(somePbHistory),
			},
			expected: testExpected{
				chestResult:   composeChestModel(somePbChest),
				historyResult: composeHistoryModel(somePbHistory),
			},
		},
		{
			name: "get_error",
			args: testArgs{
				chest:   composeChestModel(somePbChest),
				history: composeHistoryModel(somePbHistory),
			},
			expected: testExpected{
				chestResult:         composeChestModel(somePbChest),
				historyResult:       composeHistoryModel(somePbHistory),
				syncRepositoryError: errors.New("some error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockSyncClient(t)
			syncRepo := NewSyncRepository(cfg, lg)
			syncRepo.SetClient(mockClient)

			mockClient.EXPECT().AddChest(mock.Anything, &pb.ChestRequest{
				Chest:   composeChestMessage(tt.args.chest),
				History: composeHistoryMessage(tt.args.history),
			}).Return(&pb.HistoryResponse{
				History: composeHistoryMessage(tt.args.history),
			}, tt.expected.syncRepositoryError)

			history, err := syncRepo.AddChest(context.Background(), tt.args.chest, tt.args.history)
			if tt.expected.syncRepositoryError != nil {
				assert.Error(t, err, "expected error while executing syncRepo.Authentification()")
				return
			}

			assert.NoError(t, err, "failed while executing syncRepo.Registration()")
			assert.NotNil(t, history, "expected not empty history while executing syncRepo.AddChest()")
			assert.Equal(t, tt.expected.historyResult, history, "expected equal history while executing syncRepo.AddChest()")
		})
	}
}

func TestUpdateChest(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")
	somePbChest := &pb.Chest{
		Id:        "someChestID",
		UserId:    nil,
		Salt:      sha256.New().Sum([]byte("someSalt")),
		Name:      "some chest",
		Data:      sha256.New().Sum([]byte("someData")),
		DatatType: 0,
	}
	somePbHistory := &pb.History{
		Id:            uuid.NewString(),
		ChestId:       somePbChest.Id,
		UserId:        nil,
		OperationType: 0,
		OperationTime: time.Now().Unix(),
		SyncingTime:   nil,
		DeviceName:    "android",
		DeviceIp:      nil,
	}

	type testArgs struct {
		chest   *models.Chest
		history *models.History
	}

	type testExpected struct {
		syncRepositoryError error
		chestResult         *models.Chest
		historyResult       *models.History
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
				chest:   composeChestModel(somePbChest),
				history: composeHistoryModel(somePbHistory),
			},
			expected: testExpected{
				chestResult:   composeChestModel(somePbChest),
				historyResult: composeHistoryModel(somePbHistory),
			},
		},
		{
			name: "get_error",
			args: testArgs{
				chest:   composeChestModel(somePbChest),
				history: composeHistoryModel(somePbHistory),
			},
			expected: testExpected{
				chestResult:         composeChestModel(somePbChest),
				historyResult:       composeHistoryModel(somePbHistory),
				syncRepositoryError: errors.New("some error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockSyncClient(t)
			syncRepo := NewSyncRepository(cfg, lg)
			syncRepo.SetClient(mockClient)

			mockClient.EXPECT().UpdateChest(mock.Anything, &pb.ChestRequest{
				Chest:   composeChestMessage(tt.args.chest),
				History: composeHistoryMessage(tt.args.history),
			}).Return(&pb.HistoryResponse{
				History: composeHistoryMessage(tt.args.history),
			}, tt.expected.syncRepositoryError)

			history, err := syncRepo.UpdateChest(context.Background(), tt.args.chest, tt.args.history)
			if tt.expected.syncRepositoryError != nil {
				assert.Error(t, err, "expected error while executing syncRepo.Authentification()")
				return
			}

			assert.NoError(t, err, "failed while executing syncRepo.Registration()")
			assert.NotNil(t, history, "expected not empty history while executing syncRepo.UpdateChest()")
			assert.Equal(t, tt.expected.historyResult, history, "expected equal history while executing syncRepo.UpdateChest()")
		})
	}
}

func TestDeleteChest(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")
	somePbChest := &pb.Chest{
		Id:        "someChestID",
		UserId:    nil,
		Salt:      sha256.New().Sum([]byte("someSalt")),
		Name:      "some chest",
		Data:      sha256.New().Sum([]byte("someData")),
		DatatType: 0,
	}
	somePbHistory := &pb.History{
		Id:            uuid.NewString(),
		ChestId:       somePbChest.Id,
		UserId:        nil,
		OperationType: 0,
		OperationTime: time.Now().Unix(),
		SyncingTime:   nil,
		DeviceName:    "android",
		DeviceIp:      nil,
	}

	type testArgs struct {
		history *models.History
	}

	type testExpected struct {
		syncRepositoryError error
		historyResult       *models.History
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
				history: composeHistoryModel(somePbHistory),
			},
			expected: testExpected{
				historyResult: composeHistoryModel(somePbHistory),
			},
		},
		{
			name: "get_error",
			args: testArgs{
				history: composeHistoryModel(somePbHistory),
			},
			expected: testExpected{
				historyResult:       composeHistoryModel(somePbHistory),
				syncRepositoryError: errors.New("some error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockSyncClient(t)
			syncRepo := NewSyncRepository(cfg, lg)
			syncRepo.SetClient(mockClient)

			mockClient.EXPECT().DeleteChest(mock.Anything, &pb.DeleteChestRequest{
				History: composeHistoryMessage(tt.args.history),
			}).Return(&pb.HistoryResponse{
				History: composeHistoryMessage(tt.args.history),
			}, tt.expected.syncRepositoryError)

			history, err := syncRepo.DeleteChest(context.Background(), tt.args.history)
			if tt.expected.syncRepositoryError != nil {
				assert.Error(t, err, "expected error while executing syncRepo.Authentification()")
				return
			}

			assert.NoError(t, err, "failed while executing syncRepo.Registration()")
			assert.NotNil(t, history, "expected not empty history while executing syncRepo.UpdateChest()")
			assert.Equal(t, tt.expected.historyResult, history, "expected equal history while executing syncRepo.UpdateChest()")
		})
	}
}

func TestSync(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")
	somePbChest := &pb.Chest{
		Id:        "someChestID",
		UserId:    nil,
		Salt:      sha256.New().Sum([]byte("someSalt")),
		Name:      "some chest",
		Data:      sha256.New().Sum([]byte("someData")),
		DatatType: 0,
	}
	somePbHistory := &pb.History{
		Id:            uuid.NewString(),
		ChestId:       somePbChest.Id,
		UserId:        nil,
		OperationType: 0,
		OperationTime: time.Now().Unix(),
		SyncingTime:   nil,
		DeviceName:    "android",
		DeviceIp:      nil,
	}

	type testArgs struct {
		history *models.History
	}

	type testExpected struct {
		syncRepositoryError error
		historyResult       []*models.History
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
				history: composeHistoryModel(somePbHistory),
			},
			expected: testExpected{
				historyResult: []*models.History{composeHistoryModel(somePbHistory)},
			},
		},
		{
			name: "get_error",
			args: testArgs{
				history: composeHistoryModel(somePbHistory),
			},
			expected: testExpected{
				historyResult:       []*models.History{composeHistoryModel(somePbHistory)},
				syncRepositoryError: errors.New("some error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockSyncClient(t)
			syncRepo := NewSyncRepository(cfg, lg)
			syncRepo.SetClient(mockClient)

			mockClient.EXPECT().Sync(mock.Anything, &pb.SyncRequest{
				History: []*pb.History{composeHistoryMessage(tt.args.history)},
			}).Return(&pb.SyncResponse{
				History: []*pb.History{composeHistoryMessage(tt.args.history)},
			}, tt.expected.syncRepositoryError)

			history, err := syncRepo.Sync(context.Background(), []*models.History{tt.args.history})
			if tt.expected.syncRepositoryError != nil {
				assert.Error(t, err, "expected error while executing syncRepo.Authentification()")
				return
			}

			assert.NoError(t, err, "failed while executing syncRepo.Registration()")
			assert.NotNil(t, history, "expected not empty history while executing syncRepo.UpdateChest()")
			assert.Equal(t, tt.expected.historyResult, history, "expected equal history while executing syncRepo.UpdateChest()")
		})
	}
}

func TestSyncRepositoriesErrors(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	t.Run("auth_error", func(t *testing.T) {
		mockClient := newMockSyncClient(t)
		syncRepo := NewSyncRepository(cfg, lg)
		syncRepo.SetClient(mockClient)

		authErr := newSyncRepositoryError("unauthenticated", status.Errorf(codes.Unauthenticated, "some error"))
		wrongStatusErr := newSyncRepositoryError("internal", status.Errorf(codes.Internal, "some error"))
		notStatusErr := newSyncRepositoryError("some error", errors.New("some error"))
		assert.True(t, syncRepo.IsAuthentificationError(authErr), "expected true while executing syncRepo.IsAuthentificationError()")
		assert.False(t, syncRepo.IsAuthentificationError(wrongStatusErr), "expected true while executing syncRepo.IsAuthentificationError()")
		assert.False(t, syncRepo.IsAuthentificationError(notStatusErr), "expected true while executing syncRepo.IsAuthentificationError()")
		assert.False(t, syncRepo.IsAuthentificationError(errors.New("some error")), "expected false while executing syncRepo.IsAuthentificationError()")
	})

	t.Run("not_found_error", func(t *testing.T) {
		mockClient := newMockSyncClient(t)
		syncRepo := NewSyncRepository(cfg, lg)
		syncRepo.SetClient(mockClient)

		notFoundErr := newSyncRepositoryError("not found error", status.Errorf(codes.NotFound, "some error"))
		wrongStatusErr := newSyncRepositoryError("internal", status.Errorf(codes.Internal, "some error"))
		notStatusErr := newSyncRepositoryError("some error", errors.New("some error"))
		assert.True(t, syncRepo.IsNotFoundError(notFoundErr), "expected true while executing syncRepo.IsAuthentificationError()")
		assert.False(t, syncRepo.IsNotFoundError(wrongStatusErr), "expected true while executing syncRepo.IsAuthentificationError()")
		assert.False(t, syncRepo.IsNotFoundError(notStatusErr), "expected true while executing syncRepo.IsAuthentificationError()")
		assert.False(t, syncRepo.IsNotFoundError(errors.New("some error")), "expected false while executing syncRepo.IsAuthentificationError()")
	})

	t.Run("bad_user_data_error", func(t *testing.T) {
		mockClient := newMockSyncClient(t)
		syncRepo := NewSyncRepository(cfg, lg)
		syncRepo.SetClient(mockClient)

		badDataErr := newSyncRepositoryError("bad user data", status.Errorf(codes.InvalidArgument, "some error"))
		wrongStatusErr := newSyncRepositoryError("internal", status.Errorf(codes.Internal, "some error"))
		notStatusErr := newSyncRepositoryError("some error", errors.New("some error"))
		assert.Error(t, syncRepo.BadUserDataError(badDataErr), "expected true while executing syncRepo.IsAuthentificationError()")
		assert.NoError(t, syncRepo.BadUserDataError(wrongStatusErr), "expected true while executing syncRepo.IsAuthentificationError()")
		assert.NoError(t, syncRepo.BadUserDataError(notStatusErr), "expected true while executing syncRepo.IsAuthentificationError()")
		assert.NoError(t, syncRepo.BadUserDataError(errors.New("some error")), "expected false while executing syncRepo.IsAuthentificationError()")
	})

	t.Run("connection_error", func(t *testing.T) {
		mockClient := newMockSyncClient(t)
		syncRepo := NewSyncRepository(cfg, lg)
		syncRepo.SetClient(mockClient)

		connectionError := newSyncRepositoryError("connection", status.Errorf(codes.Unavailable, "some error"))
		wrongStatusErr := newSyncRepositoryError("internal", status.Errorf(codes.Internal, "some error"))
		notStatusErr := newSyncRepositoryError("some error", errors.New("some error"))
		assert.True(t, syncRepo.IsConnectionError(connectionError), "expected true while executing syncRepo.IsAuthentificationError()")
		assert.False(t, syncRepo.IsConnectionError(wrongStatusErr), "expected true while executing syncRepo.IsAuthentificationError()")
		assert.False(t, syncRepo.IsConnectionError(notStatusErr), "expected true while executing syncRepo.IsAuthentificationError()")
		assert.False(t, syncRepo.IsConnectionError(errors.New("some error")), "expected false while executing syncRepo.IsAuthentificationError()")
	})

	t.Run("data_already_exists_error", func(t *testing.T) {
		mockClient := newMockSyncClient(t)
		syncRepo := NewSyncRepository(cfg, lg)
		syncRepo.SetClient(mockClient)

		connectionError := newSyncRepositoryError("already exists", status.Errorf(codes.AlreadyExists, "some error"))
		wrongStatusErr := newSyncRepositoryError("internal", status.Errorf(codes.Internal, "some error"))
		notStatusErr := newSyncRepositoryError("some error", errors.New("some error"))
		assert.True(t, syncRepo.IsDataAlreadyExistsError(connectionError), "expected true while executing syncRepo.IsAuthentificationError()")
		assert.False(t, syncRepo.IsDataAlreadyExistsError(wrongStatusErr), "expected true while executing syncRepo.IsAuthentificationError()")
		assert.False(t, syncRepo.IsDataAlreadyExistsError(notStatusErr), "expected true while executing syncRepo.IsAuthentificationError()")
		assert.False(t, syncRepo.IsDataAlreadyExistsError(errors.New("some error")), "expected false while executing syncRepo.IsAuthentificationError()")
	})
}
