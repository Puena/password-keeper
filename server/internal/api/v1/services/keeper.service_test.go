package services

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	pb "github.com/Puena/password-keeper/proto"
	"github.com/Puena/password-keeper/server/config"
	"github.com/Puena/password-keeper/server/internal/dto"
	"github.com/google/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/selector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// import (
// 	"context"
// 	"crypto"
// 	"errors"
// 	"fmt"
// 	"io"
// 	"net"
// 	"net/netip"
// 	"strings"
// 	"testing"
// 	"time"

// 	"github.com/Puena/ya-goph-keeper-server/config"
// 	"github.com/Puena/ya-goph-keeper-server/internal/dto"
// 	"github.com/Puena/ya-goph-keeper-server/internal/models"
// 	"github.com/google/uuid"
// 	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/mock"
// 	"github.com/stretchr/testify/require"
// 	"go.uber.org/zap"
// 	"google.golang.org/grpc"
// 	"google.golang.org/grpc/codes"
// 	"google.golang.org/grpc/credentials/insecure"
// 	"google.golang.org/grpc/metadata"
// 	"google.golang.org/grpc/status"
// )

// var authHeader = "authorization"

func initKeeperService(service *KeeperService) (*grpc.Server, *grpc.ClientConn, error) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, nil, fmt.Errorf("failed when init logger %s", err)
	}

	// Prepare server
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, nil, fmt.Errorf("failed when listening net %s", err)
	}
	listenAddress := listen.Addr().String()

	gs := grpc.NewServer(
		grpc.UnaryInterceptor(
			selector.UnaryServerInterceptor(auth.UnaryServerInterceptor(service.AuthFunc), selector.MatchFunc(service.DoAuth)),
		),
	)

	pb.RegisterKeeperServer(gs, service)

	// Run server
	go func() {
		logger.Info("start grpc server at", zap.String("address", listenAddress))
		err = gs.Serve(listen)
		if err != nil {
			logger.Sugar().Fatalf("failed when serving grpc server %s", err)
			return
		}
	}()

	// Run client
	conn, err := grpc.Dial(listenAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed when dial to grpc server %s", err)
	}

	logger.Info("sucessfully connect to grpc server at", zap.String("address", listenAddress))
	return gs, conn, nil
}

func mockHandleAuth(usecase *MockKeeperUseCases, userID *uuid.UUID, err error) {
	if err != nil {
		usecase.EXPECT().Auth(mock.Anything, mock.Anything).Return(nil, err)
		mockHandlerUsecaseError(usecase, codes.Unauthenticated, err)
		return
	}
	usecase.EXPECT().Auth(mock.Anything, mock.Anything).Return(userID, nil)
}

func mockHandlerUsecaseError(usecase *MockKeeperUseCases, code codes.Code, err error) {
	usecase.EXPECT().ExtractUserErrorMessage(mock.Anything).Return(err.Error())

	if codes.InvalidArgument == code {
		usecase.EXPECT().ValidationError(mock.Anything).Return(true)
		return
	} else {
		usecase.EXPECT().ValidationError(mock.Anything).Return(false)
	}

	if codes.NotFound == code {
		usecase.EXPECT().NotFoundError(mock.Anything).Return(true)
		return
	} else {
		usecase.EXPECT().NotFoundError(mock.Anything).Return(false)
	}

	if codes.Internal == code {
		usecase.EXPECT().InternalError(mock.Anything).Return(true)
		return
	} else {
		usecase.EXPECT().InternalError(mock.Anything).Return(false)
	}

	if codes.Unauthenticated == code {
		usecase.EXPECT().AuthentificationError(mock.Anything).Return(true)
		return
	} else {
		usecase.EXPECT().AuthentificationError(mock.Anything).Return(false)
	}

	if codes.AlreadyExists == code {
		usecase.EXPECT().ConflictError(mock.Anything).Return(true)
		return
	} else {
		usecase.EXPECT().ConflictError(mock.Anything).Return(false)
	}

}

func TestSignUp(t *testing.T) {
	defaultLogger, err := zap.NewDevelopment()
	require.NoError(t, err, "failed when init logger")
	defaultConfig := &config.Config{}
	defaultContext := context.Background()

	type DataStruct struct {
		login    string
		password string
	}

	type ExpectedStruct struct {
		token string
		code  codes.Code
	}

	data := []struct {
		name     string
		data     DataStruct
		error    error
		expected ExpectedStruct
	}{
		{
			name: "success",
			data: DataStruct{
				login:    "mail@mail.ru",
				password: "asdf98as98dfas",
			},
			error: nil,
			expected: ExpectedStruct{
				token: "asdfas9d8fasdflkajsdf98",
				code:  0,
			},
		},
		{
			name: "validation_error",
			data: DataStruct{
				login:    "mail",
				password: "asdfasdfas9df",
			},
			error: errors.New("some validation error"),
			expected: ExpectedStruct{
				code: codes.InvalidArgument,
			},
		},
		{
			name: "internal_error",
			data: DataStruct{
				login:    "mail@mail.ru",
				password: "asdf98as8df9a8sd7f",
			},
			error: errors.New("some internal error"),
			expected: ExpectedStruct{
				code: codes.Internal,
			},
		},
	}

	for _, d := range data {
		d := d
		usecases := NewMockKeeperUseCases(t)
		service := New(usecases, defaultConfig, defaultLogger)

		t.Run(d.name, func(t *testing.T) {
			usecases.EXPECT().SignUp(mock.Anything, dto.AuthDataDto{
				Login:    d.data.login,
				Password: d.data.password,
			}).Return(&dto.AuthTokenDto{
				Token: d.expected.token,
			}, d.error)

			if d.error != nil {
				mockHandlerUsecaseError(usecases, d.expected.code, d.error)
			}

			server, cliCon, err := initKeeperService(service)
			require.NoError(t, err, "failed when init grpc server")
			defer server.Stop()
			defer cliCon.Close()
			cli := pb.NewKeeperClient(cliCon)

			res, err := cli.SignUp(defaultContext, &pb.AuthDataRequest{
				Login:    d.data.login,
				Password: d.data.password,
			})

			if d.error != nil {
				assert.Error(t, err, "failed while expecting error")
				assert.Nil(t, res, "failed while expecting nil response")
				s, ok := status.FromError(err)
				assert.True(t, ok, "failed while expecting status error")
				assert.Equal(t, d.expected.code, s.Code(), "failed while expecting status code")
				return
			}
			assert.NoError(t, err, "failed when sign up")
			assert.NotNil(t, res, "failed while expecting non nil response")
			assert.Equal(t, d.expected.token, res.Token, "failed while expecting non nil response")

		})
	}
}

func TestSignIn(t *testing.T) {
	defaultLogger, err := zap.NewDevelopment()
	require.NoError(t, err, "failed when init logger")
	defaultConfig := &config.Config{}
	defaultContext := context.Background()

	type DataStruct struct {
		login    string
		password string
	}

	type ExpectedStruct struct {
		token string
		code  codes.Code
	}

	data := []struct {
		name     string
		data     DataStruct
		error    error
		expected ExpectedStruct
	}{
		{
			name: "success",
			data: DataStruct{
				login:    "mail@mail.ru",
				password: "asdf98as98dfas",
			},
			error: nil,
			expected: ExpectedStruct{
				token: "asdfas9d8fasdflkajsdf98",
				code:  0,
			},
		},
		{
			name: "validation_error",
			data: DataStruct{
				login:    "mail",
				password: "asdfasdfas9df",
			},
			error: errors.New("some validation error"),
			expected: ExpectedStruct{
				code: codes.InvalidArgument,
			},
		},
		{
			name: "not_found_error",
			data: DataStruct{
				login:    "mail@mail.ru",
				password: "asdf98as8df9a8sd7f",
			},
			error: errors.New("some internal error"),
			expected: ExpectedStruct{
				code: codes.NotFound,
			},
		},
	}

	for _, d := range data {
		d := d
		usecases := NewMockKeeperUseCases(t)
		service := New(usecases, defaultConfig, defaultLogger)

		t.Run(d.name, func(t *testing.T) {
			usecases.EXPECT().SignIn(mock.Anything, dto.AuthDataDto{
				Login:    d.data.login,
				Password: d.data.password,
			}).Return(&dto.AuthTokenDto{
				Token: d.expected.token,
			}, d.error)

			if d.error != nil {
				mockHandlerUsecaseError(usecases, d.expected.code, d.error)
			}

			server, cliCon, err := initKeeperService(service)
			require.NoError(t, err, "failed when init grpc server")
			defer server.Stop()
			defer cliCon.Close()
			cli := pb.NewKeeperClient(cliCon)

			res, err := cli.SignIn(defaultContext, &pb.AuthDataRequest{
				Login:    d.data.login,
				Password: d.data.password,
			})

			if d.error != nil {
				assert.Error(t, err, "failed while expecting error")
				assert.Nil(t, res, "failed while expecting nil response")
				s, ok := status.FromError(err)
				assert.True(t, ok, "failed while expecting status error")
				assert.Equal(t, d.expected.code, s.Code(), "failed while expecting status code")
				return
			}
			assert.NoError(t, err, "failed when sign up")
			assert.NotNil(t, res, "failed while expecting non nil response")
			assert.Equal(t, d.expected.token, res.Token, "failed while expecting non nil response")

		})
	}
}

func TestGetChestByID(t *testing.T) {
	defaultLogger, err := zap.NewDevelopment()
	require.NoError(t, err, "failed when init logger")
	defaultConfig := &config.Config{}
	chestDto := &dto.Chest{
		ID:       uuid.NewString(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("some salt")),
		Name:     "some name",
		Data:     []byte("some data"),
		DataType: 0,
	}
	syncTime := time.Now()
	historyDto := &dto.History{
		ID:            uuid.NewString(),
		UserID:        uuid.New(),
		ChestID:       chestDto.ID,
		OperationType: 0,
		OperationTime: time.Now(),
		SyncingTime:   &syncTime,
		DeviceName:    "androidx",
		DeviceIP:      "10.0.0.1",
	}

	type DataStruct struct {
		chestID string
		userID  uuid.UUID
		token   string
	}

	type ExpectedStruct struct {
		chest   *dto.Chest
		history *dto.History
		code    codes.Code
	}

	data := []struct {
		name       string
		data       DataStruct
		usecaseErr error
		authErr    error
		expected   ExpectedStruct
	}{
		{
			name: "success",
			data: DataStruct{
				chestID: "some-chest-id",
				userID:  uuid.New(),
				token:   fmt.Sprintf("%s %s", authScheme, uuid.NewString()),
			},
			usecaseErr: nil,
			authErr:    nil,
			expected: ExpectedStruct{
				chest:   chestDto,
				history: historyDto,
				code:    0,
			},
		},
		{
			name: "auth_error",
			data: DataStruct{
				chestID: "some-chest-id",
				userID:  uuid.New(),
				token:   "",
			},
			authErr:    errors.New("some auth error"),
			usecaseErr: nil,
			expected: ExpectedStruct{
				chest:   chestDto,
				history: historyDto,
				code:    codes.Unauthenticated,
			},
		},
		{
			name: "not_found_error",
			data: DataStruct{
				chestID: "some-chest-id",
				userID:  uuid.New(),
				token:   fmt.Sprintf("%s %s", authScheme, uuid.NewString()),
			},
			authErr:    nil,
			usecaseErr: errors.New("not found error"),
			expected: ExpectedStruct{
				chest:   chestDto,
				history: historyDto,
				code:    codes.NotFound,
			},
		},
	}

	for _, d := range data {
		d := d
		t.Run(d.name, func(t *testing.T) {
			usecases := NewMockKeeperUseCases(t)
			service := New(usecases, defaultConfig, defaultLogger)

			if d.authErr == nil {
				mockHandleAuth(usecases, &d.data.userID, d.authErr)
				usecases.EXPECT().GetChestByID(mock.Anything, d.data.chestID, d.data.userID).Return(d.expected.chest, d.expected.history, d.usecaseErr)
			}

			if d.usecaseErr != nil {
				mockHandlerUsecaseError(usecases, d.expected.code, d.usecaseErr)
			}

			server, cliCon, err := initKeeperService(service)
			require.NoError(t, err, "failed when init grpc server")
			defer server.Stop()
			defer cliCon.Close()
			cli := pb.NewKeeperClient(cliCon)

			authMd := metadata.Pairs("authorization", d.data.token)
			ctx := metadata.NewOutgoingContext(context.Background(), authMd)
			res, err := cli.GetChestByID(ctx, &pb.ChestIDRequest{
				ChestId: d.data.chestID,
			})
			if d.authErr != nil || d.usecaseErr != nil {
				assert.Error(t, err, "failed while expecting error")
				assert.Nil(t, res, "failed while expecting nil response")
				s, ok := status.FromError(err)
				assert.True(t, ok, "failed while expecting status error")
				assert.Equal(t, d.expected.code, s.Code(), "failed while expecting status code")
				return
			}

			assert.NoError(t, err, "failed when get chest by id")
			assert.NotNil(t, res, "failed while expecting non nil response")
		})
	}
}

func TestAddChest(t *testing.T) {
	defaultLogger, err := zap.NewDevelopment()
	require.NoError(t, err, "failed when init logger")
	defaultConfig := &config.Config{}
	token := fmt.Sprintf("%s %s", authScheme, uuid.NewString())
	userID := uuid.New()
	deviceIP := "10.0.0.1"
	pbChest := &pb.Chest{
		Id:        uuid.NewString(),
		UserId:    asStringRef(userID.String()),
		Salt:      sha256.New().Sum([]byte("some salt")),
		Name:      "yandex disk",
		Data:      sha256.New().Sum([]byte("some data")),
		DatatType: 0,
	}
	pbHistory := &pb.History{
		Id:            uuid.NewString(),
		ChestId:       pbChest.Id,
		UserId:        pbChest.UserId,
		OperationType: 0,
		OperationTime: time.Now().Unix(),
		SyncingTime:   nil,
		DeviceName:    "androidx",
		DeviceIp:      &deviceIP,
	}
	syncTime := time.Now()
	expectedHistory := &dto.History{
		ID:            pbHistory.Id,
		UserID:        userID,
		ChestID:       pbChest.Id,
		OperationType: pbHistory.OperationType,
		OperationTime: time.Unix(pbHistory.OperationTime, 0),
		SyncingTime:   &syncTime,
		DeviceName:    pbHistory.DeviceName,
		DeviceIP:      deviceIP,
	}
	chestRequeest := &pb.ChestRequest{
		Chest:   pbChest,
		History: pbHistory,
	}
	badTimeHistory := *pbHistory
	badTimeHistory.OperationTime = time.Now().Add(48 * time.Hour).Unix()
	badTimeChestRequeest := &pb.ChestRequest{
		Chest:   pbChest,
		History: &badTimeHistory,
	}
	badTimeChestRequeest.History.OperationTime = time.Now().Add(48 * time.Hour).Unix()
	type DataStruct struct {
		token        string
		userID       uuid.UUID
		chestRequest *pb.ChestRequest
	}

	type ExpectedStruct struct {
		authError       error
		extractingError error
		composeError    error
		usecaseError    error
		code            codes.Code
	}

	data := []struct {
		name     string
		data     DataStruct
		expected ExpectedStruct
	}{
		{
			name: "success",
			data: DataStruct{token: token, userID: userID, chestRequest: chestRequeest},
			expected: ExpectedStruct{
				authError:       nil,
				extractingError: nil,
				composeError:    nil,
				usecaseError:    nil,
				code:            0,
			},
		},
		{
			name: "auth_error",
			data: DataStruct{token: "", userID: userID, chestRequest: chestRequeest},
			expected: ExpectedStruct{
				authError:       errors.New("auth error"),
				extractingError: nil,
				composeError:    nil,
				usecaseError:    nil,
				code:            codes.Unauthenticated,
			},
		},
		{
			name: "compose_error",
			data: DataStruct{token: token, userID: userID, chestRequest: badTimeChestRequeest},
			expected: ExpectedStruct{
				authError:       nil,
				extractingError: nil,
				composeError:    errors.New("compose error"),
				usecaseError:    nil,
				code:            codes.InvalidArgument,
			},
		},
		{
			name: "usecase_conflict_error",
			data: DataStruct{token: token, userID: userID, chestRequest: chestRequeest},
			expected: ExpectedStruct{
				authError:       nil,
				extractingError: nil,
				composeError:    nil,
				usecaseError:    errors.New("usecase error"),
				code:            codes.AlreadyExists,
			},
		},
	}

	for _, d := range data {
		d := d
		t.Run(d.name, func(t *testing.T) {
			usecases := NewMockKeeperUseCases(t)
			service := New(usecases, defaultConfig, defaultLogger)

			if d.expected.authError == nil {
				mockHandleAuth(usecases, &d.data.userID, d.expected.authError)
			}

			if d.expected.authError == nil && d.expected.extractingError == nil && d.expected.composeError == nil {
				usecases.EXPECT().AddChest(mock.Anything, mock.AnythingOfType("*dto.Chest"), mock.AnythingOfType("*dto.History")).Return(expectedHistory, d.expected.usecaseError)
			}

			if d.expected.usecaseError != nil {
				mockHandlerUsecaseError(usecases, d.expected.code, d.expected.usecaseError)
			}

			server, cliCon, err := initKeeperService(service)
			require.NoError(t, err, "failed when init grpc server")
			defer server.Stop()
			defer cliCon.Close()
			cli := pb.NewKeeperClient(cliCon)

			authMd := metadata.Pairs("authorization", d.data.token)
			ctx := metadata.NewOutgoingContext(context.Background(), authMd)
			res, err := cli.AddChest(ctx, d.data.chestRequest)
			if d.expected.code == 0 {
				assert.NoError(t, err, "failed when add chest")
				assert.NotNil(t, res, "failed while expecting non nil response")
				assert.NotNil(t, res.History.SyncingTime, "failed while expecting non nil syncing time")
			} else {
				assert.Error(t, err, "failed while expecting error")
				assert.Nil(t, res, "failed while expecting nil response")
				s, ok := status.FromError(err)
				assert.True(t, ok, "failed while expecting status error")
				assert.Equal(t, d.expected.code, s.Code(), "failed while expecting status code")
			}
		})
	}
}

func TestUpdateChest(t *testing.T) {
	defaultLogger, err := zap.NewDevelopment()
	require.NoError(t, err, "failed when init logger")
	defaultConfig := &config.Config{}
	token := fmt.Sprintf("%s %s", authScheme, uuid.NewString())
	userID := uuid.New()
	deviceIP := "10.0.0.1"
	pbChest := &pb.Chest{
		Id:        uuid.NewString(),
		UserId:    asStringRef(userID.String()),
		Salt:      sha256.New().Sum([]byte("some salt")),
		Name:      "yandex disk",
		Data:      sha256.New().Sum([]byte("some data")),
		DatatType: 0,
	}
	pbHistory := &pb.History{
		Id:            uuid.NewString(),
		ChestId:       pbChest.Id,
		UserId:        pbChest.UserId,
		OperationType: 1,
		OperationTime: time.Now().Unix(),
		SyncingTime:   nil,
		DeviceName:    "androidx",
		DeviceIp:      &deviceIP,
	}
	syncTime := time.Now()
	expectedHistory := &dto.History{
		ID:            pbHistory.Id,
		UserID:        userID,
		ChestID:       pbChest.Id,
		OperationType: pbHistory.OperationType,
		OperationTime: time.Unix(pbHistory.OperationTime, 0),
		SyncingTime:   &syncTime,
		DeviceName:    pbHistory.DeviceName,
		DeviceIP:      deviceIP,
	}
	chestRequeest := &pb.ChestRequest{
		Chest:   pbChest,
		History: pbHistory,
	}
	badTimeHistory := *pbHistory
	badTimeHistory.OperationTime = time.Now().Add(48 * time.Hour).Unix()
	badTimeChestRequeest := &pb.ChestRequest{
		Chest:   pbChest,
		History: &badTimeHistory,
	}
	badTimeChestRequeest.History.OperationTime = time.Now().Add(48 * time.Hour).Unix()
	type DataStruct struct {
		token        string
		userID       uuid.UUID
		chestRequest *pb.ChestRequest
	}

	type ExpectedStruct struct {
		authError       error
		extractingError error
		composeError    error
		usecaseError    error
		code            codes.Code
	}

	data := []struct {
		name     string
		data     DataStruct
		expected ExpectedStruct
	}{
		{
			name: "success",
			data: DataStruct{token: token, userID: userID, chestRequest: chestRequeest},
			expected: ExpectedStruct{
				authError:       nil,
				extractingError: nil,
				composeError:    nil,
				usecaseError:    nil,
				code:            0,
			},
		},
		{
			name: "auth_error",
			data: DataStruct{token: "", userID: userID, chestRequest: chestRequeest},
			expected: ExpectedStruct{
				authError:       errors.New("auth error"),
				extractingError: nil,
				composeError:    nil,
				usecaseError:    nil,
				code:            codes.Unauthenticated,
			},
		},
		{
			name: "compose_error",
			data: DataStruct{token: token, userID: userID, chestRequest: badTimeChestRequeest},
			expected: ExpectedStruct{
				authError:       nil,
				extractingError: nil,
				composeError:    errors.New("compose error"),
				usecaseError:    nil,
				code:            codes.InvalidArgument,
			},
		},
		{
			name: "usecase_internal_error",
			data: DataStruct{token: token, userID: userID, chestRequest: chestRequeest},
			expected: ExpectedStruct{
				authError:       nil,
				extractingError: nil,
				composeError:    nil,
				usecaseError:    errors.New("usecase error"),
				code:            codes.Internal,
			},
		},
	}

	for _, d := range data {
		d := d
		t.Run(d.name, func(t *testing.T) {
			usecases := NewMockKeeperUseCases(t)
			service := New(usecases, defaultConfig, defaultLogger)

			if d.expected.authError == nil {
				mockHandleAuth(usecases, &d.data.userID, d.expected.authError)
			}

			if d.expected.authError == nil && d.expected.extractingError == nil && d.expected.composeError == nil {
				usecases.EXPECT().UpsertChest(mock.Anything, mock.AnythingOfType("*dto.Chest"), mock.AnythingOfType("*dto.History")).Return(expectedHistory, d.expected.usecaseError)
			}

			if d.expected.usecaseError != nil {
				mockHandlerUsecaseError(usecases, d.expected.code, d.expected.usecaseError)
			}

			server, cliCon, err := initKeeperService(service)
			require.NoError(t, err, "failed when init grpc server")
			defer server.Stop()
			defer cliCon.Close()
			cli := pb.NewKeeperClient(cliCon)

			authMd := metadata.Pairs("authorization", d.data.token)
			ctx := metadata.NewOutgoingContext(context.Background(), authMd)
			res, err := cli.UpdateChest(ctx, d.data.chestRequest)
			if d.expected.code == 0 {
				assert.NoError(t, err, "failed when add chest")
				assert.NotNil(t, res, "failed while expecting non nil response")
				assert.NotNil(t, res.History.SyncingTime, "failed while expecting non nil syncing time")
			} else {
				assert.Error(t, err, "failed while expecting error")
				assert.Nil(t, res, "failed while expecting nil response")
				s, ok := status.FromError(err)
				assert.True(t, ok, "failed while expecting status error")
				assert.Equal(t, d.expected.code, s.Code(), "failed while expecting status code")
			}
		})
	}
}

func TestDeleteChest(t *testing.T) {
	defaultLogger, err := zap.NewDevelopment()
	require.NoError(t, err, "failed when init logger")
	defaultConfig := &config.Config{}
	token := fmt.Sprintf("%s %s", authScheme, uuid.NewString())
	userID := uuid.New()
	deviceIP := "10.0.0.1"
	pbHistory := &pb.History{
		Id:            uuid.NewString(),
		ChestId:       uuid.NewString(),
		UserId:        asStringRef(userID.String()),
		OperationType: 2,
		OperationTime: time.Now().Unix(),
		SyncingTime:   nil,
		DeviceName:    "androidx",
		DeviceIp:      &deviceIP,
	}
	syncTime := time.Now()
	expectedHistory := &dto.History{
		ID:            pbHistory.Id,
		UserID:        userID,
		ChestID:       pbHistory.ChestId,
		OperationType: pbHistory.OperationType,
		OperationTime: time.Unix(pbHistory.OperationTime, 0),
		SyncingTime:   &syncTime,
		DeviceName:    pbHistory.DeviceName,
		DeviceIP:      deviceIP,
	}
	deleteChestReq := &pb.DeleteChestRequest{
		History: pbHistory,
	}
	badTimeHistory := *pbHistory
	badTimeHistory.OperationTime = time.Now().Add(48 * time.Hour).Unix()
	badDeleteChestReq := &pb.DeleteChestRequest{
		History: &badTimeHistory,
	}
	type DataStruct struct {
		token        string
		userID       uuid.UUID
		chestRequest *pb.DeleteChestRequest
	}

	type ExpectedStruct struct {
		authError       error
		extractingError error
		composeError    error
		usecaseError    error
		code            codes.Code
	}

	data := []struct {
		name     string
		data     DataStruct
		expected ExpectedStruct
	}{
		{
			name: "success",
			data: DataStruct{token: token, userID: userID, chestRequest: deleteChestReq},
			expected: ExpectedStruct{
				authError:       nil,
				extractingError: nil,
				composeError:    nil,
				usecaseError:    nil,
				code:            0,
			},
		},
		{
			name: "auth_error",
			data: DataStruct{token: "", userID: userID, chestRequest: deleteChestReq},
			expected: ExpectedStruct{
				authError:       errors.New("auth error"),
				extractingError: nil,
				composeError:    nil,
				usecaseError:    nil,
				code:            codes.Unauthenticated,
			},
		},
		{
			name: "compose_error",
			data: DataStruct{token: token, userID: userID, chestRequest: badDeleteChestReq},
			expected: ExpectedStruct{
				authError:       nil,
				extractingError: nil,
				composeError:    errors.New("compose error"),
				usecaseError:    nil,
				code:            codes.InvalidArgument,
			},
		},
		{
			name: "usecase_internal_error",
			data: DataStruct{token: token, userID: userID, chestRequest: deleteChestReq},
			expected: ExpectedStruct{
				authError:       nil,
				extractingError: nil,
				composeError:    nil,
				usecaseError:    errors.New("usecase error"),
				code:            codes.Internal,
			},
		},
	}

	for _, d := range data {
		d := d
		t.Run(d.name, func(t *testing.T) {
			usecases := NewMockKeeperUseCases(t)
			service := New(usecases, defaultConfig, defaultLogger)

			if d.expected.authError == nil {
				mockHandleAuth(usecases, &d.data.userID, d.expected.authError)
			}

			if d.expected.authError == nil && d.expected.extractingError == nil && d.expected.composeError == nil {
				usecases.EXPECT().DeleteChest(mock.Anything, mock.AnythingOfType("*dto.History")).Return(expectedHistory, d.expected.usecaseError)
			}

			if d.expected.usecaseError != nil {
				mockHandlerUsecaseError(usecases, d.expected.code, d.expected.usecaseError)
			}

			server, cliCon, err := initKeeperService(service)
			require.NoError(t, err, "failed when init grpc server")
			defer server.Stop()
			defer cliCon.Close()
			cli := pb.NewKeeperClient(cliCon)

			authMd := metadata.Pairs("authorization", d.data.token)
			ctx := metadata.NewOutgoingContext(context.Background(), authMd)
			res, err := cli.DeleteChest(ctx, d.data.chestRequest)
			if d.expected.code == 0 {
				assert.NoError(t, err, "failed when add chest")
				assert.NotNil(t, res, "failed while expecting non nil response")
				assert.NotNil(t, res.History.SyncingTime, "failed while expecting non nil syncing time")
			} else {
				assert.Error(t, err, "failed while expecting error")
				assert.Nil(t, res, "failed while expecting nil response")
				s, ok := status.FromError(err)
				assert.True(t, ok, "failed while expecting status error")
				assert.Equal(t, d.expected.code, s.Code(), "failed while expecting status code")
			}
		})
	}
}

func TestSync(t *testing.T) {
	defaultLogger, err := zap.NewDevelopment()
	require.NoError(t, err, "failed when init logger")
	defaultConfig := &config.Config{}
	token := fmt.Sprintf("%s %s", authScheme, uuid.NewString())
	userID := uuid.New()
	deviceIP := "10.0.0.1"
	pbHistory := &pb.History{
		Id:            uuid.NewString(),
		ChestId:       uuid.NewString(),
		UserId:        asStringRef(userID.String()),
		OperationType: 2,
		OperationTime: time.Now().Unix(),
		SyncingTime:   nil,
		DeviceName:    "androidx",
		DeviceIp:      &deviceIP,
	}
	pbHistory2 := &pb.History{
		Id:            uuid.NewString(),
		ChestId:       uuid.NewString(),
		UserId:        asStringRef(userID.String()),
		OperationType: 0,
		OperationTime: time.Now().Add(2 * time.Second).Unix(),
		SyncingTime:   nil,
		DeviceName:    "androidx",
		DeviceIp:      &deviceIP,
	}
	syncTime := time.Now()
	expectedHistory := &dto.History{
		ID:            pbHistory.Id,
		UserID:        userID,
		ChestID:       pbHistory.ChestId,
		OperationType: pbHistory.OperationType,
		OperationTime: time.Unix(pbHistory.OperationTime, 0),
		SyncingTime:   &syncTime,
		DeviceName:    pbHistory.DeviceName,
		DeviceIP:      deviceIP,
	}
	expectedSyncRequest := []*dto.History{expectedHistory}
	syncRequest := &pb.SyncRequest{
		History: []*pb.History{pbHistory, pbHistory2},
	}
	badTimeHistory := *pbHistory
	badTimeHistory.OperationTime = time.Now().Add(48 * time.Hour).Unix()
	syncRequestWithBadTime := &pb.SyncRequest{
		History: []*pb.History{pbHistory, &badTimeHistory},
	}

	type DataStruct struct {
		token  string
		userID uuid.UUID
		req    *pb.SyncRequest
	}

	type ExpectedStruct struct {
		authError       error
		extractingError error
		composeError    error
		usecaseError    error
		code            codes.Code
	}

	data := []struct {
		name     string
		data     DataStruct
		expected ExpectedStruct
	}{
		{
			name: "success",
			data: DataStruct{token: token, userID: userID, req: syncRequest},
			expected: ExpectedStruct{
				authError:       nil,
				extractingError: nil,
				composeError:    nil,
				usecaseError:    nil,
				code:            0,
			},
		},
		{
			name: "auth_error",
			data: DataStruct{token: "", userID: userID, req: syncRequest},
			expected: ExpectedStruct{
				authError:       errors.New("auth error"),
				extractingError: nil,
				composeError:    nil,
				usecaseError:    nil,
				code:            codes.Unauthenticated,
			},
		},
		{
			name: "compose_error",
			data: DataStruct{token: token, userID: userID, req: syncRequestWithBadTime},
			expected: ExpectedStruct{
				authError:       nil,
				extractingError: nil,
				composeError:    errors.New("compose error"),
				usecaseError:    nil,
				code:            codes.InvalidArgument,
			},
		},
		{
			name: "usecase_internal_error",
			data: DataStruct{token: token, userID: userID, req: syncRequest},
			expected: ExpectedStruct{
				authError:       nil,
				extractingError: nil,
				composeError:    nil,
				usecaseError:    errors.New("usecase error"),
				code:            codes.Internal,
			},
		},
	}

	for _, d := range data {
		d := d
		t.Run(d.name, func(t *testing.T) {
			usecases := NewMockKeeperUseCases(t)
			service := New(usecases, defaultConfig, defaultLogger)

			if d.expected.authError == nil {
				mockHandleAuth(usecases, &d.data.userID, d.expected.authError)
			}

			if d.expected.authError == nil && d.expected.extractingError == nil && d.expected.composeError == nil {
				usecases.EXPECT().Sync(mock.Anything, mock.AnythingOfType("[]*dto.History"), d.data.userID).Return(expectedSyncRequest, d.expected.usecaseError)
			}

			if d.expected.usecaseError != nil {
				mockHandlerUsecaseError(usecases, d.expected.code, d.expected.usecaseError)
			}

			server, cliCon, err := initKeeperService(service)
			require.NoError(t, err, "failed when init grpc server")
			defer server.Stop()
			defer cliCon.Close()
			cli := pb.NewKeeperClient(cliCon)

			authMd := metadata.Pairs("authorization", d.data.token)
			ctx := metadata.NewOutgoingContext(context.Background(), authMd)
			res, err := cli.Sync(ctx, d.data.req)
			if d.expected.code == 0 {
				assert.NoError(t, err, "failed when add chest")
				assert.NotNil(t, res, "failed while expecting non nil response")
				assert.Len(t, res.History, len(expectedSyncRequest), "failed while expecting history length")
			} else {
				assert.Error(t, err, "failed while expecting error")
				assert.Nil(t, res, "failed while expecting nil response")
				s, ok := status.FromError(err)
				assert.True(t, ok, "failed while expecting status error")
				assert.Equal(t, d.expected.code, s.Code(), "failed while expecting status code")
			}
		})
	}
}
