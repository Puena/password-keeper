package services

import (
	"context"
	"errors"
	"time"

	pb "github.com/Puena/password-keeper/proto"
	"github.com/Puena/password-keeper/server/config"
	"github.com/Puena/password-keeper/server/internal/dto"
	"github.com/google/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// userIDContextType is type for key in ctx for userID.
type userIDContextType string

const (
	authScheme         string            = "bearer"
	userAgentHeader    string            = "user-agent"
	xForwaredForHeader string            = "X-Forwared-For"
	remoteAddrHeader   string            = "RemoteAddr"
	userIDContextKey   userIDContextType = "ctx-user-id"
)

var methodsWithoutAuth = [2]string{
	"/" + pb.Keeper_ServiceDesc.ServiceName + "/SignUp",
	"/" + pb.Keeper_ServiceDesc.ServiceName + "/SignIn",
}

var (
	errBadUserCtx   = errors.New("can not extract user from context")
	errBadAuthToken = errors.New("bad authentification token")
)

// KeeperUseCases represent all used usecases by [KeeperService].
//
//go:generate mockery --name KeeperUseCases
type KeeperUseCases interface {
	// Auth usecases.
	SignUp(ctx context.Context, data dto.AuthDataDto) (*dto.AuthTokenDto, error)
	SignIn(ctx context.Context, data dto.AuthDataDto) (*dto.AuthTokenDto, error)
	Auth(ctx context.Context, token string) (*uuid.UUID, error)

	// Chests usecases.
	GetChestByID(ctx context.Context, chestID string, userID uuid.UUID) (*dto.Chest, *dto.History, error)
	AddChest(ctx context.Context, chest *dto.Chest, history *dto.History) (*dto.History, error)
	UpsertChest(ctx context.Context, chest *dto.Chest, history *dto.History) (*dto.History, error)
	DeleteChest(ctx context.Context, history *dto.History) (*dto.History, error)

	// History usecases.
	Sync(ctx context.Context, history []*dto.History, userID uuid.UUID) ([]*dto.History, error)

	// Common errors.
	ValidationError(err error) bool
	NotFoundError(err error) bool
	InternalError(err error) bool
	AuthentificationError(err error) bool
	ConflictError(err error) bool
	ExtractUserErrorMessage(err error) string
}

// KeeperService represent keeper grpc service.
type KeeperService struct {
	pb.UnimplementedKeeperServer

	usecase KeeperUseCases
	config  *config.Config
	logger  *zap.Logger
}

// New responsible for [KeeperService] initialization.
func New(
	usecase KeeperUseCases,
	config *config.Config,
	logger *zap.Logger,
) *KeeperService {

	return &KeeperService{
		usecase: usecase,
		config:  config,
		logger:  logger,
	}
}

// DoAuth filter function fot checking if method need auth.
func (s *KeeperService) DoAuth(ctx context.Context, callMeta interceptors.CallMeta) bool {
	for _, name := range methodsWithoutAuth {
		if callMeta.FullMethod() == name {
			return false
		}
	}
	return true
}

// AuthFunc interceptor for authentification.
func (s *KeeperService) AuthFunc(ctx context.Context) (context.Context, error) {
	token, err := auth.AuthFromMD(ctx, authScheme)
	if err != nil {
		s.logger.Error("authentification middleware error", zap.Error(err))
		return nil, status.Errorf(codes.Unauthenticated, errBadAuthToken.Error())
	}

	userID, err := s.usecase.Auth(ctx, token)
	if err != nil {
		s.logger.Error("authentification middleware error", zap.Error(err))
		return nil, s.handleUsecaseErrors(err)
	}

	newCtx := context.WithValue(ctx, userIDContextKey, userID)

	return newCtx, nil
}

// SignUp endpoit handle new user registration, can return ValidationError.
func (s *KeeperService) SignUp(ctx context.Context, data *pb.AuthDataRequest) (*pb.AuthTokenResponse, error) {

	res, err := s.usecase.SignUp(ctx, dto.AuthDataDto{
		Login:    data.Login,
		Password: data.Password,
	})
	if err != nil {
		s.logger.Info("sing up authentification error", zap.Error(err))
		return nil, s.handleUsecaseErrors(err)
	}

	return &pb.AuthTokenResponse{
		Token: res.Token,
	}, nil
}

// SignIn endpoint handle user authentification by login and password, can return ValidationError and AuthentificationError.
func (s *KeeperService) SignIn(ctx context.Context, data *pb.AuthDataRequest) (*pb.AuthTokenResponse, error) {

	res, err := s.usecase.SignIn(ctx, dto.AuthDataDto{
		Login:    data.Login,
		Password: data.Password,
	})
	if err != nil {
		s.logger.Info("sign in authentification error, while trying sign in", zap.Error(err))
		return nil, s.handleUsecaseErrors(err)
	}

	return &pb.AuthTokenResponse{
		Token: res.Token,
	}, nil
}

// GetChestByID endpoint handle chest retriving by id, return ChestResponse or error.
func (s *KeeperService) GetChestByID(ctx context.Context, data *pb.ChestIDRequest) (*pb.ChestResponse, error) {

	uid, err := extractUserIDFromCtx(ctx)
	if err != nil {
		s.logger.Info("get chest by id error, when extract user id from context", zap.Error(err))
		return nil, status.Errorf(codes.Unauthenticated, err.Error())
	}

	chest, history, err := s.usecase.GetChestByID(ctx, data.ChestId, *uid)
	if err != nil {
		s.logger.Info("get chest by id error, when trying get it", zap.Error(err))
		return nil, s.handleUsecaseErrors(err)
	}

	return composeChestResponseMessage(chest, history), nil
}

// AddChest grpc handler for adding new chest
func (s *KeeperService) AddChest(ctx context.Context, data *pb.ChestRequest) (*pb.HistoryResponse, error) {

	uid, err := extractUserIDFromCtx(ctx)
	if err != nil {
		s.logger.Info("add chest error while exctracting user id from context", zap.Error(err))
		return nil, status.Errorf(codes.Unauthenticated, err.Error())
	}

	deviceIP, err := extractUserIP(ctx)
	if err != nil {
		s.logger.Info("add chest error while exctracting user ip from context", zap.Error(err))
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	chestDto, historyDto, err := composeChestAndHistoryDto(data, uid, deviceIP)
	if err != nil {
		s.logger.Info("add chest error while composing chest and history dto from grpc message", zap.Error(err))
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	h, err := s.usecase.AddChest(ctx, chestDto, historyDto)
	if err != nil {
		s.logger.Info("add chest error while adding chest to database", zap.Error(err))
		return nil, s.handleUsecaseErrors(err)
	}

	return composeHistoryResponseMessage(h), nil
}

func (s *KeeperService) UpdateChest(ctx context.Context, data *pb.ChestRequest) (*pb.HistoryResponse, error) {

	uid, err := extractUserIDFromCtx(ctx)
	if err != nil {
		s.logger.Info("update chest error while exctracting user id from context", zap.Error(err))
		return nil, status.Errorf(codes.Unauthenticated, err.Error())
	}

	deviceIP, err := extractUserIP(ctx)
	if err != nil {
		s.logger.Info("update chest error while exctracting user ip from context", zap.Error(err))
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	chestDto, historyDto, err := composeChestAndHistoryDto(data, uid, deviceIP)
	if err != nil {
		s.logger.Info("update chest error while composing chest and history dto from grpc message", zap.Error(err))
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	h, err := s.usecase.UpsertChest(ctx, chestDto, historyDto)
	if err != nil {
		s.logger.Info("update chest error while udpating chest in database", zap.Error(err))
		return nil, s.handleUsecaseErrors(err)
	}

	return composeHistoryResponseMessage(h), nil
}

// DeleteChest delete user chest.
func (s *KeeperService) DeleteChest(ctx context.Context, data *pb.DeleteChestRequest) (*pb.HistoryResponse, error) {

	uid, err := extractUserIDFromCtx(ctx)
	if err != nil {
		s.logger.Info("delete chest error while exctracting user id from context", zap.Error(err))
		return nil, status.Errorf(codes.Unauthenticated, err.Error())
	}

	deviceIP, err := extractUserIP(ctx)
	if err != nil {
		s.logger.Info("delete chest error while exctracting user ip from context", zap.Error(err))
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	hDto, err := composeHistoryDto(data.History, uid, deviceIP)
	if err != nil {
		s.logger.Info("delete chest error while composing history dto from grpc message", zap.Error(err))
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	rDto, err := s.usecase.DeleteChest(ctx, hDto)
	if err != nil {
		s.logger.Info("delet chest error while deleting chest in database", zap.Error(err))
		return nil, s.handleUsecaseErrors(err)

	}

	return composeHistoryResponseMessage(rDto), nil
}

// Sync synchronize user histore events.
func (s *KeeperService) Sync(ctx context.Context, data *pb.SyncRequest) (*pb.SyncResponse, error) {
	uid, err := extractUserIDFromCtx(ctx)
	if err != nil {
		s.logger.Info("sync error while exctracting user id from context", zap.Error(err))
		return nil, status.Errorf(codes.Unauthenticated, err.Error())
	}

	deviceIP, err := extractUserIP(ctx)
	if err != nil {
		s.logger.Info("sync error while exctracting user ip from context", zap.Error(err))
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	var inHistory []*dto.History
	for _, h := range data.History {
		h := h
		hDto, err := composeHistoryDto(h, uid, deviceIP)
		if err != nil {
			s.logger.Info("sync error while composing history dto from grpc message", zap.Error(err))
			return nil, status.Errorf(codes.InvalidArgument, err.Error())
		}
		inHistory = append(inHistory, hDto)
	}

	outHistory, err := s.usecase.Sync(ctx, inHistory, *uid)
	if err != nil {
		s.logger.Info("sync error while trying sync history from database", zap.Error(err))
		return nil, s.handleUsecaseErrors(err)
	}

	var respHistory []*pb.History
	for _, h := range outHistory {
		h := h
		respHistory = append(respHistory, composeHistoryMessage(h))
	}

	return &pb.SyncResponse{
		History: respHistory,
	}, nil
}

// composeHistoryResponseMessage map to protobuf HistoryResponse.
func composeHistoryResponseMessage(h *dto.History) *pb.HistoryResponse {
	return &pb.HistoryResponse{
		History: composeHistoryMessage(h),
	}
}

func composeHistoryMessage(h *dto.History) *pb.History {
	history := &pb.History{
		Id:            h.ID,
		ChestId:       h.ChestID,
		UserId:        asStringRef(h.UserID.String()),
		OperationType: h.OperationType,
		OperationTime: h.OperationTime.Unix(),
		DeviceName:    h.DeviceName,
		DeviceIp:      &h.DeviceIP,
	}
	if h.SyncingTime != nil {
		history.SyncingTime = asInt64Ref(h.SyncingTime.Unix())
	}
	return history

}

func composeHistoryDto(message *pb.History, userID *uuid.UUID, deviceIP string) (*dto.History, error) {
	operationTime := time.Unix(message.OperationTime, 0)
	if operationTime.After(time.Now().Add(24 * time.Hour)) {
		return nil, errors.New("operation time cannot be in future")
	}
	var syncingTime *time.Time
	if message.SyncingTime != nil {
		t := time.Unix(*message.SyncingTime, 0)
		syncingTime = &t
	}

	return &dto.History{
		ID:            message.Id,
		UserID:        *userID,
		ChestID:       message.ChestId,
		OperationType: message.OperationType,
		OperationTime: operationTime,
		SyncingTime:   syncingTime,
		DeviceName:    message.DeviceName,
		DeviceIP:      deviceIP,
	}, nil
}

// extractUserIP from ctx peer.
func extractUserIP(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New("cannot extract user ip from peer context")
	}
	return p.Addr.String(), nil
}

// ExtractUserIDFromCtx trying to extract user from context and check that this is uuid.
func extractUserIDFromCtx(ctx context.Context) (*uuid.UUID, error) {
	id, ok := ctx.Value(userIDContextKey).(*uuid.UUID)
	if !ok {
		return nil, errBadUserCtx
	}
	return id, nil
}

// asStringRef return ref to string.
func asStringRef(str string) *string {
	return &str
}

// asInt64Ref return ref to int64.
func asInt64Ref(i int64) *int64 {
	return &i
}

// composeChestResponseMessage accept dto.Chest and dto.History and return pb.ChestResponse.
func composeChestResponseMessage(chest *dto.Chest, history *dto.History) *pb.ChestResponse {
	return &pb.ChestResponse{
		Chest: &pb.Chest{
			Id:        chest.ID,
			Salt:      chest.Salt,
			Name:      chest.Name,
			Data:      chest.Data,
			DatatType: chest.DataType,
		},
		History: &pb.History{
			Id:            history.ID,
			ChestId:       history.ChestID,
			UserId:        asStringRef(history.UserID.String()),
			OperationType: history.OperationType,
			OperationTime: history.OperationTime.Unix(),
			SyncingTime:   asInt64Ref(history.SyncingTime.Unix()),
			DeviceName:    history.DeviceName,
			DeviceIp:      asStringRef(history.DeviceIP),
		},
	}
}

// composeChestAndHistoryDto accept pb.ChestRequest and return dto.Chest, dto.History.
func composeChestAndHistoryDto(message *pb.ChestRequest, userID *uuid.UUID, deviceIP string) (*dto.Chest, *dto.History, error) {
	chest := &dto.Chest{
		ID:       message.Chest.Id,
		UserID:   asStringRef(userID.String()),
		Salt:     message.Chest.Salt,
		Name:     message.Chest.Name,
		Data:     message.Chest.Data,
		DataType: message.Chest.DatatType,
	}
	operationTime := time.Unix(message.History.OperationTime, 0)
	if operationTime.After(time.Now().Add(24 * time.Hour)) {
		return nil, nil, errors.New("operation time is in future")
	}
	history := &dto.History{
		ID:            message.History.Id,
		UserID:        *userID,
		ChestID:       message.History.ChestId,
		OperationType: message.History.OperationType,
		OperationTime: operationTime,
		DeviceName:    message.History.DeviceName,
		DeviceIP:      deviceIP,
	}
	return chest, history, nil
}

func (s *KeeperService) handleUsecaseErrors(err error) error {
	if s.usecase.ValidationError(err) {
		return status.Errorf(codes.InvalidArgument, s.usecase.ExtractUserErrorMessage(err))
	}

	if s.usecase.NotFoundError(err) {
		return status.Errorf(codes.NotFound, s.usecase.ExtractUserErrorMessage(err))
	}

	if s.usecase.InternalError(err) {
		return status.Errorf(codes.Internal, s.usecase.ExtractUserErrorMessage(err))
	}

	if s.usecase.AuthentificationError(err) {
		return status.Errorf(codes.Unauthenticated, s.usecase.ExtractUserErrorMessage(err))
	}

	if s.usecase.ConflictError(err) {
		return status.Errorf(codes.AlreadyExists, s.usecase.ExtractUserErrorMessage(err))
	}

	return status.Errorf(codes.Internal, s.usecase.ExtractUserErrorMessage(err))
}
