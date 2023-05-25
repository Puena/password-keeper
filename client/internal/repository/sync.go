package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/models"
	pb "github.com/Puena/password-keeper/proto"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	authScheme = "bearer"
	auhtHeader = "authorization"
)

var (
	ErrGrpcConnectionNotEstablished = errors.New("grpc connection not established")
)

//go:generate mockery --name syncClient --dir=repository --output=repository/mocks --outpkg=mocks
type syncClient interface {
	pb.KeeperClient
}

type syncRepositoryError struct {
	*baseRepositoryError
}

func newSyncRepositoryError(message string, err error) *syncRepositoryError {
	return &syncRepositoryError{
		newBaseRepositoryError(message, err),
	}
}

func (e syncRepositoryError) Error() string {
	return fmt.Sprintf("sync respository error: %s, %s", e.message, e.err)
}

type syncRepository struct {
	conn   *grpc.ClientConn
	client syncClient
	config *config.Config
	logger *zap.Logger
}

func NewSyncRepository(config *config.Config, logger *zap.Logger) *syncRepository {
	return &syncRepository{
		config: config,
		logger: logger,
	}
}

// SetClient set client for repository.
func (r *syncRepository) SetClient(client syncClient) {
	r.client = client
}

// AuthClientUnaryInterceptor add auth token to grpc request.
func authClientUnaryInterceptor(authToken string) func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		data := metadata.Pairs(auhtHeader, fmt.Sprintf("%s %s", authScheme, authToken))
		ctx = metadata.NewOutgoingContext(ctx, data)
		err := invoker(ctx, method, req, reply, cc, opts...)
		return err
	}
}

// EstablishConnection create grpc connection and client.
func (r *syncRepository) EstablishConnection(authToken string) error {
	if r.client != nil {
		return nil
	}

	buildInfo := r.config.GetBuildInfo()
	cert, err := credentials.NewClientTLSFromFile(buildInfo.CertFile, buildInfo.Host)
	if err != nil {
		return newSyncRepositoryError("failed while creating tls credentials, bad certificate, try to update program", err)
	}
	conn, err := grpc.Dial(r.config.GetBuildInfo().Host, grpc.WithTransportCredentials(cert), grpc.WithUnaryInterceptor(authClientUnaryInterceptor(authToken)))
	if err != nil {
		return newSyncRepositoryError("failed while creating grpc connection", err)
	}
	r.conn = conn
	r.client = pb.NewKeeperClient(conn)
	return nil
}

// CloseConnection close grpc connection.
func (r *syncRepository) CloseConnection() error {
	if r.conn == nil {
		return nil
	}
	err := r.conn.Close()
	if err != nil {
		return newSyncRepositoryError("failed while closing grpc connection", err)
	}
	return nil
}

// Authentification perform user authentification through grpc and get auth token as result.
func (r *syncRepository) Authentification(ctx context.Context, data *models.AuthData) (string, error) {

	res, err := r.client.SignIn(ctx, &pb.AuthDataRequest{
		Login:    data.Login,
		Password: data.Password,
	})
	if err != nil {
		return "", newSyncRepositoryError("failed while doing SignIn", err)
	}
	return res.Token, nil
}

// Registration perform user registration through grpc and get auth token as result.
func (r *syncRepository) Registration(ctx context.Context, data *models.AuthData) (string, error) {

	res, err := r.client.SignUp(ctx, &pb.AuthDataRequest{
		Login:    data.Login,
		Password: data.Password,
	})
	if err != nil {
		return "", newSyncRepositoryError("failed while doing SignUp", err)
	}

	return res.Token, nil
}

// GetChestByID extract chest with last corresonding history event.
func (r *syncRepository) GetChestByID(ctx context.Context, chestID string) (*models.Chest, *models.History, error) {

	res, err := r.client.GetChestByID(ctx, &pb.ChestIDRequest{
		ChestId: chestID,
	})
	if err != nil {
		return nil, nil, newSyncRepositoryError("failed while getting chest by id", err)
	}

	chest := composeChestModel(res.Chest)
	history := composeHistoryModel(res.History)
	return chest, history, nil
}

func (r *syncRepository) AddChest(ctx context.Context, chest *models.Chest, history *models.History) (*models.History, error) {

	res, err := r.client.AddChest(ctx, &pb.ChestRequest{
		Chest:   composeChestMessage(chest),
		History: composeHistoryMessage(history),
	})
	if err != nil {
		return nil, newSyncRepositoryError("failed while adding chest", err)
	}

	return composeHistoryModel(res.History), nil
}

func (r *syncRepository) UpdateChest(ctx context.Context, chest *models.Chest, history *models.History) (*models.History, error) {

	res, err := r.client.UpdateChest(ctx, &pb.ChestRequest{
		Chest:   composeChestMessage(chest),
		History: composeHistoryMessage(history),
	})
	if err != nil {
		return nil, newSyncRepositoryError("failed while updating chest", err)
	}

	return composeHistoryModel(res.History), nil
}

// DeleteChest delete chest transfer last history event.
func (r *syncRepository) DeleteChest(ctx context.Context, history *models.History) (*models.History, error) {

	res, err := r.client.DeleteChest(ctx, &pb.DeleteChestRequest{
		History: composeHistoryMessage(history),
	})
	if err != nil {
		return nil, newSyncRepositoryError("failed while deleting chest", err)
	}

	return composeHistoryModel(res.History), nil
}

// Sync send history to server and get new history for syncing.
func (r *syncRepository) Sync(ctx context.Context, history []*models.History) ([]*models.History, error) {

	var inHistory []*pb.History
	for _, h := range history {
		inHistory = append(inHistory, composeHistoryMessage(h))
	}
	res, err := r.client.Sync(ctx, &pb.SyncRequest{
		History: inHistory,
	})

	if err != nil {
		return nil, newSyncRepositoryError("failed while syncing", err)
	}

	var outHistory []*models.History
	for _, h := range res.History {
		outHistory = append(outHistory, composeHistoryModel(h))
	}

	return outHistory, nil
}

// IsAuthentificationError check if error is authentification error.
func (r *syncRepository) IsAuthentificationError(err error) bool {
	var srerr *syncRepositoryError
	if !errors.As(err, &srerr) {
		return false
	}

	s, ok := status.FromError(err)
	if !ok {
		return false
	}

	return codes.Unauthenticated == s.Code()
}

// IsNotFoundError chest if error is not found error.
func (r *syncRepository) IsNotFoundError(err error) bool {
	var srerr *syncRepositoryError
	if !errors.As(err, &srerr) {
		return false
	}

	s, ok := status.FromError(err)
	if !ok {
		return false
	}

	return codes.NotFound == s.Code()
}

// BadUserDataError check if error is bad user data error.
func (r *syncRepository) BadUserDataError(err error) error {
	var srerr *syncRepositoryError
	if !errors.As(err, &srerr) {
		return nil
	}

	s, ok := status.FromError(err)
	if ok && codes.InvalidArgument == s.Code() {
		return srerr.Unwrap()
	}

	return nil
}

// IsConnectionError check if error is connection error.
func (r *syncRepository) IsConnectionError(err error) bool {
	var srerr *syncRepositoryError
	if !errors.As(err, &srerr) {
		return false
	}

	s, ok := status.FromError(srerr.Unwrap())
	if !ok {
		return false
	}

	return codes.Unavailable == s.Code()
}

// IsDataAlreadyExistsError check if error is data already exists error.
func (r *syncRepository) IsDataAlreadyExistsError(err error) bool {
	var srerr *syncRepositoryError
	if !errors.As(err, &srerr) {
		return false
	}

	s, ok := status.FromError(err)
	if !ok {
		return false
	}

	return codes.AlreadyExists == s.Code()
}

func composeChestMessage(model *models.Chest) *pb.Chest {
	return &pb.Chest{
		Id:        model.ID,
		UserId:    model.UserID,
		Salt:      model.Salt,
		Name:      model.Name,
		Data:      model.Data,
		DatatType: int32(model.DataType),
	}
}

func composeHistoryMessage(model *models.History) *pb.History {
	return &pb.History{
		Id:            model.ID,
		ChestId:       model.ChestID,
		UserId:        model.UserID,
		OperationType: int32(model.OperationType),
		OperationTime: model.OperationTime,
		SyncingTime:   model.SyncingTime,
		DeviceName:    model.DeviceName,
		DeviceIp:      model.DeviceIP,
	}
}

func composeChestModel(message *pb.Chest) *models.Chest {
	return &models.Chest{
		ID:       message.Id,
		UserID:   message.UserId,
		Salt:     message.Salt,
		Name:     message.Name,
		Data:     message.Data,
		DataType: models.ChestDataType(message.DatatType),
	}
}

func composeHistoryModel(message *pb.History) *models.History {
	return &models.History{
		ID:            message.Id,
		ChestID:       message.ChestId,
		UserID:        message.UserId,
		OperationType: models.HistoryOperationType(message.OperationType),
		OperationTime: message.OperationTime,
		SyncingTime:   message.SyncingTime,
		DeviceName:    message.DeviceName,
		DeviceIP:      message.DeviceIp,
	}
}
