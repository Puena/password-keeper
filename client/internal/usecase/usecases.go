package usecase

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/models"
	"github.com/google/uuid"
	"github.com/pelletier/go-toml/v2"
	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"
)

const (
	maxFileSize = 5 << 20 // 5 MB
)

//go:generate mockery --name UsecasesRepositories
type UsecasesRepositories interface {
	Viper() ViperRepository
	Crypto() EncryptionRepository
	Storage() StorageRepostiory
	Device() DeviceRepository
	Sync() SyncRepository
}

//go:generate mockery --name ViperRepository
type ViperRepository interface {
	SetToken(token string) error
	GetToken() string
	SetLogin(login string) error
	// Errors
	IsWriteConfigError(err error) bool
}

//go:generate mockery --name EncryptionRepository
type EncryptionRepository interface {
	GenerateSalt() ([]byte, error)
	GenerateLock(salt []byte, password string) []byte
	LockData(data []byte, lock []byte) ([]byte, error)
	UnlockData(data []byte, lock []byte) ([]byte, error)
	// Errors
	IsBadUserData(err error) bool
}

//go:generate mockery --name StorageRepostiory
type StorageRepostiory interface {
	SelectChestAndHistoryByID(ctx context.Context, chestID string) (chest *models.Chest, history []*models.History, err error)
	Insert(ctx context.Context, chest *models.Chest, history *models.History) error
	Upsert(ctx context.Context, chest *models.Chest, history *models.History) error
	Update(ctx context.Context, chest *models.Chest, history *models.History) error
	Delete(ctx context.Context, chestID string, history *models.History) error
	SelectIdNameTypeChests(ctx context.Context) (chests []*models.Chest, err error)
	SelectChestByName(ctx context.Context, name string) (chest *models.Chest, err error)
	SelectLastHistoryEventForAllChests(ctx context.Context) (history []*models.History, err error)
	UpdateHistorySyncData(ctx context.Context, history *models.History) error
	// Errors
	IsConfictError(err error) bool
	IsNotFoundError(err error) bool
}

//go:generate mockery --name DeviceRepository
type DeviceRepository interface {
	ExtractDeviceName() (*models.DeviceInfo, error)
}

//go:generate mockery --name SyncRepository
type SyncRepository interface {
	EstablishConnection(authToken string) error
	CloseConnection() error
	Authentification(ctx context.Context, data *models.AuthData) (string, error)
	Registration(ctx context.Context, data *models.AuthData) (string, error)
	GetChestByID(ctx context.Context, chestID string) (*models.Chest, *models.History, error)
	AddChest(ctx context.Context, chest *models.Chest, history *models.History) (*models.History, error)
	UpdateChest(ctx context.Context, chest *models.Chest, history *models.History) (*models.History, error)
	DeleteChest(ctx context.Context, history *models.History) (*models.History, error)
	Sync(ctx context.Context, history []*models.History) ([]*models.History, error)
	// Errors
	BadUserDataError(err error) error
	IsNotFoundError(err error) bool
	IsAuthentificationError(err error) bool
	IsConnectionError(err error) bool
	IsDataAlreadyExistsError(err error) bool
}

type usecasesErrorType int

const (
	internalUsecaseError usecasesErrorType = iota
	badDataUsecaseError
	conflictUsecaseError
	authentificationUsecaseError
	notFoundUsecaseError
)

type usecasesError struct {
	message string
	errType usecasesErrorType
	err     error
}

type usecases struct {
	logger               *zap.Logger
	config               *config.Config
	viper                ViperRepository
	encryption           EncryptionRepository
	storage              StorageRepostiory
	device               DeviceRepository
	sync                 SyncRepository
	backgroundTasksLimit int64
}

// NewUsecases create usecases.
func NewUsecases(repositories UsecasesRepositories, config *config.Config, logger *zap.Logger) *usecases {
	vCfg, _ := config.ReadViperConfig()
	return &usecases{
		logger:               logger,
		config:               config,
		viper:                repositories.Viper(),
		encryption:           repositories.Crypto(),
		storage:              repositories.Storage(),
		device:               repositories.Device(),
		sync:                 repositories.Sync(),
		backgroundTasksLimit: int64(vCfg.BackgroundTasksLimit),
	}
}

func composeHistoryModel(chestID string, operationType models.HistoryOperationType, deviceName string) *models.History {
	return &models.History{
		ID:            uuid.NewString(),
		ChestID:       chestID,
		OperationType: operationType,
		OperationTime: time.Now().UTC().Unix(),
		DeviceName:    deviceName,
	}
}

// encryptData perform data encryption, and return encrypted data and salt.
// If salt is empty, it will be generated.
func (c *usecases) encryptData(data []byte, salt []byte, lockPassword string) (encryptedData []byte, outSalt []byte, err error) {
	if len(salt) == 0 {
		salt, err = c.encryption.GenerateSalt()
		if err != nil {
			return nil, nil, NewUsecaseError("failed while generate salt", internalUsecaseError, err)
		}
	}
	outSalt = salt

	lock := c.encryption.GenerateLock(salt, lockPassword)

	encryptedData, err = c.encryption.LockData(data, lock)
	if err != nil {
		return nil, nil, NewUsecaseError("failed while encrypt data", internalUsecaseError, err)
	}

	return
}

// AddChest perform data encryption and save it to storage.
func (c *usecases) AddChest(ctx context.Context, name string, data []byte, dataType models.ChestDataType, lockPassword string) error {
	if lockPassword == "" {
		return NewUsecaseError("lock password can not be empty", badDataUsecaseError, errors.New("empty lock password"))
	}

	if data == nil {
		return NewUsecaseError("data can not be empty", badDataUsecaseError, errors.New("empty user data"))
	}

	encryptedData, salt, err := c.encryptData(data, nil, lockPassword)
	if err != nil {
		return NewUsecaseError("failed while encryp data", internalUsecaseError, err)
	}

	chest := &models.Chest{
		ID:       uuid.NewString(),
		Salt:     salt,
		Name:     name,
		Data:     encryptedData,
		DataType: dataType,
	}

	devName, err := c.device.ExtractDeviceName()
	if err != nil {
		return NewUsecaseError("failed while extract device name", internalUsecaseError, err)
	}
	history := composeHistoryModel(chest.ID, models.HistoryCreateOperation, devName.Name)

	err = c.storage.Insert(ctx, chest, history)
	if err != nil {
		return c.handleStorageErrors(err)
	}

	return nil
}

// handleCardUpdate function that perform card data update.
// If new data is nil, it will return old data.
// It return updated data.
func handleCardUpdate(dataType models.ChestDataType, updateData []byte, newData []byte) ([]byte, error) {
	if dataType != models.ChestCreditCardData {
		return nil, NewUsecaseError("data type is not card", badDataUsecaseError, errors.New("data type is not card"))
	}
	if newData == nil {
		return updateData, nil
	}

	updateCard, err := bytesToCard(updateData)
	if err != nil {
		return nil, err
	}
	newCard, err := bytesToCard(newData)
	if err != nil {
		return nil, err
	}

	if newCard.Number != "" {
		updateCard.Number = newCard.Number
	}
	if newCard.Owner != "" {
		updateCard.Owner = newCard.Owner
	}
	if newCard.Cvv != "" {
		updateCard.Cvv = newCard.Cvv
	}
	if newCard.Expired != "" {
		updateCard.Expired = newCard.Expired
	}

	return cardToBytes(updateCard)
}

// handlePasswordUpdate function that perform password update.
// If new data is nil, it will return old data.
func handlePasswordUpdate(dataType models.ChestDataType, updateData []byte, newData []byte) ([]byte, error) {
	if newData == nil {
		return updateData, nil
	}
	if dataType != models.ChestPasswordData {
		return nil, NewUsecaseError("data type is not password", badDataUsecaseError, errors.New("data type is not password"))
	}
	return newData, nil
}

// handleFileUpdate function that perform file update.
// if new data is nil, it will return old data.
func handleFileUpdate(dataType models.ChestDataType, updateData []byte, newData []byte) ([]byte, error) {
	if dataType != models.ChestFileData {
		return nil, NewUsecaseError("data type is not file", badDataUsecaseError, errors.New("data type is not file"))
	}
	if newData == nil {
		return updateData, nil
	}
	return newData, nil
}

// EditChest perform data encryption and save it to storage.
// If newName is empty, name will not be changed.
// If newData is empty, data will not be changed.
// handleData is a function that will be called to handle data update.
func (c *usecases) EditChest(ctx context.Context, name string, newName string, newData []byte, lockPassword string, handleData func(dataType models.ChestDataType, updateData []byte, newData []byte) ([]byte, error)) error {
	chest, err := c.GetChestByName(ctx, name, lockPassword)
	if err != nil {
		return err
	}

	updatedData, err := handleData(chest.DataType, chest.Data, newData)
	if err != nil {
		return err
	}

	encrypted, salt, err := c.encryptData(updatedData, chest.Salt, lockPassword)
	if err != nil {
		return err
	}

	chest.Salt = salt
	chest.Data = encrypted

	if newName != "" {
		chest.Name = newName
	}

	device, err := c.device.ExtractDeviceName()
	if err != nil {
		return NewUsecaseError("failed while extract device name", internalUsecaseError, err)
	}

	history := composeHistoryModel(chest.ID, models.HistoryUpdateOperation, device.Name)

	err = c.storage.Update(ctx, chest, history)
	if err != nil {
		return c.handleStorageErrors(err)
	}
	return nil
}

// Delete remove chest by name from storage, only if lock password is correct, then do corresponding event in history.
func (c *usecases) DeleteChest(ctx context.Context, name string, lockPassword string) error {
	if name == "" {
		return NewUsecaseError("name can not be empty", badDataUsecaseError, errors.New("empty name"))
	}

	chest, err := c.storage.SelectChestByName(ctx, name)
	if err != nil {
		return NewUsecaseError("failed while trying to find chest by name", internalUsecaseError, err)
	}

	lock := c.encryption.GenerateLock(chest.Salt, lockPassword)
	_, err = c.encryption.UnlockData(chest.Data, lock)
	if err != nil {
		return NewUsecaseError("bad auth data provided", badDataUsecaseError, err)
	}

	dev, err := c.device.ExtractDeviceName()
	if err != nil {
		return NewUsecaseError("failed while trying extract device info", internalUsecaseError, err)
	}

	history := composeHistoryModel(chest.ID, models.HistoryDeleteOperation, dev.Name)

	err = c.storage.Delete(ctx, chest.ID, history)
	if err != nil {
		return NewUsecaseError("failed while trying delete chest", internalUsecaseError, err)
	}

	return nil
}

// Sync syncronize data with remote server.
// statusOutput is optional parameter, if it is not nil, it will be used to print sync status.
func (c *usecases) Sync(ctx context.Context, statusOutput io.Writer) error {
	token := c.viper.GetToken()
	if token == "" {
		return NewUsecaseError("before sync you shoud authentificate to your accout", authentificationUsecaseError, errors.New("token is empty"))
	}

	history, err := c.storage.SelectLastHistoryEventForAllChests(ctx)
	if err != nil {
		return NewUsecaseError("failed while selecting last history event for all chests", internalUsecaseError, err)
	}

	err = c.sync.EstablishConnection(token)
	if err != nil {
		return c.handleSyncErrors(err)
	}
	defer c.sync.CloseConnection()

	remoteHistory, err := c.sync.Sync(ctx, history)
	if err != nil {
		return c.handleSyncErrors(err)
	}

	errs := c.backgroundTasks(ctx, remoteHistory, statusOutput)

	for _, e := range errs {
		if e != nil {
			err = errors.Join(e, err)
		}
	}
	return err
}

func (c *usecases) backgroundTasks(ctx context.Context, history []*models.History, status io.Writer) []error {
	var errors []error
	var completed int64
	total := len(history)
	semo := semaphore.NewWeighted(c.backgroundTasksLimit)

	for _, h := range history {
		h := h
		err := semo.Acquire(ctx, 1)
		if err != nil {
			errors = append(errors, NewUsecaseError("failed while do background task, try again later", internalUsecaseError, err))
			break
		}

		go func() {
			defer semo.Release(1)
			err = c.handleSyncHistory(ctx, h)
			if err != nil {
				errors = append(errors, err)
			}
			done := atomic.AddInt64(&completed, 1)
			status.Write([]byte(fmt.Sprintf("\rProcessed %d/%d ", done, total)))
		}()
	}
	// wait for all tasks
	err := semo.Acquire(ctx, c.backgroundTasksLimit)
	if err != nil {
		errors = append(errors, NewUsecaseError("failed while waiting background tasks, try again later", internalUsecaseError, err))
	}
	semo.Release(c.backgroundTasksLimit)

	return errors
}

// GetToken return saved token, can return empty string.
func (c *usecases) GetToken() string {
	return c.viper.GetToken()
}

// Authentification authentificate user by login and password, save token in local storage.
func (c *usecases) Authentification(ctx context.Context, login string, password string) error {
	if password == "" {
		return NewUsecaseError("password can not be empty", badDataUsecaseError, errors.New("empty password"))
	}
	if login == "" {
		return NewUsecaseError("login can not be empty", badDataUsecaseError, errors.New("empty login"))
	}

	err := c.sync.EstablishConnection("")
	if err != nil {
		return c.handleSyncErrors(err)
	}
	defer c.sync.CloseConnection()

	token, err := c.sync.Authentification(ctx, &models.AuthData{
		Login:    login,
		Password: password,
	})
	if err != nil {
		return c.handleSyncErrors(err)
	}

	err = c.viper.SetToken(token)
	if err != nil {
		return NewUsecaseError("failed while trying to save token", internalUsecaseError, err)
	}

	err = c.viper.SetLogin(login)
	if err != nil {
		return NewUsecaseError("failed while trying to save login", internalUsecaseError, err)
	}

	return nil
}

// Registration register new user on remote server and save token in local storage.
func (c *usecases) Registration(ctx context.Context, login string, password string) error {
	if login == "" {
		return NewUsecaseError("login can not be empty", badDataUsecaseError, errors.New("empty login"))
	}
	if password == "" {
		return NewUsecaseError("password can not be empty", badDataUsecaseError, errors.New("empty password"))
	}

	err := c.sync.EstablishConnection("")
	if err != nil {
		return c.handleSyncErrors(err)
	}
	defer c.sync.CloseConnection()

	token, err := c.sync.Registration(ctx, &models.AuthData{
		Login:    login,
		Password: password,
	})
	if err != nil {
		return c.handleSyncErrors(err)
	}

	err = c.viper.SetToken(token)
	if err != nil {
		return NewUsecaseError("failed while trying to save token", internalUsecaseError, err)
	}

	err = c.viper.SetLogin(login)
	if err != nil {
		return NewUsecaseError("failed while trying to save login", internalUsecaseError, err)
	}

	return nil
}

func (c *usecases) handleSyncErrors(err error) error {
	if err == nil {
		return nil
	}

	if c.sync.IsAuthentificationError(err) {
		return NewUsecaseError("you are not authentificated, please do it.", authentificationUsecaseError, err)
	}
	if berr := c.sync.BadUserDataError(err); berr != nil {
		return NewUsecaseError(fmt.Sprintf("bad user data provided %s", berr), badDataUsecaseError, err)
	}
	if c.sync.IsConnectionError(err) {
		return NewUsecaseError("failed while trying to establish connection with remote server, chest your internet connection", authentificationUsecaseError, err)
	}
	if c.sync.IsDataAlreadyExistsError(err) {
		return NewUsecaseError("data with this id already exists", conflictUsecaseError, err)
	}
	if c.sync.IsNotFoundError(err) {
		return NewUsecaseError("this data not found", badDataUsecaseError, err)
	}
	return NewUsecaseError("failed while trying to add chest to remote server", internalUsecaseError, err)
}

func (c *usecases) handleStorageErrors(err error) error {
	if err == nil {
		return nil
	}

	if c.storage.IsNotFoundError(err) {
		return NewUsecaseError("data not found", notFoundUsecaseError, err)
	}
	if c.storage.IsConfictError(err) {
		return NewUsecaseError("data already exists", conflictUsecaseError, err)
	}
	return NewUsecaseError("internal database error", internalUsecaseError, err)
}

func (c *usecases) handleEncryptionErrors(err error) error {
	if err == nil {
		return nil
	}

	if c.encryption.IsBadUserData(err) {
		return NewUsecaseError("invalid lock password", badDataUsecaseError, err)
	}
	return NewUsecaseError("internal error while trying to unlock data", internalUsecaseError, err)
}

// handleSyncHistory helper function for handling sync history, we need auth context and remote history for input.
func (c *usecases) handleSyncHistory(ctx context.Context, history *models.History) error {
	// If we got syncing time nil from remote server history then our data is newest than server.
	if history.SyncingTime == nil {
		return c.handleSyncHistoryRemote(ctx, history)
	}

	return c.handSyncHistoryLocal(ctx, history)
}

func (c *usecases) handleSyncHistoryRemote(ctx context.Context, history *models.History) error {
	switch history.OperationType {
	case models.HistoryCreateOperation: // Create operation
		chest, history, err := c.storage.SelectChestAndHistoryByID(ctx, history.ChestID)
		if err != nil {
			return c.handleStorageErrors(err)
		}
		remoteHistory, err := c.sync.AddChest(ctx, chest, history[0])
		if err != nil {
			return c.handleSyncErrors(err)
		}

		if remoteHistory.SyncingTime == nil {
			return NewUsecaseError("syncing time can not be nil, bad data from server", internalUsecaseError, errors.New("server error: syncing time is nil"))
		}
		err = c.storage.UpdateHistorySyncData(ctx, remoteHistory)
		if err != nil {
			return c.handleStorageErrors(err)
		}
	case models.HistoryUpdateOperation: // Update operation
		chest, history, err := c.storage.SelectChestAndHistoryByID(ctx, history.ChestID)
		if err != nil {
			return c.handleStorageErrors(err)
		}
		remoteHistory, err := c.sync.UpdateChest(ctx, chest, history[0])
		if err != nil {
			return c.handleSyncErrors(err)
		}
		if remoteHistory.SyncingTime == nil {
			return NewUsecaseError("syncing time can not be nil, bad data from server", internalUsecaseError, errors.New("server error: syncing time is nil"))
		}
		err = c.storage.UpdateHistorySyncData(ctx, remoteHistory)
		if err != nil {
			return c.handleStorageErrors(err)
		}
	case models.HistoryDeleteOperation: // Delete operation
		remoteHistory, err := c.sync.DeleteChest(ctx, history)
		if err != nil {
			return c.handleSyncErrors(err)
		}
		if remoteHistory.SyncingTime == nil {
			return NewUsecaseError("syncing time can not be nil, bad data from server", internalUsecaseError, errors.New("server error: syncing time is nil"))
		}
		err = c.storage.UpdateHistorySyncData(ctx, remoteHistory)
		if err != nil {
			return c.handleStorageErrors(err)
		}
	}
	return nil
}

func (c *usecases) handSyncHistoryLocal(ctx context.Context, history *models.History) error {
	switch history.OperationType {
	case models.HistoryCreateOperation: // Create operation
		remoteChest, remoteHistory, err := c.sync.GetChestByID(ctx, history.ChestID)
		if err != nil {
			return c.handleSyncErrors(err)
		}

		err = c.storage.Insert(ctx, remoteChest, remoteHistory)
		if err != nil {
			return NewUsecaseError("failed while trying to insert chest and history", internalUsecaseError, err)
		}
	case models.HistoryUpdateOperation: // Update operation
		remoteChest, remoteHistory, err := c.sync.GetChestByID(ctx, history.ChestID)
		if err != nil {
			return c.handleSyncErrors(err)
		}

		err = c.storage.Upsert(ctx, remoteChest, remoteHistory)
		if err != nil {
			return NewUsecaseError("failed while trying to insert chest and history", internalUsecaseError, err)
		}
	case models.HistoryDeleteOperation: // Delete operation
		err := c.storage.Delete(ctx, history.ChestID, history)
		// Ignore if not found.
		if err != nil && !c.storage.IsNotFoundError(err) {
			return NewUsecaseError("failed while trying to insert chest and history", internalUsecaseError, err)
		}

		if history.SyncingTime == nil {
			return NewUsecaseError("syncing time can not be nil, bad data from server", internalUsecaseError, errors.New("server error: syncing time is nil"))
		}
		err = c.storage.UpdateHistorySyncData(ctx, history)
		if err != nil {
			return NewUsecaseError("failed while trying to update history sync time", internalUsecaseError, err)
		}
	}
	return nil
}

// AddPassword short hand for adding password, for detail implementation look [AddChest].
func (c *usecases) AddPassword(ctx context.Context, name string, password string, lockPassword string) error {
	return c.AddChest(ctx, name, []byte(password), models.ChestPasswordData, lockPassword)
}

// AddCard short hand for adding card, for detail implementation look [AddChest].
func (c *usecases) AddCard(ctx context.Context, name string, card *models.Card, lockPassword string) error {
	bytes, err := cardToBytes(card)
	if err != nil {
		return NewUsecaseError("failed while marshaling card to bytes", internalUsecaseError, err)
	}
	return c.AddChest(ctx, name, bytes, models.ChestCreditCardData, lockPassword)
}

func (c *usecases) ReadFile(ctx context.Context, path string) ([]byte, error) {
	fileStat, err := os.Stat(path)
	if err != nil {
		return nil, NewUsecaseError("failed while trying reading file, check your path", internalUsecaseError, err)
	}
	if fileStat.IsDir() {
		return nil, NewUsecaseError("path is directory, not a file", badDataUsecaseError, errors.New("path is directory, not a file"))
	}

	if fileStat.Size() > maxFileSize {
		return nil, NewUsecaseError("file size is too big", badDataUsecaseError, errors.New("file size is too big"))
	}

	file, err := os.ReadFile(path)
	if err != nil {
		return nil, NewUsecaseError("failed while trying reading file, check your path", internalUsecaseError, err)
	}
	return file, nil
}

// AddFile short hand for adding file, for detail implementation look [AddChest].
func (c *usecases) AddFile(ctx context.Context, name string, data []byte, lockPassword string) error {
	if len(data) == 0 {
		return NewUsecaseError("data is empty nothing to save", badDataUsecaseError, errors.New("file data empty"))
	}
	return c.AddChest(ctx, name, data, models.ChestFileData, lockPassword)
}

// cardToBytes helper function that convert card to bytes, if error return [NewUsecaseError].
func cardToBytes(card *models.Card) ([]byte, error) {
	if card == nil {
		return nil, nil
	}
	data, err := toml.Marshal(card)
	if err != nil {
		return nil, NewUsecaseError("failed while marshaling card to bytes", internalUsecaseError, err)
	}
	return data, nil
}

// bytesToCard helper function that convert bytes to card, if error return [NewUsecaseError].
func bytesToCard(bytes []byte) (*models.Card, error) {
	if bytes == nil {
		return nil, NewUsecaseError("empty card data nothing to unmarshal", badDataUsecaseError, errors.New("bytes can not be nil"))
	}
	card := &models.Card{}
	err := toml.Unmarshal(bytes, card)
	if err != nil {
		return nil, NewUsecaseError("failed while unmarshaling bytes to card", internalUsecaseError, err)
	}
	return card, nil
}

// EditPassword short hand for editing password, for detail implementation look at [EditChest].
func (c *usecases) EditPassword(ctx context.Context, name string, newName string, newPassword string, lockPassword string) error {
	return c.EditChest(ctx, name, newName, []byte(newPassword), lockPassword, handlePasswordUpdate)
}

// EditFile short hand for editing file, for detail implementation look at [EditChest].
func (c *usecases) EditFile(ctx context.Context, name string, newName string, newData []byte, lockPassword string) error {
	return c.EditChest(ctx, name, newName, newData, lockPassword, handleFileUpdate)
}

// EditCard short hand for editing card, for detail implementation look at [EditChest].
// If newName is empty, it will use the old name.
// If newCard is nil, it will use the old card.
func (c *usecases) EditCard(ctx context.Context, name string, newName string, newCard *models.Card, lockPassword string) error {
	bytes, err := cardToBytes(newCard)
	if err != nil {
		return NewUsecaseError("failed while marshaling card to bytes", internalUsecaseError, err)
	}
	return c.EditChest(ctx, name, newName, bytes, lockPassword, handleCardUpdate)
}

// GetChestByName return chest by name with decrypted data if lock password is correct.
func (c *usecases) GetChestByName(ctx context.Context, name string, lockPassword string) (*models.Chest, error) {
	chest, err := c.storage.SelectChestByName(ctx, name)
	if err != nil {
		return nil, c.handleStorageErrors(err)
	}

	lock := c.encryption.GenerateLock(chest.Salt, lockPassword)
	decrypted, err := c.encryption.UnlockData(chest.Data, lock)
	if err != nil {
		return nil, c.handleEncryptionErrors(err)
	}

	chest.Data = decrypted
	return chest, nil
}

// WriteFile write file to path.
func (c *usecases) WriteFile(ctx context.Context, path string, data []byte) error {
	err := os.WriteFile(path, data, 0744)
	return err
}

// GetFileByName return file by name with decrypted data if lock password is correct.
func (c *usecases) GetFileByName(ctx context.Context, name string, lockPassword string) (file []byte, err error) {
	chest, err := c.GetChestByName(ctx, name, lockPassword)
	if err != nil {
		return
	}

	if chest.DataType != models.ChestFileData {
		err = NewUsecaseError(fmt.Sprintf("chest data type is not file, is %s, use coressponding command to show data properly", chest.DataType.String()), badDataUsecaseError, errors.New("chest data type is "))
		return
	}

	return chest.Data, nil
}

// GetCardByName return card by name with encrypted data if lock password correct.
func (c *usecases) GetCardByName(ctx context.Context, name string, lockPassword string) (card *models.Card, err error) {
	chest, err := c.GetChestByName(ctx, name, lockPassword)
	if err != nil {
		return
	}

	if chest.DataType != models.ChestCreditCardData {
		err = NewUsecaseError(fmt.Sprintf("chest data type is not card, is %s, use coressponding command to show data properly", chest.DataType.String()), badDataUsecaseError, errors.New("chest data type is "))
		return
	}

	card, err = bytesToCard(chest.Data)
	if err != nil {
		return
	}

	return
}

// GetPasswordByName return chest by name with encrypted data if lock password correct.
func (c *usecases) GetPasswordByName(ctx context.Context, name string, lockPassword string) (password string, err error) {
	var chest *models.Chest
	chest, err = c.GetChestByName(ctx, name, lockPassword)
	if err != nil {
		return
	}

	if chest.DataType != models.ChestPasswordData {
		err = NewUsecaseError(fmt.Sprintf("chest data type is not password, is %s, use coressponding command to show data properly", chest.DataType.String()), badDataUsecaseError, errors.New("chest data type is "))
		return
	}

	password = string(chest.Data)
	return
}

// GetAllChests return all chests.
func (c *usecases) GetAllChests(ctx context.Context) (chest []*models.Chest, err error) {
	chest, err = c.storage.SelectIdNameTypeChests(ctx)
	return
}

// IsInternalError checks that error is internal.
func (c *usecases) IsInternalError(err error) bool {
	var uerr *usecasesError
	if errors.As(err, &uerr) {
		return uerr.errType == internalUsecaseError
	}

	return false
}

func (c *usecases) ExtractUserError(err error) error {
	var uerr *usecasesError
	if errors.As(err, &uerr) {
		return errors.New(uerr.message)
	}
	return err
}

// IsBadDataError checks that error is usecase error.
func (c *usecases) IsUsecaseError(err error) bool {
	var uerr *usecasesError
	return errors.As(err, &uerr)
}

func (c *usecases) IsAuthentificationError(err error) bool {
	var uerr *usecasesError
	if errors.As(err, &uerr) {
		return uerr.errType == authentificationUsecaseError
	}

	return false
}

func (c *usecases) IsConnectionProblem(err error) bool {
	return c.sync.IsConnectionError(err)
}

// NewUsecaseError create new usecase error.
func NewUsecaseError(message string, errType usecasesErrorType, err error) error {
	return &usecasesError{
		message: message,
		errType: errType,
		err:     err,
	}
}

// Error implements errors.Errorer interface.
func (e usecasesError) Error() string {
	return fmt.Sprintf("usecase error: %s; %s", e.message, e.err)
}

// Unwrap implements errors.Wrapper interface.
func (e usecasesError) Unwrap() error {
	return e.err
}
