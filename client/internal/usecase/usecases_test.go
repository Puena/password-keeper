package usecase

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type groupMock struct {
	viper   *MockViperRepository
	crypto  *MockEncryptionRepository
	storage *MockStorageRepostiory
	device  *MockDeviceRepository
	sync    *MockSyncRepository
}

func initGroupMock(t *testing.T) *groupMock {
	return &groupMock{
		viper:   NewMockViperRepository(t),
		crypto:  NewMockEncryptionRepository(t),
		storage: NewMockStorageRepostiory(t),
		device:  NewMockDeviceRepository(t),
		sync:    NewMockSyncRepository(t),
	}
}

func (g *groupMock) Viper() ViperRepository {
	return g.viper
}

func (g *groupMock) Crypto() EncryptionRepository {
	return g.crypto
}

func (g *groupMock) Storage() StorageRepostiory {
	return g.storage
}

func (g *groupMock) Device() DeviceRepository {
	return g.device
}

func (g *groupMock) Sync() SyncRepository {
	return g.sync
}

func TestEncryptData(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while trying to create config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while trying to create logger")

	type testArgs struct {
		data         []byte
		salt         []byte
		lockPassword string
	}

	type testExpected struct {
		salt            []byte
		lock            []byte
		encryptedData   []byte
		saltEror        error
		encryptionError error
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
				data:         sha256.New().Sum([]byte("data")),
				salt:         []byte{},
				lockPassword: "lock",
			},
			expected: testExpected{
				salt:          sha256.New().Sum([]byte("salt")),
				lock:          sha256.New().Sum([]byte("lock")),
				encryptedData: sha256.New().Sum([]byte("encryptedData")),
			},
		},
		{
			name: "success_with_old_salt",
			args: testArgs{
				data:         sha256.New().Sum([]byte("data")),
				salt:         sha256.New().Sum([]byte("salt")),
				lockPassword: "lock",
			},
			expected: testExpected{
				salt:          sha256.New().Sum([]byte("salt")),
				lock:          sha256.New().Sum([]byte("lock")),
				encryptedData: sha256.New().Sum([]byte("encryptedData")),
			},
		},
		{
			name: "error_salt_generation",
			args: testArgs{
				data:         sha256.New().Sum([]byte("data")),
				salt:         []byte{},
				lockPassword: "lock",
			},
			expected: testExpected{
				salt:          sha256.New().Sum([]byte("salt")),
				lock:          sha256.New().Sum([]byte("lock")),
				encryptedData: sha256.New().Sum([]byte("encryptedData")),
				saltEror:      errors.New("salt generation error"),
			},
		},
		{
			name: "error_lock_data",
			args: testArgs{
				data:         sha256.New().Sum([]byte("data")),
				salt:         sha256.New().Sum([]byte("salt")),
				lockPassword: "lock",
			},
			expected: testExpected{
				salt:            sha256.New().Sum([]byte("salt")),
				lock:            sha256.New().Sum([]byte("lock")),
				encryptedData:   sha256.New().Sum([]byte("encryptedData")),
				encryptionError: errors.New("lock data error"),
			},
		},
	}

	for _, testData := range data {
		t.Run(testData.name, func(t *testing.T) {
			mockRepos := initGroupMock(t)
			cryptoMock := mockRepos.Crypto().(*MockEncryptionRepository)
			usecase := NewUsecases(mockRepos, cfg, lg)

			defer func() {
				eData, oSalt, err := usecase.encryptData(testData.args.data, testData.args.salt, testData.args.lockPassword)
				if testData.expected.saltEror != nil ||
					testData.expected.encryptionError != nil {
					assert.Error(t, err, "failed while expecting error from encryptData")
					return
				}

				assert.NoError(t, err, "failed while trying to encrypt data")
				assert.NotNil(t, eData, "failed while trying to encrypt data")
				assert.NotNil(t, oSalt, "failed while trying to encrypt data")
			}()

			if len(testData.args.salt) == 0 {
				cryptoMock.EXPECT().GenerateSalt().Return(testData.expected.salt, testData.expected.saltEror)
				if testData.expected.saltEror != nil {
					return
				}
			}

			cryptoMock.EXPECT().GenerateLock(testData.expected.salt, testData.args.lockPassword).Return(testData.expected.lock)

			cryptoMock.EXPECT().LockData(testData.args.data, testData.expected.lock).Return(testData.expected.encryptedData, testData.expected.encryptionError)
			if testData.expected.encryptionError != nil {
				return
			}
		})
	}
}

func TestAddChest(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while trying to create config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while trying to create logger")

	type testArgs struct {
		name         string
		data         []byte
		dataType     models.ChestDataType
		lockPassword string
	}

	type testExpected struct {
		encryptedData   []byte
		passwordError   error
		dataError       error
		encryptionError error
		deviceError     error
		insertError     error
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
				name:         "some password",
				data:         []byte("data"),
				dataType:     0,
				lockPassword: "lock",
			},
			expected: testExpected{
				encryptedData: sha256.New().Sum([]byte("encryptedData")),
			},
		},
		{
			name: "empty_password",
			args: testArgs{
				name:         "some password",
				data:         []byte("data"),
				dataType:     0,
				lockPassword: "",
			},
			expected: testExpected{
				encryptedData: sha256.New().Sum([]byte("encryptedData")),
				passwordError: errors.New("empty password"),
			},
		},
		{
			name: "empty_data",
			args: testArgs{
				name:         "some password",
				data:         nil,
				dataType:     0,
				lockPassword: "lock",
			},
			expected: testExpected{
				encryptedData: sha256.New().Sum([]byte("encryptedData")),
				dataError:     errors.New("empty data"),
			},
		},
		{
			name: "encryption_error",
			args: testArgs{
				name:         "some password",
				data:         []byte("data"),
				dataType:     0,
				lockPassword: "lock",
			},
			expected: testExpected{
				encryptedData:   sha256.New().Sum([]byte("encryptedData")),
				encryptionError: errors.New("encryption error"),
			},
		},
		{
			name: "device_error",
			args: testArgs{
				name:         "some password",
				data:         []byte("data"),
				dataType:     0,
				lockPassword: "lock",
			},
			expected: testExpected{
				encryptedData: sha256.New().Sum([]byte("encryptedData")),
				deviceError:   errors.New("device error"),
			},
		},
		{
			name: "insert_error",
			args: testArgs{
				name:         "some password",
				data:         []byte("data"),
				dataType:     0,
				lockPassword: "lock",
			},
			expected: testExpected{
				encryptedData: sha256.New().Sum([]byte("encryptedData")),
				insertError:   errors.New("insert error"),
			},
		},
	}

	for _, testData := range data {
		t.Run(testData.name, func(t *testing.T) {
			mockRepos := initGroupMock(t)
			cryptoMock := mockRepos.crypto
			deviceMock := mockRepos.device
			storageMock := mockRepos.storage
			usecase := NewUsecases(mockRepos, cfg, lg)

			defer func() {
				err := usecase.AddChest(context.Background(), testData.args.name, testData.args.data, testData.args.dataType, testData.args.lockPassword)
				if testData.expected.passwordError != nil ||
					testData.expected.dataError != nil ||
					testData.expected.encryptionError != nil ||
					testData.expected.deviceError != nil ||
					testData.expected.insertError != nil {
					assert.Error(t, err, "failed while expecting error from encryptData")
					return
				}

				assert.NoError(t, err, "failed while trying to encrypt data")
			}()

			if testData.expected.passwordError != nil {
				return
			}
			if testData.expected.dataError != nil {
				return
			}

			salt := sha256.New().Sum([]byte("salt"))
			cryptoMock.EXPECT().GenerateSalt().Return(salt, nil)
			lock := sha256.New().Sum([]byte("lock"))
			cryptoMock.EXPECT().GenerateLock(salt, testData.args.lockPassword).Return(lock)
			cryptoMock.EXPECT().LockData(testData.args.data, lock).Return(testData.expected.encryptedData, testData.expected.encryptionError)

			if testData.expected.encryptionError != nil {
				return
			}

			deviceMock.EXPECT().ExtractDeviceName().Return(&models.DeviceInfo{
				Name: "android",
			}, testData.expected.deviceError)

			if testData.expected.deviceError != nil {
				return
			}

			storageMock.EXPECT().Insert(mock.Anything, mock.AnythingOfType("*models.Chest"), mock.AnythingOfType("*models.History")).Return(testData.expected.insertError)

			if testData.expected.insertError != nil {
				storageMock.EXPECT().IsNotFoundError(testData.expected.insertError).Return(false)
				storageMock.EXPECT().IsConfictError(testData.expected.insertError).Return(false)
				return
			}
		})
	}
}

func TestHandleCardUpdate(t *testing.T) {
	oneCard := &models.Card{
		Number:  "1344 1234 1234 1234",
		Owner:   "John Doe",
		Expired: "12/22",
		Cvv:     "123",
	}
	secondCard := &models.Card{
		Number:  "4312 4321 4321 4321",
		Owner:   "Some Who",
		Expired: "12/23",
		Cvv:     "321",
	}
	// emptyCard := &models.Card{}

	oCard, _ := cardToBytes(oneCard)
	sCard, _ := cardToBytes(secondCard)
	// eCard, _ := cardToBytes(emptyCard)

	type testArgs struct {
		dataType   models.ChestDataType
		updateData []byte
		newData    []byte
	}

	type testExpected struct {
		newCard   []byte
		cardError error
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
				dataType:   models.ChestCreditCardData,
				updateData: oCard,
				newData:    sCard,
			},
			expected: testExpected{
				newCard: sCard,
			},
		},
		{
			name: "wrong_data_type",
			args: testArgs{
				dataType:   models.ChestPasswordData,
				updateData: oCard,
				newData:    sCard,
			},
			expected: testExpected{
				newCard:   sCard,
				cardError: errors.New("wrong data type"),
			},
		},
		{
			name: "new_data_is_empty",
			args: testArgs{
				dataType:   models.ChestCreditCardData,
				updateData: oCard,
				newData:    nil,
			},
			expected: testExpected{
				newCard: oCard,
			},
		},
		{
			name: "update_card_error",
			args: testArgs{
				dataType:   models.ChestCreditCardData,
				updateData: sha256.New().Sum([]byte("updateData")),
				newData:    sCard,
			},
			expected: testExpected{
				newCard:   sCard,
				cardError: errors.New("update card error"),
			},
		},
		{
			name: "newdata_card_error",
			args: testArgs{
				dataType:   models.ChestCreditCardData,
				updateData: oCard,
				newData:    sha256.New().Sum([]byte("newData")),
			},
			expected: testExpected{
				newCard:   sCard,
				cardError: errors.New("new card error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			res, err := handleCardUpdate(tt.args.dataType, tt.args.updateData, tt.args.newData)
			if tt.expected.cardError != nil {
				assert.Error(t, err, "failed while expecting error from handleCardUpdate")
				return
			}
			assert.NoError(t, err, "failed while trying to update card")
			assert.Equal(t, tt.expected.newCard, res)
		})
	}
}

func TestHandlePasswordUpdate(t *testing.T) {
	type testArgs struct {
		dataType   models.ChestDataType
		updateData []byte
		newData    []byte
	}

	type testExpected struct {
		newPassword []byte
		cardError   error
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
				dataType:   models.ChestPasswordData,
				updateData: []byte("old password"),
				newData:    []byte("new password"),
			},
			expected: testExpected{
				newPassword: []byte("new password"),
			},
		},
		{
			name: "new_data_is_empty",
			args: testArgs{
				dataType:   models.ChestPasswordData,
				updateData: []byte("old password"),
				newData:    nil,
			},
			expected: testExpected{
				newPassword: []byte("old password"),
			},
		},
		{
			name: "wrong_data_type",
			args: testArgs{
				dataType:   models.ChestCreditCardData,
				updateData: []byte("old password"),
				newData:    []byte("new password"),
			},
			expected: testExpected{
				newPassword: []byte("new password"),
				cardError:   errors.New("wrong data type"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			res, err := handlePasswordUpdate(tt.args.dataType, tt.args.updateData, tt.args.newData)
			if tt.expected.cardError != nil {
				assert.Error(t, err, "failed while expecting error from handlePasswordUpdate")
				return
			}
			assert.NoError(t, err, "failed while trying to update password")
			assert.Equal(t, tt.expected.newPassword, res)
		})
	}
}

func TestHandleFileUpdate(t *testing.T) {
	type testArgs struct {
		dataType   models.ChestDataType
		updateData []byte
		newData    []byte
	}

	type testExpected struct {
		newFile   []byte
		cardError error
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
				dataType:   models.ChestFileData,
				updateData: []byte("old file"),
				newData:    []byte("new file"),
			},
			expected: testExpected{
				newFile: []byte("new file"),
			},
		},
		{
			name: "new_data_is_empty",
			args: testArgs{
				dataType:   models.ChestFileData,
				updateData: []byte("old file"),
				newData:    nil,
			},
			expected: testExpected{
				newFile: []byte("old file"),
			},
		},
		{
			name: "wrong_data_type",
			args: testArgs{
				dataType:   models.ChestCreditCardData,
				updateData: []byte("old newFile"),
				newData:    []byte("new newFile"),
			},
			expected: testExpected{
				newFile:   []byte("new newFile"),
				cardError: errors.New("wrong data type"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			res, err := handleFileUpdate(tt.args.dataType, tt.args.updateData, tt.args.newData)
			if tt.expected.cardError != nil {
				assert.Error(t, err, "failed while expecting error from handlePasswordUpdate")
				return
			}
			assert.NoError(t, err, "failed while trying to update password")
			assert.Equal(t, tt.expected.newFile, res)
		})
	}
}

func TestGetChestByName(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while trying to create config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while trying to create logger")
	someChest := &models.Chest{
		ID:       uuid.NewString(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("salt")),
		Name:     "some password",
		Data:     sha256.New().Sum([]byte("data")),
		DataType: 0,
	}

	type testArgs struct {
		name         string
		lockPassword string
	}

	type testExpected struct {
		chest         *models.Chest
		lock          []byte
		decryptedData []byte
		selectError   error
		decryptError  error
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
				name:         "some password",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:         someChest,
				lock:          sha256.New().Sum([]byte("lock")),
				decryptedData: sha256.New().Sum([]byte("decrypted data")),
			},
		},
		{
			name: "select_error",
			args: testArgs{
				name:         "some password",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:         someChest,
				lock:          sha256.New().Sum([]byte("lock")),
				decryptedData: sha256.New().Sum([]byte("decrypted data")),
				selectError:   errors.New("select error"),
			},
		},
		{
			name: "decrypt_error",
			args: testArgs{
				name:         "some password",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:         someChest,
				lock:          sha256.New().Sum([]byte("lock")),
				decryptedData: sha256.New().Sum([]byte("decrypted data")),
				decryptError:  errors.New("decrypt error"),
			},
		},
	}

	for _, testData := range data {
		t.Run(testData.name, func(t *testing.T) {
			mockRepos := initGroupMock(t)
			cryptoMock := mockRepos.crypto
			storageMock := mockRepos.storage
			usecase := NewUsecases(mockRepos, cfg, lg)

			defer func() {
				chest, err := usecase.GetChestByName(context.Background(), testData.args.name, testData.args.lockPassword)
				if testData.expected.decryptError != nil ||
					testData.expected.selectError != nil {
					assert.Error(t, err, "failed while expecting error from encryptData")
					return
				}

				assert.NoError(t, err, "failed while trying to encrypt data")
				assert.NotNil(t, chest, "failed while trying to encrypt data")
				assert.Equal(t, testData.expected.decryptedData, chest.Data, "data not decrypted")
			}()

			storageMock.EXPECT().SelectChestByName(mock.Anything, testData.args.name).Return(testData.expected.chest, testData.expected.selectError)
			if testData.expected.selectError != nil {
				storageMock.EXPECT().IsNotFoundError(testData.expected.selectError).Return(false)
				storageMock.EXPECT().IsConfictError(testData.expected.selectError).Return(false)
				return
			}

			cryptoMock.EXPECT().GenerateLock(testData.expected.chest.Salt, testData.args.lockPassword).Return(testData.expected.lock)
			cryptoMock.EXPECT().UnlockData(testData.expected.chest.Data, testData.expected.lock).Return(testData.expected.decryptedData, testData.expected.decryptError)
			if testData.expected.decryptError != nil {
				cryptoMock.EXPECT().IsBadUserData(testData.expected.decryptError).Return(false)
				return
			}

		})
	}
}

func TestGetFileByName(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while trying to create config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while trying to create logger")
	someFileChest := &models.Chest{
		ID:       uuid.NewString(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("salt")),
		Name:     "some password",
		Data:     sha256.New().Sum([]byte("data")),
		DataType: models.ChestFileData,
	}
	somePasswordChest := &models.Chest{
		ID:       uuid.NewString(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("salt")),
		Name:     "some password",
		Data:     sha256.New().Sum([]byte("data")),
		DataType: models.ChestPasswordData,
	}

	type testArgs struct {
		name         string
		lockPassword string
	}

	type testExpected struct {
		chest         *models.Chest
		decryptedData []byte
		getChestError error
		dataTypeError error
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
				name:         "some file",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:         someFileChest,
				decryptedData: sha256.New().Sum([]byte("decrypted data")),
			},
		},
		{
			name: "get_chest_error",
			args: testArgs{
				name:         "some file",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:         someFileChest,
				decryptedData: sha256.New().Sum([]byte("decrypted data")),
				getChestError: errors.New("select error"),
			},
		},
		{
			name: "data_type_error",
			args: testArgs{
				name:         "some file",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:         somePasswordChest,
				decryptedData: sha256.New().Sum([]byte("decrypted data")),
				dataTypeError: errors.New("some error"),
			},
		},
	}

	for _, testData := range data {
		t.Run(testData.name, func(t *testing.T) {
			mockRepos := initGroupMock(t)
			cryptoMock := mockRepos.crypto
			storageMock := mockRepos.storage
			usecase := NewUsecases(mockRepos, cfg, lg)

			defer func() {
				chestDecryptedData, err := usecase.GetFileByName(context.Background(), testData.args.name, testData.args.lockPassword)
				if testData.expected.getChestError != nil ||
					testData.expected.dataTypeError != nil {
					assert.Error(t, err, "failed while expecting error from encryptData")
					return
				}

				assert.NoError(t, err, "failed while trying to encrypt data")
				assert.NotNil(t, chestDecryptedData, "failed while trying to encrypt data")
				assert.Equal(t, testData.expected.decryptedData, chestDecryptedData, "data not decrypted")
			}()

			storageMock.EXPECT().SelectChestByName(mock.Anything, testData.args.name).Return(testData.expected.chest, testData.expected.getChestError)
			if testData.expected.getChestError != nil {
				storageMock.EXPECT().IsNotFoundError(testData.expected.getChestError).Return(false)
				storageMock.EXPECT().IsConfictError(testData.expected.getChestError).Return(false)
				return
			}

			someExpectedLock := sha256.New().Sum([]byte("some-lock"))
			cryptoMock.EXPECT().GenerateLock(testData.expected.chest.Salt, testData.args.lockPassword).Return(someExpectedLock)
			cryptoMock.EXPECT().UnlockData(testData.expected.chest.Data, someExpectedLock).Return(testData.expected.decryptedData, nil)
		})
	}
}

func TestGetCardByName(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while trying to create config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while trying to create logger")
	someCard := &models.Card{
		Number:  "1234 1234 1234 1234",
		Owner:   "John How",
		Expired: "12|23",
		Cvv:     "554",
	}
	someCardBytes, _ := cardToBytes(someCard)
	someCardChest := &models.Chest{
		ID:       uuid.NewString(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("salt")),
		Name:     "some password",
		Data:     someCardBytes,
		DataType: models.ChestCreditCardData,
	}
	somePasswordChest := &models.Chest{
		ID:       uuid.NewString(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("salt")),
		Name:     "some password",
		Data:     sha256.New().Sum([]byte("data")),
		DataType: models.ChestPasswordData,
	}

	type testArgs struct {
		name         string
		lockPassword string
	}

	type testExpected struct {
		chest          *models.Chest
		decryptedData  []byte
		card           *models.Card
		getChestError  error
		dataTypeError  error
		wrongCardError error
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
				name:         "some file",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:         someCardChest,
				decryptedData: someCardChest.Data,
				card:          someCard,
			},
		},
		{
			name: "get_chest_error",
			args: testArgs{
				name:         "some file",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:         someCardChest,
				decryptedData: someCardChest.Data,
				card:          someCard,
				getChestError: errors.New("some error"),
			},
		},
		{
			name: "data_type_error",
			args: testArgs{
				name:         "some file",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:         somePasswordChest,
				decryptedData: somePasswordChest.Data,
				dataTypeError: errors.New("some data type error"),
			},
		},
		{
			name: "wrong_card_data_error",
			args: testArgs{
				name:         "some file",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:          someCardChest,
				decryptedData:  somePasswordChest.Data,
				wrongCardError: errors.New("some error"),
			},
		},
	}

	for _, testData := range data {
		t.Run(testData.name, func(t *testing.T) {
			mockRepos := initGroupMock(t)
			cryptoMock := mockRepos.crypto
			storageMock := mockRepos.storage
			usecase := NewUsecases(mockRepos, cfg, lg)

			defer func() {
				chestCard, err := usecase.GetCardByName(context.Background(), testData.args.name, testData.args.lockPassword)
				if testData.expected.getChestError != nil ||
					testData.expected.dataTypeError != nil ||
					testData.expected.wrongCardError != nil {
					assert.Error(t, err, "failed while expecting error from encryptData")
					return
				}

				assert.NoError(t, err, "failed while trying to encrypt data")
				assert.NotNil(t, chestCard, "failed while trying to encrypt data")
				assert.Equal(t, testData.expected.card, chestCard, "data not decrypted")
			}()

			storageMock.EXPECT().SelectChestByName(mock.Anything, testData.args.name).Return(testData.expected.chest, testData.expected.getChestError)
			if testData.expected.getChestError != nil {
				storageMock.EXPECT().IsNotFoundError(testData.expected.getChestError).Return(false)
				storageMock.EXPECT().IsConfictError(testData.expected.getChestError).Return(false)
				return
			}

			someExpectedLock := sha256.New().Sum([]byte("some-lock"))
			cryptoMock.EXPECT().GenerateLock(testData.expected.chest.Salt, testData.args.lockPassword).Return(someExpectedLock)
			cryptoMock.EXPECT().UnlockData(testData.expected.chest.Data, someExpectedLock).Return(testData.expected.decryptedData, nil)
		})
	}
}

func TestGetPasswordByName(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while trying to create config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while trying to create logger")
	someFileChest := &models.Chest{
		ID:       uuid.NewString(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("salt")),
		Name:     "some password",
		Data:     sha256.New().Sum([]byte("data")),
		DataType: models.ChestFileData,
	}
	somePasswordChest := &models.Chest{
		ID:       uuid.NewString(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("salt")),
		Name:     "some password",
		Data:     sha256.New().Sum([]byte("data")),
		DataType: models.ChestPasswordData,
	}

	type testArgs struct {
		name         string
		lockPassword string
	}

	type testExpected struct {
		chest         *models.Chest
		decryptedData []byte
		getChestError error
		dataTypeError error
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
				name:         "some password",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:         somePasswordChest,
				decryptedData: somePasswordChest.Data,
			},
		},
		{
			name: "get_chest_error",
			args: testArgs{
				name:         "some password",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:         somePasswordChest,
				decryptedData: someFileChest.Data,
				getChestError: errors.New("select error"),
			},
		},
		{
			name: "data_type_error",
			args: testArgs{
				name:         "some password",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:         someFileChest,
				decryptedData: someFileChest.Data,
				dataTypeError: errors.New("some error"),
			},
		},
	}

	for _, testData := range data {
		t.Run(testData.name, func(t *testing.T) {
			mockRepos := initGroupMock(t)
			cryptoMock := mockRepos.crypto
			storageMock := mockRepos.storage
			usecase := NewUsecases(mockRepos, cfg, lg)

			defer func() {
				chestDecryptedData, err := usecase.GetPasswordByName(context.Background(), testData.args.name, testData.args.lockPassword)
				if testData.expected.getChestError != nil ||
					testData.expected.dataTypeError != nil {
					assert.Error(t, err, "failed while expecting error from encryptData")
					return
				}

				assert.NoError(t, err, "failed while trying to encrypt data")
				assert.NotNil(t, chestDecryptedData, "failed while trying to encrypt data")
				assert.Equal(t, string(testData.expected.decryptedData), chestDecryptedData, "data not decrypted")
			}()

			storageMock.EXPECT().SelectChestByName(mock.Anything, testData.args.name).Return(testData.expected.chest, testData.expected.getChestError)
			if testData.expected.getChestError != nil {
				storageMock.EXPECT().IsNotFoundError(testData.expected.getChestError).Return(false)
				storageMock.EXPECT().IsConfictError(testData.expected.getChestError).Return(false)
				return
			}

			someExpectedLock := sha256.New().Sum([]byte("some-lock"))
			cryptoMock.EXPECT().GenerateLock(testData.expected.chest.Salt, testData.args.lockPassword).Return(someExpectedLock)
			cryptoMock.EXPECT().UnlockData(testData.expected.chest.Data, someExpectedLock).Return(testData.expected.decryptedData, nil)
		})
	}
}

func TestGetAllChests(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")
	someChest := &models.Chest{
		ID:       uuid.NewString(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("some salt")),
		Name:     "some password chest",
		Data:     sha256.New().Sum([]byte("some data")),
		DataType: models.ChestPasswordData,
	}

	t.Run("success", func(t *testing.T) {
		mockRepos := initGroupMock(t)
		storageMock := mockRepos.storage
		usecase := NewUsecases(mockRepos, cfg, lg)

		storageMock.EXPECT().SelectIdNameTypeChests(mock.Anything).Return([]*models.Chest{someChest}, nil)

		chests, err := usecase.GetAllChests(context.Background())
		assert.NoError(t, err, "failed while get all cehsts, error not expected")
		assert.NotNil(t, chests, "failed while expecing not nil result from getallchests")
	})
}

func TestEditChest(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")
	someChest := &models.Chest{
		ID:       uuid.NewString(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("some salt")),
		Name:     "yandex.disk",
		Data:     sha256.New().Sum([]byte("some data")),
		DataType: models.ChestPasswordData,
	}
	someChestAfterUpdate := &models.Chest{
		ID:       uuid.NewString(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("some salt")),
		Name:     "some password chest",
		Data:     sha256.New().Sum([]byte("some new data")),
		DataType: models.ChestPasswordData,
	}
	wrongDataTypeChest := &models.Chest{
		ID:       uuid.NewString(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("some salt")),
		Name:     "yandex.disk",
		Data:     sha256.New().Sum([]byte("some data")),
		DataType: models.ChestFileData,
	}

	type testArgs struct {
		name         string
		newName      string
		newData      []byte
		lockPassword string
		handleData   func(dataType models.ChestDataType, updateData []byte, newData []byte) ([]byte, error)
	}

	type testExpected struct {
		chest           *models.Chest
		newChest        *models.Chest
		getChestError   error
		handleDataError error
		encryptionError error
		deviceError     error
		storageError    error
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
				name:         "yandex.disk",
				newName:      "mail.disk",
				newData:      someChestAfterUpdate.Data,
				lockPassword: "lock",
				handleData:   handlePasswordUpdate,
			},
			expected: testExpected{
				chest:    someChest,
				newChest: someChestAfterUpdate,
			},
		},
		{
			name: "get_chest_error",
			args: testArgs{
				name:         "yandex.disk",
				newName:      "",
				newData:      someChestAfterUpdate.Data,
				lockPassword: "lock",
				handleData:   handlePasswordUpdate,
			},
			expected: testExpected{
				chest:         someChest,
				newChest:      someChestAfterUpdate,
				getChestError: errors.New("some error"),
			},
		},
		{
			name: "handle_data_error",
			args: testArgs{
				name:         "yandex.disk",
				newName:      "",
				newData:      someChestAfterUpdate.Data,
				lockPassword: "lock",
				handleData:   handlePasswordUpdate,
			},
			expected: testExpected{
				chest:           wrongDataTypeChest,
				newChest:        someChestAfterUpdate,
				handleDataError: errors.New("some error"),
			},
		},
		{
			name: "encrypt_data_error",
			args: testArgs{
				name:         "yandex.disk",
				newName:      "",
				newData:      someChestAfterUpdate.Data,
				lockPassword: "lock",
				handleData:   handlePasswordUpdate,
			},
			expected: testExpected{
				chest:           someChest,
				newChest:        someChestAfterUpdate,
				encryptionError: errors.New("some error"),
			},
		},
		{
			name: "device_error",
			args: testArgs{
				name:         "yandex.disk",
				newName:      "",
				newData:      someChestAfterUpdate.Data,
				lockPassword: "lock",
				handleData:   handlePasswordUpdate,
			},
			expected: testExpected{
				chest:       someChest,
				newChest:    someChestAfterUpdate,
				deviceError: errors.New("some error"),
			},
		},
		{
			name: "storage_error",
			args: testArgs{
				name:         "yandex.disk",
				newName:      "",
				newData:      someChestAfterUpdate.Data,
				lockPassword: "lock",
				handleData:   handlePasswordUpdate,
			},
			expected: testExpected{
				chest:        someChest,
				newChest:     someChestAfterUpdate,
				storageError: errors.New("some error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mockRepos := initGroupMock(t)
			storageMock := mockRepos.storage
			cryptoMock := mockRepos.crypto
			deviceMock := mockRepos.device
			usecase := NewUsecases(mockRepos, cfg, lg)

			defer func() {
				err := usecase.EditChest(context.Background(), tt.args.name, tt.args.newName, tt.args.newData, tt.args.lockPassword, tt.args.handleData)
				if tt.expected.deviceError != nil ||
					tt.expected.encryptionError != nil ||
					tt.expected.getChestError != nil ||
					tt.expected.storageError != nil ||
					tt.expected.handleDataError != nil {
					assert.Error(t, err, "failed while expecting error from EditChest()")
					return
				}

				assert.NoError(t, err, "not expected error while doing EditChest()")
			}()

			getChestByNameMock(storageMock, cryptoMock, tt.expected.chest, tt.args.lockPassword, tt.expected.getChestError)
			if tt.expected.getChestError != nil {
				return
			}

			if tt.expected.handleDataError != nil {
				return
			}

			encryptDataMock(cryptoMock, tt.expected.chest.Salt, tt.expected.newChest.Data, tt.args.lockPassword, tt.expected.encryptionError)
			if tt.expected.encryptionError != nil {
				return
			}

			deviceMock.EXPECT().ExtractDeviceName().Return(&models.DeviceInfo{
				Name: "some_device",
			}, tt.expected.deviceError)
			if tt.expected.deviceError != nil {
				return
			}

			storageMock.EXPECT().Update(mock.Anything, mock.AnythingOfType("*models.Chest"), mock.AnythingOfType("*models.History")).Return(tt.expected.storageError)
			if tt.expected.storageError != nil {
				handleStorageErrorsMock(storageMock, tt.expected.storageError)
				return
			}
		})
	}
}

func TestDeleteChest(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while creating config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while creating logger")

	someChest := &models.Chest{
		ID:       uuid.NewString(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("some salt")),
		Name:     "yandex.disk",
		Data:     sha256.New().Sum([]byte("some data")),
		DataType: models.ChestPasswordData,
	}

	type testArgs struct {
		name         string
		lockPassword string
	}

	type testExpected struct {
		chest        *models.Chest
		nameError    error
		selectError  error
		unlockError  error
		deviceError  error
		storageError error
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
				name:         "yandex.disk",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest: someChest,
			},
		},
		{
			name: "empty_name",
			args: testArgs{
				name:         "",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:     someChest,
				nameError: errors.New("empty chest name"),
			},
		},
		{
			name: "select_error",
			args: testArgs{
				name:         "yandex.disk",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:       someChest,
				selectError: errors.New("some error"),
			},
		},
		{
			name: "unlock_error",
			args: testArgs{
				name:         "yandex.disk",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:       someChest,
				unlockError: errors.New("some error"),
			},
		},
		{
			name: "device_error",
			args: testArgs{
				name:         "yandex.disk",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:       someChest,
				deviceError: errors.New("some error"),
			},
		},
		{
			name: "storage_error",
			args: testArgs{
				name:         "yandex.disk",
				lockPassword: "lock",
			},
			expected: testExpected{
				chest:        someChest,
				storageError: errors.New("some error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mockRepos := initGroupMock(t)
			storageMock := mockRepos.storage
			cryptoMock := mockRepos.crypto
			deviceMock := mockRepos.device
			usecase := NewUsecases(mockRepos, cfg, lg)

			defer func() {
				err := usecase.DeleteChest(context.Background(), tt.args.name, tt.args.lockPassword)
				if tt.expected.deviceError != nil ||
					tt.expected.selectError != nil ||
					tt.expected.unlockError != nil ||
					tt.expected.storageError != nil ||
					tt.expected.nameError != nil {
					assert.Error(t, err, "failed while expecting error from DeleteChest()")
					return
				}

				assert.NoError(t, err, "not expected error while doing DeleteChest()")
			}()

			if tt.expected.nameError != nil {
				return
			}

			storageMock.EXPECT().SelectChestByName(mock.Anything, tt.args.name).Return(tt.expected.chest, tt.expected.selectError)
			if tt.expected.selectError != nil {
				return
			}

			someLock := sha256.New().Sum([]byte("some lock"))
			cryptoMock.EXPECT().GenerateLock(tt.expected.chest.Salt, tt.args.lockPassword).Return(someLock)
			cryptoMock.EXPECT().UnlockData(tt.expected.chest.Data, someLock).Return(tt.expected.chest.Data, tt.expected.unlockError)
			if tt.expected.unlockError != nil {
				return
			}

			deviceMock.EXPECT().ExtractDeviceName().Return(&models.DeviceInfo{
				Name: "some_device",
			}, tt.expected.deviceError)
			if tt.expected.deviceError != nil {
				return
			}

			storageMock.EXPECT().Delete(mock.Anything, tt.expected.chest.ID, mock.AnythingOfType("*models.History")).Return(tt.expected.storageError)
			if tt.expected.storageError != nil {
				return
			}
		})
	}
}

func TestGetToken(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while creating config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while creating logger")
	mockRepos := initGroupMock(t)
	viperRepo := mockRepos.viper
	usecase := NewUsecases(mockRepos, cfg, lg)
	viperRepo.EXPECT().GetToken().Return("some-token")
	token := usecase.GetToken()
	assert.NotEmpty(t, token, "token is empty")
}

func TestAuthentification(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while creating config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while creating logger")

	type testArgs struct {
		login    string
		password string
	}

	type testExpected struct {
		token                 string
		emptyPassowrdError    error
		emptyLoginError       error
		connectionError       error
		authentificationError error
		setTokenError         error
		setLoginError         error
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
				login:    "some@login.ru",
				password: "some-strong-password",
			},
			expected: testExpected{
				token: uuid.NewString(),
			},
		},
		{
			name: "empty_password",
			args: testArgs{
				login:    "some@login.ru",
				password: "",
			},
			expected: testExpected{
				token:              uuid.NewString(),
				emptyPassowrdError: errors.New("empty password"),
			},
		},
		{
			name: "empty_login",
			args: testArgs{
				login:    "",
				password: "some-strong-password",
			},
			expected: testExpected{
				token:           uuid.NewString(),
				emptyLoginError: errors.New("empty password"),
			},
		},
		{
			name: "connection_error",
			args: testArgs{
				login:    "some@login.ru",
				password: "some-strong-password",
			},
			expected: testExpected{
				token:           uuid.NewString(),
				connectionError: errors.New("connection error"),
			},
		},
		{
			name: "authentification_error",
			args: testArgs{
				login:    "some@login.ru",
				password: "some-strong-password",
			},
			expected: testExpected{
				token:                 uuid.NewString(),
				authentificationError: errors.New("connection error"),
			},
		},
		{
			name: "set_token_error",
			args: testArgs{
				login:    "some@login.ru",
				password: "some-strong-password",
			},
			expected: testExpected{
				token:         uuid.NewString(),
				setTokenError: errors.New("connection error"),
			},
		},
		{
			name: "set_login_error",
			args: testArgs{
				login:    "some@login.ru",
				password: "some-strong-password",
			},
			expected: testExpected{
				token:         uuid.NewString(),
				setLoginError: errors.New("connection error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mockRepos := initGroupMock(t)
			viperRepo := mockRepos.viper
			syncRepo := mockRepos.sync
			usecase := NewUsecases(mockRepos, cfg, lg)

			defer func() {
				err := usecase.Authentification(context.Background(), tt.args.login, tt.args.password)
				if tt.expected.emptyLoginError != nil ||
					tt.expected.emptyPassowrdError != nil ||
					tt.expected.connectionError != nil ||
					tt.expected.authentificationError != nil ||
					tt.expected.setTokenError != nil ||
					tt.expected.setLoginError != nil {
					assert.Error(t, err, "failed while expecting error from Authentificate()")
					return
				}

				assert.NoError(t, err, "not expected error while doing Authentificate()")
			}()

			if tt.expected.emptyPassowrdError != nil {
				return
			}
			if tt.expected.emptyLoginError != nil {
				return
			}

			syncRepo.EXPECT().EstablishConnection("").Return(tt.expected.connectionError)
			if tt.expected.connectionError != nil {
				handleSyncErrorsMock(syncRepo, tt.expected.connectionError)
				return
			}
			defer syncRepo.EXPECT().CloseConnection().Return(nil)

			syncRepo.EXPECT().Authentification(mock.Anything, &models.AuthData{
				Login:    tt.args.login,
				Password: tt.args.password,
			}).Return(tt.expected.token, tt.expected.authentificationError)
			if tt.expected.authentificationError != nil {
				handleSyncErrorsMock(syncRepo, tt.expected.authentificationError)
				return
			}

			viperRepo.EXPECT().SetToken(tt.expected.token).Return(tt.expected.setTokenError)
			if tt.expected.setTokenError != nil {
				return
			}

			viperRepo.EXPECT().SetLogin(tt.args.login).Return(tt.expected.setLoginError)
			if tt.expected.setLoginError != nil {
				return
			}
		})
	}
}

func TestRegistration(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while creating config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while creating logger")

	type testArgs struct {
		login    string
		password string
	}

	type testExpected struct {
		token                 string
		emptyPassowrdError    error
		emptyLoginError       error
		connectionError       error
		authentificationError error
		setTokenError         error
		setLoginError         error
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
				login:    "some@login.ru",
				password: "some-strong-password",
			},
			expected: testExpected{
				token: uuid.NewString(),
			},
		},
		{
			name: "empty_password",
			args: testArgs{
				login:    "some@login.ru",
				password: "",
			},
			expected: testExpected{
				token:              uuid.NewString(),
				emptyPassowrdError: errors.New("empty password"),
			},
		},
		{
			name: "empty_login",
			args: testArgs{
				login:    "",
				password: "some-strong-password",
			},
			expected: testExpected{
				token:           uuid.NewString(),
				emptyLoginError: errors.New("empty password"),
			},
		},
		{
			name: "connection_error",
			args: testArgs{
				login:    "some@login.ru",
				password: "some-strong-password",
			},
			expected: testExpected{
				token:           uuid.NewString(),
				connectionError: errors.New("connection error"),
			},
		},
		{
			name: "authentification_error",
			args: testArgs{
				login:    "some@login.ru",
				password: "some-strong-password",
			},
			expected: testExpected{
				token:                 uuid.NewString(),
				authentificationError: errors.New("connection error"),
			},
		},
		{
			name: "set_token_error",
			args: testArgs{
				login:    "some@login.ru",
				password: "some-strong-password",
			},
			expected: testExpected{
				token:         uuid.NewString(),
				setTokenError: errors.New("connection error"),
			},
		},
		{
			name: "set_login_error",
			args: testArgs{
				login:    "some@login.ru",
				password: "some-strong-password",
			},
			expected: testExpected{
				token:         uuid.NewString(),
				setLoginError: errors.New("connection error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mockRepos := initGroupMock(t)
			viperRepo := mockRepos.viper
			syncRepo := mockRepos.sync
			usecase := NewUsecases(mockRepos, cfg, lg)

			defer func() {
				err := usecase.Registration(context.Background(), tt.args.login, tt.args.password)
				if tt.expected.emptyLoginError != nil ||
					tt.expected.emptyPassowrdError != nil ||
					tt.expected.connectionError != nil ||
					tt.expected.authentificationError != nil ||
					tt.expected.setTokenError != nil ||
					tt.expected.setLoginError != nil {
					assert.Error(t, err, "failed while expecting error from Authentificate()")
					return
				}

				assert.NoError(t, err, "not expected error while doing Authentificate()")
			}()

			if tt.expected.emptyPassowrdError != nil {
				return
			}
			if tt.expected.emptyLoginError != nil {
				return
			}

			syncRepo.EXPECT().EstablishConnection("").Return(tt.expected.connectionError)
			if tt.expected.connectionError != nil {
				handleSyncErrorsMock(syncRepo, tt.expected.connectionError)
				return
			}
			defer syncRepo.EXPECT().CloseConnection().Return(nil)

			syncRepo.EXPECT().Registration(mock.Anything, &models.AuthData{
				Login:    tt.args.login,
				Password: tt.args.password,
			}).Return(tt.expected.token, tt.expected.authentificationError)
			if tt.expected.authentificationError != nil {
				handleSyncErrorsMock(syncRepo, tt.expected.authentificationError)
				return
			}

			viperRepo.EXPECT().SetToken(tt.expected.token).Return(tt.expected.setTokenError)
			if tt.expected.setTokenError != nil {
				return
			}

			viperRepo.EXPECT().SetLogin(tt.args.login).Return(tt.expected.setLoginError)
			if tt.expected.setLoginError != nil {
				return
			}
		})
	}
}

func TestSync(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")
	someChest := &models.Chest{
		ID:       uuid.NewString(),
		UserID:   nil,
		Salt:     sha256.New().Sum([]byte("some-salt")),
		Name:     "some-name",
		Data:     sha256.New().Sum([]byte("some-data")),
		DataType: 0,
	}
	someHistory := []*models.History{
		{
			ID:            uuid.NewString(),
			ChestID:       uuid.NewString(),
			UserID:        nil,
			OperationType: 0,
			OperationTime: time.Now().Unix(),
			SyncingTime:   nil,
			DeviceName:    "some-device",
			DeviceIP:      nil,
		},
	}
	userID := uuid.NewString()
	syncTime := time.Now().Unix()
	deviceIP := "10.0.0.1"
	someRemoteHistory := []*models.History{
		{
			ID:            uuid.NewString(),
			ChestID:       uuid.NewString(),
			UserID:        &userID,
			OperationType: 1,
			OperationTime: time.Now().Unix(),
			SyncingTime:   &syncTime,
			DeviceName:    "some-device",
			DeviceIP:      &deviceIP,
		},
	}

	type testArgs struct {
	}

	type testExpected struct {
		token           string
		history         []*models.History
		remoteHistory   []*models.History
		chest           *models.Chest
		tokenError      error
		storageError    error
		connectionError error
		syncError       error
		poolError       error
	}

	type testData struct {
		name     string
		args     testArgs
		expected testExpected
	}

	data := []testData{
		{
			name: "success",
			args: testArgs{},
			expected: testExpected{
				token:         uuid.NewString(),
				history:       someHistory,
				remoteHistory: someRemoteHistory,
				chest:         someChest,
			},
		},
		{
			name: "empty_token",
			args: testArgs{},
			expected: testExpected{
				token:         "",
				history:       someHistory,
				remoteHistory: someRemoteHistory,
				tokenError:    errors.New("empty token"),
			},
		},
		{
			name: "storage_error",
			args: testArgs{},
			expected: testExpected{
				token:         uuid.NewString(),
				history:       someHistory,
				remoteHistory: someRemoteHistory,
				storageError:  errors.New("storage error"),
			},
		},
		{
			name: "connection_error",
			args: testArgs{},
			expected: testExpected{
				token:           uuid.NewString(),
				history:         someHistory,
				remoteHistory:   someRemoteHistory,
				connectionError: errors.New("connection error"),
			},
		},
		{
			name: "sync_error",
			args: testArgs{},
			expected: testExpected{
				token:         uuid.NewString(),
				history:       someHistory,
				remoteHistory: someRemoteHistory,
				syncError:     errors.New("sync error"),
			},
		},
		{
			name: "pool_error",
			args: testArgs{},
			expected: testExpected{
				token:         uuid.NewString(),
				history:       someHistory,
				remoteHistory: someRemoteHistory,
				chest:         someChest,
				poolError:     errors.New("pool error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			groupMock := initGroupMock(t)
			storageRepo := groupMock.storage
			viperRepo := groupMock.viper
			syncRepo := groupMock.sync
			usecase := NewUsecases(groupMock, cfg, lg)

			defer func() {
				buf := os.Stdout
				err := usecase.Sync(context.Background(), buf)
				if tt.expected.tokenError != nil ||
					tt.expected.connectionError != nil ||
					tt.expected.storageError != nil ||
					tt.expected.syncError != nil ||
					tt.expected.poolError != nil {
					assert.Error(t, err, "failed while expecting error from Sync()")
					return
				}

				assert.NoError(t, err, "not expected error while doing Sync()")
			}()

			viperRepo.EXPECT().GetToken().Return(tt.expected.token)
			if tt.expected.tokenError != nil {
				return
			}

			storageRepo.EXPECT().SelectLastHistoryEventForAllChests(mock.Anything).Return(tt.expected.history, tt.expected.storageError)
			if tt.expected.storageError != nil {
				return
			}

			syncRepo.EXPECT().EstablishConnection(tt.expected.token).Return(tt.expected.connectionError)
			if tt.expected.connectionError != nil {
				handleSyncErrorsMock(syncRepo, tt.expected.connectionError)
				return
			}
			defer syncRepo.EXPECT().CloseConnection().Return(nil)

			syncRepo.EXPECT().Sync(mock.Anything, tt.expected.history).Return(tt.expected.remoteHistory, tt.expected.syncError)
			if tt.expected.syncError != nil {
				handleSyncErrorsMock(syncRepo, tt.expected.syncError)
				return
			}

			syncRepo.EXPECT().GetChestByID(mock.Anything, mock.AnythingOfType("string")).Return(tt.expected.chest, tt.expected.history[0], tt.expected.poolError)
			if tt.expected.poolError != nil {
				handleSyncErrorsMock(syncRepo, tt.expected.poolError)
				return
			}

			storageRepo.EXPECT().Upsert(mock.Anything, tt.expected.chest, tt.expected.history[0]).Return(nil)
		})
	}
}

func TestHandleSyncErrors(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err)
	lg, err := zap.NewDevelopment()
	require.NoError(t, err)

	t.Run("auth_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		syncRepo := groupMock.sync
		usecase := NewUsecases(groupMock, cfg, lg)

		syncRepo.EXPECT().IsAuthentificationError(mock.Anything).Return(true)
		err := usecase.handleSyncErrors(errors.New("auth error"))
		assert.Error(t, err, "failed while expecting error from handleSyncErrors()")
	})

	t.Run("bad_user_data_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		syncRepo := groupMock.sync
		usecase := NewUsecases(groupMock, cfg, lg)

		syncRepo.EXPECT().IsAuthentificationError(mock.Anything).Return(false)
		syncRepo.EXPECT().BadUserDataError(mock.Anything).Return(errors.New("bad user data error"))
		err := usecase.handleSyncErrors(errors.New("auth error"))
		assert.Error(t, err, "failed while expecting error from handleSyncErrors()")
	})

	t.Run("connection_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		syncRepo := groupMock.sync
		usecase := NewUsecases(groupMock, cfg, lg)

		syncRepo.EXPECT().IsAuthentificationError(mock.Anything).Return(false)
		syncRepo.EXPECT().BadUserDataError(mock.Anything).Return(nil)
		syncRepo.EXPECT().IsConnectionError(mock.Anything).Return(true)
		err := usecase.handleSyncErrors(errors.New("auth error"))
		assert.Error(t, err, "failed while expecting error from handleSyncErrors()")
	})

	t.Run("data_already_exists_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		syncRepo := groupMock.sync
		usecase := NewUsecases(groupMock, cfg, lg)

		syncRepo.EXPECT().IsAuthentificationError(mock.Anything).Return(false)
		syncRepo.EXPECT().BadUserDataError(mock.Anything).Return(nil)
		syncRepo.EXPECT().IsConnectionError(mock.Anything).Return(false)
		syncRepo.EXPECT().IsDataAlreadyExistsError(mock.Anything).Return(true)
		err := usecase.handleSyncErrors(errors.New("auth error"))
		assert.Error(t, err, "failed while expecting error from handleSyncErrors()")
	})

	t.Run("not_found_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		syncRepo := groupMock.sync
		usecase := NewUsecases(groupMock, cfg, lg)

		syncRepo.EXPECT().IsAuthentificationError(mock.Anything).Return(false)
		syncRepo.EXPECT().BadUserDataError(mock.Anything).Return(nil)
		syncRepo.EXPECT().IsConnectionError(mock.Anything).Return(false)
		syncRepo.EXPECT().IsDataAlreadyExistsError(mock.Anything).Return(false)
		syncRepo.EXPECT().IsNotFoundError(mock.Anything).Return(true)
		err := usecase.handleSyncErrors(errors.New("auth error"))
		assert.Error(t, err, "failed while expecting error from handleSyncErrors()")
	})

	t.Run("default_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		syncRepo := groupMock.sync
		usecase := NewUsecases(groupMock, cfg, lg)

		syncRepo.EXPECT().IsAuthentificationError(mock.Anything).Return(false)
		syncRepo.EXPECT().BadUserDataError(mock.Anything).Return(nil)
		syncRepo.EXPECT().IsConnectionError(mock.Anything).Return(false)
		syncRepo.EXPECT().IsDataAlreadyExistsError(mock.Anything).Return(false)
		syncRepo.EXPECT().IsNotFoundError(mock.Anything).Return(false)
		err := usecase.handleSyncErrors(errors.New("auth error"))
		assert.Error(t, err, "failed while expecting error from handleSyncErrors()")
	})

	t.Run("default_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		usecase := NewUsecases(groupMock, cfg, lg)

		err := usecase.handleSyncErrors(nil)
		assert.Nil(t, err, "failed while expecting error from handleSyncErrors()")
	})
}

func TestHandleStorageErrors(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing logger")

	t.Run("not_found_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		storageRepo := groupMock.storage
		usecase := NewUsecases(groupMock, cfg, lg)

		storageRepo.EXPECT().IsNotFoundError(mock.Anything).Return(true)
		err := usecase.handleStorageErrors(errors.New("auth error"))
		var ucerr *usecasesError
		if errors.As(err, &ucerr) {
			assert.True(t, ucerr.errType == notFoundUsecaseError, "failed while expecting error from handleStorageErrors()")
		} else {
			assert.Fail(t, "failed while expecting error from handleStorageErrors()")
		}

	})

	t.Run("conflict_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		storageRepo := groupMock.storage
		usecase := NewUsecases(groupMock, cfg, lg)

		storageRepo.EXPECT().IsNotFoundError(mock.Anything).Return(false)
		storageRepo.EXPECT().IsConfictError(mock.Anything).Return(true)
		err := usecase.handleStorageErrors(errors.New("auth error"))
		var ucerr *usecasesError
		if errors.As(err, &ucerr) {
			assert.True(t, ucerr.errType == conflictUsecaseError, "failed while expecting error from handleStorageErrors()")
		} else {
			assert.Fail(t, "failed while expecting error from handleStorageErrors()")
		}

	})

	t.Run("internal_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		storageRepo := groupMock.storage
		usecase := NewUsecases(groupMock, cfg, lg)

		storageRepo.EXPECT().IsNotFoundError(mock.Anything).Return(false)
		storageRepo.EXPECT().IsConfictError(mock.Anything).Return(false)
		err := usecase.handleStorageErrors(errors.New("auth error"))
		var ucerr *usecasesError
		if errors.As(err, &ucerr) {
			assert.True(t, ucerr.errType == internalUsecaseError, "failed while expecting error from handleStorageErrors()")
		} else {
			assert.Fail(t, "failed while expecting error from handleStorageErrors()")
		}

	})

	t.Run("nil_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		usecase := NewUsecases(groupMock, cfg, lg)

		err := usecase.handleStorageErrors(nil)
		assert.Nil(t, err, "failed while expecting error from handleStorageErrors()")
	})
}

func TestHandleEncryptionErrors(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing logger")

	t.Run("nil_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		usecase := NewUsecases(groupMock, cfg, lg)

		err := usecase.handleEncryptionErrors(nil)
		assert.Nil(t, err, "failed while expecting error from handleEncryptionErrors()")
	})

	t.Run("bad_user_data_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		cryptoRepo := groupMock.crypto
		usecase := NewUsecases(groupMock, cfg, lg)

		cryptoRepo.EXPECT().IsBadUserData(mock.Anything).Return(true)

		err := usecase.handleEncryptionErrors(errors.New("auth error"))
		assert.Error(t, err, "failed while expecting error from handleEncryptionErrors()")
		var ucerr *usecasesError
		if errors.As(err, &ucerr) {
			assert.True(t, ucerr.errType == badDataUsecaseError, "failed while expecting error from handleEncryptionErrors()")
		} else {
			assert.Fail(t, "failed while expecting error from handleEncryptionErrors()")
		}
	})

	t.Run("internal_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		cryptoRepo := groupMock.crypto
		usecase := NewUsecases(groupMock, cfg, lg)

		cryptoRepo.EXPECT().IsBadUserData(mock.Anything).Return(false)

		err := usecase.handleEncryptionErrors(errors.New("auth error"))
		assert.Error(t, err, "failed while expecting error from handleEncryptionErrors()")
	})

}

func TestUsecaseErrors(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing logger")

	t.Run("internal_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		usecase := NewUsecases(groupMock, cfg, lg)

		uErr := NewUsecaseError("some error", internalUsecaseError, errors.New("some error"))
		assert.True(t, usecase.IsInternalError(uErr), "failed while expecting error from IsInternalError()")
		assert.False(t, usecase.IsInternalError(errors.New("some")), "failed while expecting error from IsNotFoundError()")
	})

	t.Run("extract_user_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		usecase := NewUsecases(groupMock, cfg, lg)

		uErr := NewUsecaseError("some error", internalUsecaseError, errors.New("some error"))
		assert.Equal(t, "some error", usecase.ExtractUserError(uErr).Error(), "failed while expecting error from ExtractUserError()")
		assert.Equal(t, errors.New("some").Error(), usecase.ExtractUserError(errors.New("some")).Error(), "failed while expecting error from IsNotFoundError()")
		assert.NotEmpty(t, uErr.Error(), "failed while expecting error")
		assert.Error(t, errors.Unwrap(uErr), "failed while expecting error")
	})

	t.Run("usecase_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		usecase := NewUsecases(groupMock, cfg, lg)

		uErr := NewUsecaseError("some error", internalUsecaseError, errors.New("some error"))
		assert.True(t, usecase.IsUsecaseError(uErr), "failed while expecting error")
		assert.False(t, usecase.IsUsecaseError(errors.New("some")), "failed while expecting error")
	})

	t.Run("auth_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		usecase := NewUsecases(groupMock, cfg, lg)

		uErr := NewUsecaseError("some error", authentificationUsecaseError, errors.New("some error"))
		assert.True(t, usecase.IsAuthentificationError(uErr), "failed while expecting error")
		assert.False(t, usecase.IsAuthentificationError(errors.New("some")), "failed while expecting error")
	})

	t.Run("auth_error", func(t *testing.T) {
		groupMock := initGroupMock(t)
		syncRepo := groupMock.sync
		usecase := NewUsecases(groupMock, cfg, lg)

		syncRepo.EXPECT().IsConnectionError(mock.Anything).Return(true)
		status := usecase.IsConnectionProblem(errors.New("some error"))
		assert.True(t, status, "failed while expecting error")
	})
}

func TestAddPassword(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing logger")

	t.Run("success", func(t *testing.T) {
		groupMock := initGroupMock(t)
		cryptoRepo := groupMock.crypto
		storageRepo := groupMock.storage
		deviceRepo := groupMock.device
		usecase := NewUsecases(groupMock, cfg, lg)

		defer func() {
			err := usecase.AddPassword(context.Background(), "yandex.disk", "some-password", "some-lock-password")
			assert.NoError(t, err, "failed while expecting error from AddPassword()")
		}()

		addChestMock(cryptoRepo, storageRepo, deviceRepo, "some-lock-password", nil)
	})
}

func TestAddCard(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing logger")

	t.Run("success", func(t *testing.T) {
		groupMock := initGroupMock(t)
		cryptoRepo := groupMock.crypto
		storageRepo := groupMock.storage
		deviceRepo := groupMock.device
		usecase := NewUsecases(groupMock, cfg, lg)

		defer func() {
			err := usecase.AddCard(context.Background(), "yandex.disk", &models.Card{
				Number:  "1234 1345 1234 1234",
				Owner:   "John Doe",
				Expired: "12/22",
				Cvv:     "123",
			}, "some-lock-password")
			assert.NoError(t, err, "failed while expecting error from AddCard()")
		}()

		addChestMock(cryptoRepo, storageRepo, deviceRepo, "some-lock-password", nil)
	})
}

func TestAddFile(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing logger")

	t.Run("success", func(t *testing.T) {
		groupMock := initGroupMock(t)
		cryptoRepo := groupMock.crypto
		storageRepo := groupMock.storage
		deviceRepo := groupMock.device
		usecase := NewUsecases(groupMock, cfg, lg)

		someFile := sha256.New().Sum([]byte("some-file"))

		defer func() {
			err := usecase.AddFile(context.Background(), "yandex.disk", someFile, "some-lock-password")
			assert.NoError(t, err, "failed while expecting error from AddCard()")
		}()

		addChestMock(cryptoRepo, storageRepo, deviceRepo, "some-lock-password", nil)
	})

	t.Run("empty_file", func(t *testing.T) {
		groupMock := initGroupMock(t)
		usecase := NewUsecases(groupMock, cfg, lg)

		someFile := []byte{}

		defer func() {
			err := usecase.AddFile(context.Background(), "yandex.disk", someFile, "some-lock-password")
			assert.Error(t, err, "failed while expecting error from AddFile()")
		}()
	})
}

func TestEditPassword(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing logger")

	t.Run("success", func(t *testing.T) {
		groupMock := initGroupMock(t)
		cryptoRepo := groupMock.crypto
		storageRepo := groupMock.storage
		deviceRepo := groupMock.device
		usecase := NewUsecases(groupMock, cfg, lg)

		defer func() {
			err := usecase.EditPassword(context.Background(), "yandex.disk", "", "some-password", "some-lock-password")
			assert.NoError(t, err, "failed while expecting error from EditPassword()")
		}()
		expectedChest := &models.Chest{
			ID:       uuid.NewString(),
			UserID:   nil,
			Salt:     sha256.New().Sum([]byte("some-salt")),
			Name:     "some-file",
			Data:     []byte("some-password"),
			DataType: models.ChestPasswordData,
		}
		editChestMock(cryptoRepo, storageRepo, deviceRepo, expectedChest, "some-lock-password", nil)
	})
}

func TestEditFile(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing logger")

	t.Run("success", func(t *testing.T) {
		groupMock := initGroupMock(t)
		cryptoRepo := groupMock.crypto
		storageRepo := groupMock.storage
		deviceRepo := groupMock.device
		usecase := NewUsecases(groupMock, cfg, lg)

		someFile := []byte("some-file")
		expectedChest := &models.Chest{
			ID:       uuid.NewString(),
			UserID:   nil,
			Salt:     sha256.New().Sum([]byte("some-salt")),
			Name:     "some-file",
			Data:     someFile,
			DataType: models.ChestFileData,
		}

		defer func() {
			err := usecase.EditFile(context.Background(), "yandex.disk", "", someFile, "some-lock-password")
			assert.NoError(t, err, "failed while expecting error from EditFile()")
		}()

		editChestMock(cryptoRepo, storageRepo, deviceRepo, expectedChest, "some-lock-password", nil)
	})
}

func TestEditCard(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing logger")

	t.Run("success", func(t *testing.T) {
		groupMock := initGroupMock(t)
		cryptoRepo := groupMock.crypto
		storageRepo := groupMock.storage
		deviceRepo := groupMock.device
		usecase := NewUsecases(groupMock, cfg, lg)

		someCard := &models.Card{
			Number:  "1234 1345 1234 1234",
			Owner:   "John Doe",
			Expired: "12/22",
			Cvv:     "123",
		}
		byteCard, _ := cardToBytes(someCard)

		defer func() {
			err := usecase.EditCard(context.Background(), "yandex.disk", "", someCard, "some-lock-password")
			assert.NoError(t, err, "failed while expecting error from EditCard()")
		}()

		expectedChest := &models.Chest{
			ID:       uuid.NewString(),
			UserID:   nil,
			Salt:     sha256.New().Sum([]byte("some-salt")),
			Name:     "credit card",
			Data:     byteCard,
			DataType: models.ChestCreditCardData,
		}
		editChestMock(cryptoRepo, storageRepo, deviceRepo, expectedChest, "some-lock-password", nil)
	})
}

func TestHandleSyncHistoryLocal(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing logger")

	type testArgs struct {
		history *models.History
	}

	type testExpected struct {
		remoteHistory      *models.History
		remoteChest        *models.Chest
		syncError          error
		storageError       error
		deleteStorageError error
		syncTimeError      error
	}

	type testData struct {
		name     string
		args     testArgs
		expected testExpected
	}
	chestID := uuid.NewString()

	data := []testData{
		{
			name: "success_create",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryCreateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        strAsRef(uuid.NewString()),
					OperationType: models.HistoryCreateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   int64AsRef(time.Now().Unix()),
					DeviceName:    "some-device",
					DeviceIP:      strAsRef("10.0.0.1"),
				},
			},
		},
		{
			name: "get_chest_error_when_create",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryCreateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        strAsRef(uuid.NewString()),
					OperationType: models.HistoryCreateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   int64AsRef(time.Now().Unix()),
					DeviceName:    "some-device",
					DeviceIP:      strAsRef("10.0.0.1"),
				},
				syncError: errors.New("some-error"),
			},
		},
		{
			name: "insert_chest_error_when_create",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryCreateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        strAsRef(uuid.NewString()),
					OperationType: models.HistoryCreateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   int64AsRef(time.Now().Unix()),
					DeviceName:    "some-device",
					DeviceIP:      strAsRef("10.0.0.1"),
				},
				storageError: errors.New("some-error"),
			},
		},
		{
			name: "success_update",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryUpdateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        strAsRef(uuid.NewString()),
					OperationType: models.HistoryCreateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   int64AsRef(time.Now().Unix()),
					DeviceName:    "some-device",
					DeviceIP:      strAsRef("10.0.0.1"),
				},
			},
		},
		{
			name: "get_chest_error_when_update",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryUpdateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        strAsRef(uuid.NewString()),
					OperationType: models.HistoryUpdateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   int64AsRef(time.Now().Unix()),
					DeviceName:    "some-device",
					DeviceIP:      strAsRef("10.0.0.1"),
				},
				syncError: errors.New("some-error"),
			},
		},
		{
			name: "insert_chest_error_when_update",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryUpdateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        strAsRef(uuid.NewString()),
					OperationType: models.HistoryUpdateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   int64AsRef(time.Now().Unix()),
					DeviceName:    "some-device",
					DeviceIP:      strAsRef("10.0.0.1"),
				},
				storageError: errors.New("some-error"),
			},
		},
		{
			name: "success_delete",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryDeleteOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   int64AsRef(time.Now().Unix()),
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        strAsRef(uuid.NewString()),
					OperationType: models.HistoryDeleteOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   int64AsRef(time.Now().Unix()),
					DeviceName:    "some-device",
					DeviceIP:      strAsRef("10.0.0.1"),
				},
			},
		},
		{
			name: "get_chest_error_when_delete",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryDeleteOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   int64AsRef(time.Now().Unix()),
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        strAsRef(uuid.NewString()),
					OperationType: models.HistoryDeleteOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   int64AsRef(time.Now().Unix()),
					DeviceName:    "some-device",
					DeviceIP:      strAsRef("10.0.0.1"),
				},
				deleteStorageError: errors.New("some-error"),
			},
		},
		{
			name: "delete_chest_error_when_delete",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryDeleteOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   int64AsRef(time.Now().Unix()),
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        strAsRef(uuid.NewString()),
					OperationType: models.HistoryCreateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   int64AsRef(time.Now().Unix()),
					DeviceName:    "some-device",
					DeviceIP:      strAsRef("10.0.0.1"),
				},
				storageError: errors.New("some-error"),
			},
		},
		{
			name: "sync_time_error_when_delete",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryDeleteOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        strAsRef(uuid.NewString()),
					OperationType: models.HistoryCreateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   int64AsRef(time.Now().Unix()),
					DeviceName:    "some-device",
					DeviceIP:      strAsRef("10.0.0.1"),
				},
				syncTimeError: errors.New("some-error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mockGroup := initGroupMock(t)
			syncRepo := mockGroup.sync
			storRepo := mockGroup.storage
			usecase := NewUsecases(mockGroup, cfg, lg)

			defer func() {
				err := usecase.handSyncHistoryLocal(context.Background(), tt.args.history)
				if tt.expected.syncError != nil ||
					tt.expected.storageError != nil ||
					tt.expected.syncTimeError != nil ||
					tt.expected.deleteStorageError != nil {
					assert.Error(t, err, "failed while expecting error from handSyncHistoryLocal()")
					return
				}

				assert.NoError(t, err, "failed while not expecting error from handSyncHistoryLocal()")
			}()

			switch tt.args.history.OperationType {
			case models.HistoryCreateOperation:
				syncRepo.EXPECT().GetChestByID(mock.Anything, tt.args.history.ChestID).Return(tt.expected.remoteChest, tt.expected.remoteHistory, tt.expected.syncError)
				if tt.expected.syncError != nil {
					handleSyncErrorsMock(syncRepo, tt.expected.syncError)
					return
				}

				storRepo.EXPECT().Insert(mock.Anything, tt.expected.remoteChest, tt.expected.remoteHistory).Return(tt.expected.storageError)
				if tt.expected.storageError != nil {
					return
				}
			case models.HistoryUpdateOperation:
				syncRepo.EXPECT().GetChestByID(mock.Anything, tt.args.history.ChestID).Return(tt.expected.remoteChest, tt.expected.remoteHistory, tt.expected.syncError)
				if tt.expected.syncError != nil {
					handleSyncErrorsMock(syncRepo, tt.expected.syncError)
					return
				}

				storRepo.EXPECT().Upsert(mock.Anything, tt.expected.remoteChest, tt.expected.remoteHistory).Return(tt.expected.storageError)
				if tt.expected.storageError != nil {
					return
				}
			case models.HistoryDeleteOperation:
				storRepo.EXPECT().Delete(mock.Anything, tt.args.history.ChestID, tt.args.history).Return(tt.expected.deleteStorageError)
				if tt.expected.deleteStorageError != nil {
					storRepo.EXPECT().IsNotFoundError(tt.expected.deleteStorageError).Return(false)
					return
				}

				if tt.expected.syncTimeError != nil {
					return
				}

				storRepo.EXPECT().UpdateHistorySyncData(mock.Anything, tt.args.history).Return(tt.expected.storageError)
				if tt.expected.syncTimeError != nil {
					return
				}
			}

		})
	}

}

func TestHandleSyncHistoryRemote(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing logger")

	type testArgs struct {
		history *models.History
	}

	type testExpected struct {
		remoteHistory      []*models.History
		remoteChest        *models.Chest
		syncError          error
		storageError       error
		updateStorageError error
		syncTimeError      error
	}

	type testData struct {
		name     string
		args     testArgs
		expected testExpected
	}
	chestID := uuid.NewString()

	data := []testData{
		{
			name: "success_create",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryCreateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: []*models.History{
					{
						ID:            uuid.NewString(),
						ChestID:       chestID,
						UserID:        strAsRef(uuid.NewString()),
						OperationType: models.HistoryCreateOperation,
						OperationTime: time.Now().Unix(),
						SyncingTime:   int64AsRef(time.Now().Unix()),
						DeviceName:    "some-device",
						DeviceIP:      strAsRef("10.0.0.1"),
					},
				},
			},
		},
		{
			name: "sync_error_when_create",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryCreateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: []*models.History{
					{
						ID:            uuid.NewString(),
						ChestID:       chestID,
						UserID:        strAsRef(uuid.NewString()),
						OperationType: models.HistoryCreateOperation,
						OperationTime: time.Now().Unix(),
						SyncingTime:   int64AsRef(time.Now().Unix()),
						DeviceName:    "some-device",
						DeviceIP:      strAsRef("10.0.0.1"),
					},
				},
				syncError: errors.New("some-error"),
			},
		},
		{
			name: "storage_error_when_create",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryCreateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: []*models.History{
					{
						ID:            uuid.NewString(),
						ChestID:       chestID,
						UserID:        strAsRef(uuid.NewString()),
						OperationType: models.HistoryCreateOperation,
						OperationTime: time.Now().Unix(),
						SyncingTime:   int64AsRef(time.Now().Unix()),
						DeviceName:    "some-device",
						DeviceIP:      strAsRef("10.0.0.1"),
					},
				},
				storageError: errors.New("some-error"),
			},
		},
		{
			name: "sync_time_error_when_create",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryCreateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: []*models.History{
					{
						ID:            uuid.NewString(),
						ChestID:       chestID,
						UserID:        strAsRef(uuid.NewString()),
						OperationType: models.HistoryCreateOperation,
						OperationTime: time.Now().Unix(),
						SyncingTime:   nil,
						DeviceName:    "some-device",
						DeviceIP:      strAsRef("10.0.0.1"),
					},
				},
				syncTimeError: errors.New("some-error"),
			},
		},
		{
			name: "udpate_storage_error_when_create",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryCreateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: []*models.History{
					{
						ID:            uuid.NewString(),
						ChestID:       chestID,
						UserID:        strAsRef(uuid.NewString()),
						OperationType: models.HistoryCreateOperation,
						OperationTime: time.Now().Unix(),
						SyncingTime:   int64AsRef(time.Now().Unix()),
						DeviceName:    "some-device",
						DeviceIP:      strAsRef("10.0.0.1"),
					},
				},
				updateStorageError: errors.New("some-error"),
			},
		},
		{
			name: "success_update",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryUpdateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: []*models.History{
					{
						ID:            uuid.NewString(),
						ChestID:       chestID,
						UserID:        strAsRef(uuid.NewString()),
						OperationType: models.HistoryUpdateOperation,
						OperationTime: time.Now().Unix(),
						SyncingTime:   int64AsRef(time.Now().Unix()),
						DeviceName:    "some-device",
						DeviceIP:      strAsRef("10.0.0.1"),
					},
				},
			},
		},
		{
			name: "sync_error_when_update",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryUpdateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: []*models.History{
					{
						ID:            uuid.NewString(),
						ChestID:       chestID,
						UserID:        strAsRef(uuid.NewString()),
						OperationType: models.HistoryUpdateOperation,
						OperationTime: time.Now().Unix(),
						SyncingTime:   int64AsRef(time.Now().Unix()),
						DeviceName:    "some-device",
						DeviceIP:      strAsRef("10.0.0.1"),
					},
				},
				syncError: errors.New("some-error"),
			},
		},
		{
			name: "storage_error_when_update",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryUpdateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: []*models.History{
					{
						ID:            uuid.NewString(),
						ChestID:       chestID,
						UserID:        strAsRef(uuid.NewString()),
						OperationType: models.HistoryUpdateOperation,
						OperationTime: time.Now().Unix(),
						SyncingTime:   int64AsRef(time.Now().Unix()),
						DeviceName:    "some-device",
						DeviceIP:      strAsRef("10.0.0.1"),
					},
				},
				storageError: errors.New("some-error"),
			},
		},
		{
			name: "sync_time_error_when_update",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryUpdateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: []*models.History{
					{
						ID:            uuid.NewString(),
						ChestID:       chestID,
						UserID:        strAsRef(uuid.NewString()),
						OperationType: models.HistoryUpdateOperation,
						OperationTime: time.Now().Unix(),
						SyncingTime:   nil,
						DeviceName:    "some-device",
						DeviceIP:      strAsRef("10.0.0.1"),
					},
				},
				syncTimeError: errors.New("some-error"),
			},
		},
		{
			name: "udpate_storage_error_when_update",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryUpdateOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: []*models.History{
					{
						ID:            uuid.NewString(),
						ChestID:       chestID,
						UserID:        strAsRef(uuid.NewString()),
						OperationType: models.HistoryUpdateOperation,
						OperationTime: time.Now().Unix(),
						SyncingTime:   int64AsRef(time.Now().Unix()),
						DeviceName:    "some-device",
						DeviceIP:      strAsRef("10.0.0.1"),
					},
				},
				updateStorageError: errors.New("some-error"),
			},
		},
		{
			name: "success_delete",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryDeleteOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: []*models.History{
					{
						ID:            uuid.NewString(),
						ChestID:       chestID,
						UserID:        strAsRef(uuid.NewString()),
						OperationType: models.HistoryDeleteOperation,
						OperationTime: time.Now().Unix(),
						SyncingTime:   int64AsRef(time.Now().Unix()),
						DeviceName:    "some-device",
						DeviceIP:      strAsRef("10.0.0.1"),
					},
				},
			},
		},
		{
			name: "sync_error_when_delete",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryDeleteOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: []*models.History{
					{
						ID:            uuid.NewString(),
						ChestID:       chestID,
						UserID:        strAsRef(uuid.NewString()),
						OperationType: models.HistoryDeleteOperation,
						OperationTime: time.Now().Unix(),
						SyncingTime:   int64AsRef(time.Now().Unix()),
						DeviceName:    "some-device",
						DeviceIP:      strAsRef("10.0.0.1"),
					},
				},
				syncError: errors.New("some-error"),
			},
		},
		{
			name: "sync_time_error_when_delete",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryDeleteOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: []*models.History{
					{
						ID:            uuid.NewString(),
						ChestID:       chestID,
						UserID:        strAsRef(uuid.NewString()),
						OperationType: models.HistoryDeleteOperation,
						OperationTime: time.Now().Unix(),
						SyncingTime:   nil,
						DeviceName:    "some-device",
						DeviceIP:      strAsRef("10.0.0.1"),
					},
				},
				syncTimeError: errors.New("some-error"),
			},
		},
		{
			name: "update_storage_error_when_delete",
			args: testArgs{
				history: &models.History{
					ID:            uuid.NewString(),
					ChestID:       chestID,
					UserID:        nil,
					OperationType: models.HistoryDeleteOperation,
					OperationTime: time.Now().Unix(),
					SyncingTime:   nil,
					DeviceName:    "some-device",
					DeviceIP:      nil,
				},
			},
			expected: testExpected{
				remoteChest: &models.Chest{
					ID:       chestID,
					UserID:   strAsRef(uuid.NewString()),
					Salt:     sha256.New().Sum([]byte("some-salt")),
					Name:     "some-file",
					Data:     []byte("some-password"),
					DataType: models.ChestFileData,
				},
				remoteHistory: []*models.History{
					{
						ID:            uuid.NewString(),
						ChestID:       chestID,
						UserID:        strAsRef(uuid.NewString()),
						OperationType: models.HistoryDeleteOperation,
						OperationTime: time.Now().Unix(),
						SyncingTime:   int64AsRef(time.Now().Unix()),
						DeviceName:    "some-device",
						DeviceIP:      strAsRef("10.0.0.1"),
					},
				},
				updateStorageError: errors.New("some-error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mockGroup := initGroupMock(t)
			syncRepo := mockGroup.sync
			storRepo := mockGroup.storage
			usecase := NewUsecases(mockGroup, cfg, lg)

			defer func() {
				err := usecase.handleSyncHistoryRemote(context.Background(), tt.args.history)
				if tt.expected.syncError != nil ||
					tt.expected.storageError != nil ||
					tt.expected.syncTimeError != nil ||
					tt.expected.updateStorageError != nil {
					assert.Error(t, err, "failed while expecting error from handSyncHistoryLocal()")
					return
				}

				assert.NoError(t, err, "failed while not expecting error from handSyncHistoryLocal()")
			}()

			switch tt.args.history.OperationType {
			case models.HistoryCreateOperation:
				storRepo.EXPECT().SelectChestAndHistoryByID(mock.Anything, tt.args.history.ChestID).Return(tt.expected.remoteChest, tt.expected.remoteHistory, tt.expected.storageError)
				if tt.expected.storageError != nil {
					handleStorageErrorsMock(storRepo, tt.expected.storageError)
					return
				}

				syncRepo.EXPECT().AddChest(mock.Anything, mock.AnythingOfType("*models.Chest"), mock.AnythingOfType("*models.History")).Return(tt.expected.remoteHistory[0], tt.expected.syncError)
				if tt.expected.syncError != nil {
					handleSyncErrorsMock(syncRepo, tt.expected.syncError)
					return
				}

				if tt.expected.syncTimeError != nil {
					return
				}

				storRepo.EXPECT().UpdateHistorySyncData(mock.Anything, mock.AnythingOfType("*models.History")).Return(tt.expected.updateStorageError)
				if tt.expected.updateStorageError != nil {
					handleStorageErrorsMock(storRepo, tt.expected.updateStorageError)
					return
				}

			case models.HistoryUpdateOperation:
				storRepo.EXPECT().SelectChestAndHistoryByID(mock.Anything, tt.args.history.ChestID).Return(tt.expected.remoteChest, tt.expected.remoteHistory, tt.expected.storageError)
				if tt.expected.storageError != nil {
					handleStorageErrorsMock(storRepo, tt.expected.storageError)
					return
				}

				syncRepo.EXPECT().UpdateChest(mock.Anything, mock.AnythingOfType("*models.Chest"), mock.AnythingOfType("*models.History")).Return(tt.expected.remoteHistory[0], tt.expected.syncError)
				if tt.expected.syncError != nil {
					handleSyncErrorsMock(syncRepo, tt.expected.syncError)
					return
				}

				if tt.expected.syncTimeError != nil {
					return
				}

				storRepo.EXPECT().UpdateHistorySyncData(mock.Anything, mock.AnythingOfType("*models.History")).Return(tt.expected.updateStorageError)
				if tt.expected.updateStorageError != nil {
					handleStorageErrorsMock(storRepo, tt.expected.updateStorageError)
					return
				}

			case models.HistoryDeleteOperation:
				syncRepo.EXPECT().DeleteChest(mock.Anything, mock.AnythingOfType("*models.History")).Return(tt.expected.remoteHistory[0], tt.expected.syncError)
				if tt.expected.syncError != nil {
					handleSyncErrorsMock(syncRepo, tt.expected.syncError)
					return
				}

				if tt.expected.syncTimeError != nil {
					return
				}

				storRepo.EXPECT().UpdateHistorySyncData(mock.Anything, mock.AnythingOfType("*models.History")).Return(tt.expected.updateStorageError)
				if tt.expected.updateStorageError != nil {
					handleStorageErrorsMock(storRepo, tt.expected.updateStorageError)
					return
				}

			}

		})
	}

}

func TestCardToByte(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		someCard := &models.Card{
			Number:  "1234 1234 1234 1234",
			Owner:   "John Doe",
			Expired: "12/21",
			Cvv:     "123",
		}

		b, err := cardToBytes(someCard)
		assert.NoError(t, err, "failed while not expecting error from cardToByte()")

		assert.IsType(t, []byte{}, b, "failed while expecting []byte from cardToByte()")
	})

	t.Run("nil", func(t *testing.T) {
		b, err := cardToBytes(nil)
		assert.NoError(t, err, "failed while not expecting error from cardToByte()")

		assert.Nil(t, b, "failed while expecting nil from cardToByte()")
	})
}

func TestBytesToCard(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		someCard := &models.Card{
			Number:  "1234 1234 1234 1234",
			Owner:   "John Doe",
			Expired: "12/21",
			Cvv:     "123",
		}
		b, err := cardToBytes(someCard)
		require.NoError(t, err, "failed while not expecting error from cardToByte()")

		c, err := bytesToCard(b)
		assert.NoError(t, err, "failed while not expecting error from bytesToCard()")
		assert.IsType(t, &models.Card{}, c, "failed while expecting *models.Card from bytesToCard()")
	})

	t.Run("nil", func(t *testing.T) {
		b, err := cardToBytes(nil)
		require.NoError(t, err, "failed while not expecting error from cardToByte()")

		_, err = bytesToCard(b)
		assert.Error(t, err, "failed while expecting error from bytesToCard()")
	})

	t.Run("unmarshal_error", func(t *testing.T) {
		b := []byte("some-invalid-bytes")
		_, err := bytesToCard(b)
		assert.Error(t, err, "failed while expecting error from bytesToCard()")
	})
}

func addChestMock(cryptoRepo *MockEncryptionRepository, storageRepo *MockStorageRepostiory, deviceRepo *MockDeviceRepository, lockPassword string, expectedError error) {

	someSalt := []byte{}
	someData := sha256.New().Sum([]byte("some-data"))
	encryptDataMock(cryptoRepo, someSalt, someData, lockPassword, nil)

	deviceRepo.EXPECT().ExtractDeviceName().Return(&models.DeviceInfo{
		Name: "some-device",
	}, nil)

	storageRepo.EXPECT().Insert(mock.Anything, mock.AnythingOfType("*models.Chest"), mock.AnythingOfType("*models.History")).Return(expectedError)
}

func editChestMock(cryptoRepo *MockEncryptionRepository, storageRepo *MockStorageRepostiory, deviceRepo *MockDeviceRepository, expectedChest *models.Chest, lockPassword string, expectedError error) {

	getChestByNameMock(storageRepo, cryptoRepo, expectedChest, lockPassword, nil)
	encryptDataMock(cryptoRepo, expectedChest.Salt, expectedChest.Data, lockPassword, nil)
	deviceRepo.EXPECT().ExtractDeviceName().Return(&models.DeviceInfo{
		Name: "some-device",
	}, nil)
	storageRepo.EXPECT().Update(mock.Anything, mock.AnythingOfType("*models.Chest"), mock.AnythingOfType("*models.History")).Return(expectedError)
}

func handleSyncErrorsMock(repo *MockSyncRepository, err error) {
	repo.EXPECT().IsAuthentificationError(err).Return(false)
	repo.EXPECT().BadUserDataError(err).Return(nil)
	repo.EXPECT().IsConnectionError(err).Return(false)
	repo.EXPECT().IsDataAlreadyExistsError(err).Return(false)
	repo.EXPECT().IsNotFoundError(err).Return(false)
}

func handleStorageErrorsMock(repo *MockStorageRepostiory, err error) {
	repo.EXPECT().IsNotFoundError(err).Return(false)
	repo.EXPECT().IsConfictError(err).Return(false)
}

func encryptDataMock(repo *MockEncryptionRepository, expectedSalt []byte, expectedData []byte, lockPassword string, err error) {
	if len(expectedSalt) == 0 {
		repo.EXPECT().GenerateSalt().Return(expectedSalt, nil)
	}

	someLock := sha256.New().Sum([]byte("some-lock"))
	repo.EXPECT().GenerateLock(expectedSalt, lockPassword).Return(someLock)
	repo.EXPECT().LockData(mock.AnythingOfType("[]uint8"), someLock).Return(expectedData, err)
}

func getChestByNameMock(storageRepo *MockStorageRepostiory, cryptoRepo *MockEncryptionRepository, expectedChest *models.Chest, lockPassword string, err error) {
	storageRepo.EXPECT().SelectChestByName(mock.Anything, mock.AnythingOfType("string")).Return(expectedChest, err)
	if err != nil {
		storageRepo.EXPECT().IsNotFoundError(err).Return(false)
		storageRepo.EXPECT().IsConfictError(err).Return(false)
		return
	}

	someLock := sha256.New().Sum([]byte("some-lock"))
	cryptoRepo.EXPECT().GenerateLock(expectedChest.Salt, lockPassword).Return(someLock)
	cryptoRepo.EXPECT().UnlockData(expectedChest.Data, someLock).Return(expectedChest.Data, nil)
}

func strAsRef(s string) *string {
	return &s
}

func int64AsRef(i int64) *int64 {
	return &i
}
