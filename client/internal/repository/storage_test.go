package repository

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/models"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func strAsRef(s string) *string {
	return &s
}

func int64AsRef(i int64) *int64 {
	return &i
}

func historyToRows(testHistory *models.History) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "user_id", "chest_id", "operation_type", "operation_time", "syncing_time", "device_name", "device_ip"}).
		AddRow(testHistory.ID, testHistory.UserID, testHistory.ChestID, testHistory.OperationType, testHistory.OperationTime, testHistory.SyncingTime, testHistory.DeviceName, testHistory.DeviceIP)
}

func chestToRows(testChest *models.Chest) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "salt", "name", "data", "data_type"}).
		AddRow(testChest.ID, testChest.Salt, testChest.Name, testChest.Data, testChest.DataType)
}

func chestIdNameTypeToRows(testChest *models.Chest) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "name", "data_type"}).
		AddRow(testChest.ID, testChest.Name, testChest.DataType)
}

func TestSelectLastHistoryEventForAllChests(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	someUserID := uuid.New().String()
	history := []*models.History{
		{
			ID:            uuid.New().String(),
			UserID:        &someUserID,
			ChestID:       uuid.New().String(),
			OperationType: 0,
			OperationTime: time.Now().Unix(),
			SyncingTime:   int64AsRef(time.Now().Unix()),
			DeviceName:    "android",
			DeviceIP:      strAsRef("10.0.0.1"),
		},
		{
			ID:            uuid.New().String(),
			UserID:        &someUserID,
			ChestID:       uuid.New().String(),
			OperationType: 1,
			OperationTime: time.Now().Unix(),
			SyncingTime:   int64AsRef(time.Now().Unix()),
			DeviceName:    "android",
			DeviceIP:      strAsRef("10.0.0.1"),
		},
	}

	type testArgs struct {
	}

	type testExpected struct {
		storageError error
		history      []*models.History
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
				history: history,
			},
		},
		{
			name: "internal_error",
			args: testArgs{},
			expected: testExpected{
				history:      history,
				storageError: errors.New("some error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err, "failed while initializing sqlmock")
			defer db.Close()
			dbMock := sqlx.NewDb(db, "sqlmock")

			mock.ExpectQuery("SELECT").WillReturnRows(historyToRows(history[0]), historyToRows(history[1])).WillReturnError(tt.expected.storageError)

			storage := NewStorageRepository(dbMock, cfg, lg)

			defer func() {
				history, err := storage.SelectLastHistoryEventForAllChests(context.Background())
				if tt.expected.storageError != nil {
					require.Error(t, err, "expected error")
					return
				}

				require.NoError(t, err, "failed while selecting last history event for all chests")
				require.NotNil(t, history, "history should not be nil")
				require.IsType(t, []*models.History{}, history, "history should be a slice of *models.History")
			}()

		})
	}
}

func TestSelectIdNameTypeChests(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	someUserID := uuid.New().String()
	chests := []*models.Chest{
		{
			ID:       uuid.NewString(),
			UserID:   strAsRef(someUserID),
			Salt:     sha256.New().Sum([]byte("some salt")),
			Name:     "some name 1",
			Data:     sha256.New().Sum([]byte("some data")),
			DataType: 0,
		},
		{
			ID:       uuid.NewString(),
			UserID:   strAsRef(someUserID),
			Salt:     sha256.New().Sum([]byte("some salt")),
			Name:     "some name 2",
			Data:     sha256.New().Sum([]byte("some data")),
			DataType: 1,
		},
	}

	type testArgs struct {
	}

	type testExpected struct {
		storageError error
		chests       []*models.Chest
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
				chests: chests,
			},
		},
		{
			name: "internal_error",
			args: testArgs{},
			expected: testExpected{
				storageError: errors.New("some error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err, "failed while initializing sqlmock")
			defer db.Close()
			dbMock := sqlx.NewDb(db, "sqlmock")

			var rows []*sqlmock.Rows
			for _, c := range tt.expected.chests {
				rows = append(rows, chestIdNameTypeToRows(c))
			}

			mock.ExpectQuery("SELECT id, name, data_type FROM chests").WillReturnRows(rows...).WillReturnError(tt.expected.storageError)

			storage := NewStorageRepository(dbMock, cfg, lg)

			defer func() {
				chests, err := storage.SelectIdNameTypeChests(context.Background())
				if tt.expected.storageError != nil {
					require.Error(t, err, "expected error")
					return
				}

				require.NoError(t, err, "failed while selecting last history event for all chests")
				require.NotNil(t, chests, "chests should not be nil")
				require.IsType(t, []*models.Chest{}, chests, "chests should be a slice of *models.Chest")
			}()

		})
	}
}

func TestSelectChestByName(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	someUserID := uuid.New().String()
	chests := []*models.Chest{
		{
			ID:       uuid.NewString(),
			UserID:   strAsRef(someUserID),
			Salt:     sha256.New().Sum([]byte("some salt")),
			Name:     "some name 1",
			Data:     sha256.New().Sum([]byte("some data")),
			DataType: 0,
		},
		{
			ID:       uuid.NewString(),
			UserID:   strAsRef(someUserID),
			Salt:     sha256.New().Sum([]byte("some salt")),
			Name:     "some name 2",
			Data:     sha256.New().Sum([]byte("some data")),
			DataType: 1,
		},
	}

	type testArgs struct {
		name string
	}

	type testExpected struct {
		storageError error
		chest        *models.Chest
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
				name: "some name 1",
			},
			expected: testExpected{
				chest: chests[0],
			},
		},
		{
			name: "internal_error",
			args: testArgs{
				name: "some name 2",
			},
			expected: testExpected{
				chest:        chests[1],
				storageError: errors.New("some error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err, "failed while initializing sqlmock")
			defer db.Close()
			dbMock := sqlx.NewDb(db, "sqlmock")

			mock.ExpectQuery("SELECT (.+) FROM chests WHERE name = ?").WithArgs(tt.args.name).WillReturnRows(chestToRows(tt.expected.chest)).WillReturnError(tt.expected.storageError)

			storage := NewStorageRepository(dbMock, cfg, lg)

			defer func() {
				chest, err := storage.SelectChestByName(context.Background(), tt.args.name)
				if tt.expected.storageError != nil {
					require.Error(t, err, "expected error")
					return
				}

				require.NoError(t, err, "failed while selecting last history event for all chests")
				require.NotNil(t, chest, "chests should not be nil")
				require.IsType(t, &models.Chest{}, chest, "chests should be a slice of *models.Chest")
			}()

		})
	}
}

func TestSelectChestAndHistoryByID(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	someUserID := uuid.New().String()

	chests := []*models.Chest{
		{
			ID:       uuid.NewString(),
			UserID:   strAsRef(someUserID),
			Salt:     sha256.New().Sum([]byte("some salt")),
			Name:     "some name 1",
			Data:     sha256.New().Sum([]byte("some data")),
			DataType: 0,
		},
		{
			ID:       uuid.NewString(),
			UserID:   strAsRef(someUserID),
			Salt:     sha256.New().Sum([]byte("some salt")),
			Name:     "some name 2",
			Data:     sha256.New().Sum([]byte("some data")),
			DataType: 1,
		},
	}

	history := []*models.History{
		{
			ID:            uuid.New().String(),
			UserID:        &someUserID,
			ChestID:       chests[0].ID,
			OperationType: 0,
			OperationTime: time.Now().Unix(),
			SyncingTime:   int64AsRef(time.Now().Unix()),
			DeviceName:    "android",
			DeviceIP:      strAsRef("10.0.0.1"),
		},
		{
			ID:            uuid.New().String(),
			UserID:        &someUserID,
			ChestID:       chests[1].ID,
			OperationType: 1,
			OperationTime: time.Now().Unix(),
			SyncingTime:   int64AsRef(time.Now().Unix()),
			DeviceName:    "android",
			DeviceIP:      strAsRef("10.0.0.1"),
		},
	}

	type testArgs struct {
		chestID string
	}

	type testExpected struct {
		chestError   error
		historyError error
		chest        *models.Chest
		history      []*models.History
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
				chestID: chests[0].ID,
			},
			expected: testExpected{
				chest:   chests[0],
				history: history,
			},
		},
		{
			name: "chest_query_error",
			args: testArgs{
				chestID: chests[1].ID,
			},
			expected: testExpected{
				history:    history,
				chest:      chests[1],
				chestError: errors.New("some error"),
			},
		},
		{
			name: "history_query_error",
			args: testArgs{
				chestID: chests[1].ID,
			},
			expected: testExpected{
				history:      history,
				chest:        chests[1],
				historyError: errors.New("some error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err, "failed while initializing sqlmock")
			defer db.Close()
			dbMock := sqlx.NewDb(db, "sqlmock")
			storage := NewStorageRepository(dbMock, cfg, lg)

			defer func() {
				chest, history, err := storage.SelectChestAndHistoryByID(context.Background(), tt.args.chestID)
				if tt.expected.chestError != nil ||
					tt.expected.historyError != nil {
					require.Error(t, err, "expected error")
					return
				}

				require.NoError(t, err, "failed while selecting last history event for all chests")
				require.NotNil(t, chest, "chests should not be nil")
				require.NotNil(t, history, "history should not be nil")
				require.IsType(t, &models.Chest{}, chest, "chests should be *models.Chest")
				require.IsType(t, []*models.History{}, history, "history should be a slice of *models.History")
			}()

			mock.ExpectQuery("SELECT (.+) FROM chests WHERE id=?").WithArgs(tt.args.chestID).WillReturnRows(chestToRows(tt.expected.chest)).WillReturnError(tt.expected.chestError)

			if tt.expected.chestError != nil {
				return
			}

			var historyRows []*sqlmock.Rows
			for _, h := range tt.expected.history {
				historyRows = append(historyRows, historyToRows(h))
			}
			mock.ExpectQuery("SELECT (.+) FROM history WHERE chest_id=?").WithArgs(tt.args.chestID).WillReturnRows(historyRows...).WillReturnError(tt.expected.historyError)

			if tt.expected.historyError != nil {
				return
			}

		})
	}
}

func TestInsert(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	someChestID := uuid.New().String()
	someUserID := uuid.New().String()
	someCHest := &models.Chest{
		ID:       someChestID,
		UserID:   strAsRef(someUserID),
		Salt:     sha256.New().Sum([]byte("some salt")),
		Name:     "some chest",
		Data:     sha256.New().Sum([]byte("some data")),
		DataType: 0,
	}
	someHistory := &models.History{
		ID:            someChestID,
		UserID:        strAsRef(someUserID),
		ChestID:       someChestID,
		OperationType: 0,
		OperationTime: time.Now().Unix(),
		SyncingTime:   int64AsRef(time.Now().Unix()),
		DeviceName:    "android",
		DeviceIP:      strAsRef("10.0.0.1"),
	}

	type testArgs struct {
		chest   *models.Chest
		history *models.History
	}

	type testExpected struct {
		chestResult        driver.Result
		historyResult      driver.Result
		chestInsertError   error
		chestNotAffected   error
		historyInsertError error
		historyNotAffected error
		beginError         error
		commitError        error
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
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:   sqlmock.NewResult(0, 1),
				historyResult: sqlmock.NewResult(0, 1),
			},
		},
		{
			name: "begin_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				beginError: errors.New("some begin error"),
			},
		},
		{
			name: "inert_chest_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:      sqlmock.NewResult(0, 1),
				chestInsertError: errors.New("some chest insert error"),
			},
		},
		{
			name: "inert_chest_not_affected_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:      sqlmock.NewErrorResult(errors.New("some chest not affected error")),
				chestNotAffected: errors.New("some chest not affected error"),
			},
		},
		{
			name: "inert_history_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:        sqlmock.NewResult(0, 1),
				historyResult:      sqlmock.NewResult(0, 1),
				historyInsertError: errors.New("some history insert error"),
			},
		},
		{
			name: "inert_history_not_affected_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:        sqlmock.NewResult(0, 1),
				historyResult:      sqlmock.NewErrorResult(errors.New("some history not affected error")),
				historyNotAffected: errors.New("some history not affected error"),
			},
		},
		{
			name: "commit_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:   sqlmock.NewResult(0, 1),
				historyResult: sqlmock.NewResult(0, 1),
				commitError:   errors.New("some commit error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err, "failed while initializing sqlmock")
			defer db.Close()
			dbMock := sqlx.NewDb(db, "sqlmock")
			storage := NewStorageRepository(dbMock, cfg, lg)

			defer func() {
				err := storage.Insert(context.Background(), tt.args.chest, tt.args.history)
				if tt.expected.beginError != nil ||
					tt.expected.chestInsertError != nil ||
					tt.expected.historyInsertError != nil ||
					tt.expected.commitError != nil ||
					tt.expected.chestNotAffected != nil ||
					tt.expected.historyNotAffected != nil {
					assert.Error(t, err, "failed while waiting repository error, got nil instead")
					return
				}

				assert.NoError(t, err, "failed when whaiting result, got error instead")
			}()

			mock.ExpectBegin().WillReturnError(tt.expected.beginError)
			if tt.expected.beginError != nil {
				return
			}
			defer func() {
				mock.ExpectRollback()
			}()

			mock.ExpectExec("INSERT INTO chests (.+) VALUES (.+)").
				WithArgs(&tt.args.chest.ID, &tt.args.chest.UserID, &tt.args.chest.Salt, &tt.args.chest.Name, &tt.args.chest.Data, &tt.args.chest.DataType).
				WillReturnResult(tt.expected.chestResult).
				WillReturnError(tt.expected.chestInsertError)
			if tt.expected.chestInsertError != nil || tt.expected.chestNotAffected != nil {
				return
			}

			mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").
				WithArgs(&tt.args.history.ID, &tt.args.history.ChestID, &tt.args.history.UserID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).
				WillReturnResult(tt.expected.historyResult).
				WillReturnError(tt.expected.historyInsertError)
			if tt.expected.historyInsertError != nil || tt.expected.historyNotAffected != nil {
				return
			}

			mock.ExpectCommit().WillReturnError(tt.expected.commitError)

		})
	}
}

func TestUpsert(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	someChestID := uuid.New().String()
	someUserID := uuid.New().String()
	someCHest := &models.Chest{
		ID:       someChestID,
		UserID:   strAsRef(someUserID),
		Salt:     sha256.New().Sum([]byte("some salt")),
		Name:     "some chest",
		Data:     sha256.New().Sum([]byte("some data")),
		DataType: 0,
	}
	someHistory := &models.History{
		ID:            someChestID,
		UserID:        strAsRef(someUserID),
		ChestID:       someChestID,
		OperationType: 0,
		OperationTime: time.Now().Unix(),
		SyncingTime:   int64AsRef(time.Now().Unix()),
		DeviceName:    "android",
		DeviceIP:      strAsRef("10.0.0.1"),
	}

	type testArgs struct {
		chest   *models.Chest
		history *models.History
	}

	type testExpected struct {
		chestResult        driver.Result
		historyResult      driver.Result
		chestInsertError   error
		chestNotAffected   error
		historyInsertError error
		historyNotAffected error
		beginError         error
		commitError        error
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
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:   sqlmock.NewResult(0, 1),
				historyResult: sqlmock.NewResult(0, 1),
			},
		},
		{
			name: "begin_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				beginError: errors.New("some begin error"),
			},
		},
		{
			name: "inert_chest_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:      sqlmock.NewResult(0, 1),
				chestInsertError: errors.New("some chest insert error"),
			},
		},
		{
			name: "inert_chest_not_affected_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:      sqlmock.NewErrorResult(errors.New("some chest not affected error")),
				chestNotAffected: errors.New("some chest not affected error"),
			},
		},
		{
			name: "inert_history_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:        sqlmock.NewResult(0, 1),
				historyResult:      sqlmock.NewResult(0, 1),
				historyInsertError: errors.New("some history insert error"),
			},
		},
		{
			name: "inert_history_not_affected_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:        sqlmock.NewResult(0, 1),
				historyResult:      sqlmock.NewErrorResult(errors.New("some history not affected error")),
				historyNotAffected: errors.New("some history not affected error"),
			},
		},
		{
			name: "commit_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:   sqlmock.NewResult(0, 1),
				historyResult: sqlmock.NewResult(0, 1),
				commitError:   errors.New("some commit error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err, "failed while initializing sqlmock")
			defer db.Close()
			dbMock := sqlx.NewDb(db, "sqlmock")
			storage := NewStorageRepository(dbMock, cfg, lg)

			defer func() {
				err := storage.Upsert(context.Background(), tt.args.chest, tt.args.history)
				if tt.expected.beginError != nil ||
					tt.expected.chestInsertError != nil ||
					tt.expected.historyInsertError != nil ||
					tt.expected.commitError != nil ||
					tt.expected.chestNotAffected != nil ||
					tt.expected.historyNotAffected != nil {
					assert.Error(t, err, "failed while waiting repository error, got nil instead")
					return
				}

				assert.NoError(t, err, "failed when whaiting result, got error instead")
			}()

			mock.ExpectBegin().WillReturnError(tt.expected.beginError)
			if tt.expected.beginError != nil {
				return
			}
			defer func() {
				mock.ExpectRollback()
			}()

			mock.ExpectExec("INSERT INTO chests (.+) VALUES (.+) ON CONFLICT (.+) DO UPDATE SET (.+)").
				WithArgs(&tt.args.chest.ID, &tt.args.chest.UserID, &tt.args.chest.Salt, &tt.args.chest.Name, &tt.args.chest.Data, &tt.args.chest.DataType).
				WillReturnResult(tt.expected.chestResult).
				WillReturnError(tt.expected.chestInsertError)
			if tt.expected.chestInsertError != nil || tt.expected.chestNotAffected != nil {
				return
			}

			mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").
				WithArgs(&tt.args.history.ID, &tt.args.history.ChestID, &tt.args.history.UserID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).
				WillReturnResult(tt.expected.historyResult).
				WillReturnError(tt.expected.historyInsertError)
			if tt.expected.historyInsertError != nil || tt.expected.historyNotAffected != nil {
				return
			}

			mock.ExpectCommit().WillReturnError(tt.expected.commitError)

		})
	}
}

func TestUpdate(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	someChestID := uuid.New().String()
	someUserID := uuid.New().String()
	someCHest := &models.Chest{
		ID:       someChestID,
		UserID:   strAsRef(someUserID),
		Salt:     sha256.New().Sum([]byte("some salt")),
		Name:     "some chest",
		Data:     sha256.New().Sum([]byte("some data")),
		DataType: 0,
	}
	someHistory := &models.History{
		ID:            someChestID,
		UserID:        strAsRef(someUserID),
		ChestID:       someChestID,
		OperationType: 0,
		OperationTime: time.Now().Unix(),
		SyncingTime:   int64AsRef(time.Now().Unix()),
		DeviceName:    "android",
		DeviceIP:      strAsRef("10.0.0.1"),
	}

	type testArgs struct {
		chest   *models.Chest
		history *models.History
	}

	type testExpected struct {
		chestResult        driver.Result
		historyResult      driver.Result
		chestInsertError   error
		chestNotAffected   error
		historyInsertError error
		historyNotAffected error
		beginError         error
		commitError        error
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
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:   sqlmock.NewResult(0, 1),
				historyResult: sqlmock.NewResult(0, 1),
			},
		},
		{
			name: "begin_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				beginError: errors.New("some begin error"),
			},
		},
		{
			name: "inert_chest_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:      sqlmock.NewResult(0, 1),
				chestInsertError: errors.New("some chest insert error"),
			},
		},
		{
			name: "inert_chest_not_affected_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:      sqlmock.NewErrorResult(errors.New("some chest not affected error")),
				chestNotAffected: errors.New("some chest not affected error"),
			},
		},
		{
			name: "inert_history_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:        sqlmock.NewResult(0, 1),
				historyResult:      sqlmock.NewResult(0, 1),
				historyInsertError: errors.New("some history insert error"),
			},
		},
		{
			name: "inert_history_not_affected_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:        sqlmock.NewResult(0, 1),
				historyResult:      sqlmock.NewErrorResult(errors.New("some history not affected error")),
				historyNotAffected: errors.New("some history not affected error"),
			},
		},
		{
			name: "commit_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:   sqlmock.NewResult(0, 1),
				historyResult: sqlmock.NewResult(0, 1),
				commitError:   errors.New("some commit error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err, "failed while initializing sqlmock")
			defer db.Close()
			dbMock := sqlx.NewDb(db, "sqlmock")
			storage := NewStorageRepository(dbMock, cfg, lg)

			defer func() {
				err := storage.Update(context.Background(), tt.args.chest, tt.args.history)
				if tt.expected.beginError != nil ||
					tt.expected.chestInsertError != nil ||
					tt.expected.historyInsertError != nil ||
					tt.expected.commitError != nil ||
					tt.expected.chestNotAffected != nil ||
					tt.expected.historyNotAffected != nil {
					assert.Error(t, err, "failed while waiting repository error, got nil instead")
					return
				}

				assert.NoError(t, err, "failed when whaiting result, got error instead")
			}()

			mock.ExpectBegin().WillReturnError(tt.expected.beginError)
			if tt.expected.beginError != nil {
				return
			}
			defer func() {
				mock.ExpectRollback()
			}()

			mock.ExpectExec("UPDATE chests SET (.+) WHERE id=(.+)").
				WithArgs(&tt.args.chest.ID, &tt.args.chest.Salt, &tt.args.chest.Name, &tt.args.chest.Data, &tt.args.chest.DataType).
				WillReturnResult(tt.expected.chestResult).
				WillReturnError(tt.expected.chestInsertError)
			if tt.expected.chestInsertError != nil || tt.expected.chestNotAffected != nil {
				return
			}

			mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").
				WithArgs(&tt.args.history.ID, &tt.args.history.ChestID, &tt.args.history.UserID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).
				WillReturnResult(tt.expected.historyResult).
				WillReturnError(tt.expected.historyInsertError)
			if tt.expected.historyInsertError != nil || tt.expected.historyNotAffected != nil {
				return
			}

			mock.ExpectCommit().WillReturnError(tt.expected.commitError)

		})
	}
}

func TestDelete(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	someChestID := uuid.New().String()
	someUserID := uuid.New().String()
	someCHest := &models.Chest{
		ID:       someChestID,
		UserID:   strAsRef(someUserID),
		Salt:     sha256.New().Sum([]byte("some salt")),
		Name:     "some chest",
		Data:     sha256.New().Sum([]byte("some data")),
		DataType: 0,
	}
	someHistory := &models.History{
		ID:            someChestID,
		UserID:        strAsRef(someUserID),
		ChestID:       someChestID,
		OperationType: 0,
		OperationTime: time.Now().Unix(),
		SyncingTime:   int64AsRef(time.Now().Unix()),
		DeviceName:    "android",
		DeviceIP:      strAsRef("10.0.0.1"),
	}

	type testArgs struct {
		chestID string
		history *models.History
	}

	type testExpected struct {
		chestResult        driver.Result
		historyResult      driver.Result
		chestInsertError   error
		chestNotAffected   error
		historyInsertError error
		historyNotAffected error
		beginError         error
		commitError        error
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
				chestID: someCHest.ID,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:   sqlmock.NewResult(0, 1),
				historyResult: sqlmock.NewResult(0, 1),
			},
		},
		{
			name: "begin_error",
			args: testArgs{
				chestID: someCHest.ID,
				history: someHistory,
			},
			expected: testExpected{
				beginError: errors.New("some begin error"),
			},
		},
		{
			name: "inert_chest_error",
			args: testArgs{
				chestID: someCHest.ID,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:      sqlmock.NewResult(0, 1),
				chestInsertError: errors.New("some chest insert error"),
			},
		},
		{
			name: "inert_chest_not_affected_error",
			args: testArgs{
				chestID: someCHest.ID,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:      sqlmock.NewErrorResult(errors.New("some chest not affected error")),
				chestNotAffected: errors.New("some chest not affected error"),
			},
		},
		{
			name: "inert_history_error",
			args: testArgs{
				chestID: someCHest.ID,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:        sqlmock.NewResult(0, 1),
				historyResult:      sqlmock.NewResult(0, 1),
				historyInsertError: errors.New("some history insert error"),
			},
		},
		{
			name: "inert_history_not_affected_error",
			args: testArgs{
				chestID: someCHest.ID,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:        sqlmock.NewResult(0, 1),
				historyResult:      sqlmock.NewErrorResult(errors.New("some history not affected error")),
				historyNotAffected: errors.New("some history not affected error"),
			},
		},
		{
			name: "commit_error",
			args: testArgs{
				chestID: someCHest.ID,
				history: someHistory,
			},
			expected: testExpected{
				chestResult:   sqlmock.NewResult(0, 1),
				historyResult: sqlmock.NewResult(0, 1),
				commitError:   errors.New("some commit error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err, "failed while initializing sqlmock")
			defer db.Close()
			dbMock := sqlx.NewDb(db, "sqlmock")
			storage := NewStorageRepository(dbMock, cfg, lg)

			defer func() {
				err := storage.Delete(context.Background(), tt.args.chestID, tt.args.history)
				if tt.expected.beginError != nil ||
					tt.expected.chestInsertError != nil ||
					tt.expected.historyInsertError != nil ||
					tt.expected.commitError != nil ||
					tt.expected.chestNotAffected != nil ||
					tt.expected.historyNotAffected != nil {
					assert.Error(t, err, "failed while waiting repository error, got nil instead")
					return
				}

				assert.NoError(t, err, "failed when whaiting result, got error instead")
			}()

			mock.ExpectBegin().WillReturnError(tt.expected.beginError)
			if tt.expected.beginError != nil {
				return
			}
			defer func() {
				mock.ExpectRollback()
			}()

			mock.ExpectExec("DELETE FROM chests WHERE id=(.+)").
				WithArgs(&tt.args.chestID).
				WillReturnResult(tt.expected.chestResult).
				WillReturnError(tt.expected.chestInsertError)
			if tt.expected.chestInsertError != nil || tt.expected.chestNotAffected != nil {
				return
			}

			mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").
				WithArgs(&tt.args.history.ID, &tt.args.history.ChestID, &tt.args.history.UserID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).
				WillReturnResult(tt.expected.historyResult).
				WillReturnError(tt.expected.historyInsertError)
			if tt.expected.historyInsertError != nil || tt.expected.historyNotAffected != nil {
				return
			}

			mock.ExpectCommit().WillReturnError(tt.expected.commitError)

		})
	}
}

func TestUpdateHistorySyncData(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing logger")

	someHistory := &models.History{
		ID:            uuid.NewString(),
		UserID:        strAsRef(uuid.NewString()),
		ChestID:       uuid.NewString(),
		OperationType: 0,
		OperationTime: time.Now().Unix(),
		SyncingTime:   int64AsRef(time.Now().Unix()),
		DeviceName:    "android",
		DeviceIP:      strAsRef("10.0.0.1"),
	}

	type testArgs struct {
		history *models.History
	}

	type testExpected struct {
		result        driver.Result
		updateError   error
		affectedError error
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
				history: someHistory,
			},
			expected: testExpected{
				result: sqlmock.NewResult(0, 1),
			},
		},
		{
			name: "update_error",
			args: testArgs{
				history: someHistory,
			},
			expected: testExpected{
				result:      sqlmock.NewResult(0, 1),
				updateError: errors.New("some update error"),
			},
		},
		{
			name: "affected_error",
			args: testArgs{
				history: someHistory,
			},
			expected: testExpected{
				result:        sqlmock.NewErrorResult(errors.New("some affected error")),
				affectedError: errors.New("some affected error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err, "failed while initializing sqlmock")
			defer db.Close()
			dbMock := sqlx.NewDb(db, "sqlmock")
			storage := NewStorageRepository(dbMock, cfg, lg)

			defer func() {
				err := storage.UpdateHistorySyncData(context.Background(), tt.args.history)
				if tt.expected.updateError != nil ||
					tt.expected.affectedError != nil {
					assert.Error(t, err, "failed while waiting repository error, got nil instead")
					return
				}

				assert.NoError(t, err, "failed when whaiting result, got error instead")
			}()

			mock.ExpectExec("UPDATE history SET (.+) WHERE id=(.+)").
				WithArgs(&tt.args.history.SyncingTime, &tt.args.history.DeviceIP, &tt.args.history.UserID, &tt.args.history.ID).
				WillReturnResult(tt.expected.result).
				WillReturnError(tt.expected.updateError)
		})
	}
}

func TestStorageRepositoryErrors(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while initializing config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing logger")

	db, _, err := sqlmock.New()
	require.NoError(t, err, "failed while initializing sqlmock")
	defer db.Close()
	dbMock := sqlx.NewDb(db, "sqlmock")
	storage := NewStorageRepository(dbMock, cfg, lg)

	t.Run("is storage repository error", func(t *testing.T) {
		srErr := NewStorageRepositoryError("some error", errors.New("some error"))
		assert.True(t, storage.IsStorageRepositoryError(srErr), "failed while checking storage repository error")
		assert.False(t, storage.IsStorageRepositoryError(errors.New("some error")), "failed while checking storage repository error")
		assert.NotEmpty(t, srErr.Error(), "failed while checking storage repository error")
	})
}
