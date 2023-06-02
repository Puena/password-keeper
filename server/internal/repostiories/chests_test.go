package repositories

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Puena/password-keeper/server/config"
	"github.com/Puena/password-keeper/server/internal/models"
	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func chestRows(testChest *models.Chest) *pgxmock.Rows {
	return pgxmock.NewRows([]string{"id", "user_id", "salt", "name", "data", "data_type"}).
		AddRows([]any{testChest.ID, testChest.UserID, testChest.Salt, testChest.Name, testChest.Data, testChest.DataType})
}

func historyRows(testHistory *models.History) *pgxmock.Rows {
	return pgxmock.NewRows([]string{"id", "user_id", "chest_id", "operation_type", "operation_time", "syncing_time", "device_name", "device_ip"}).
		AddRows([]any{testHistory.ID, testHistory.UserID, testHistory.ChestID, testHistory.OperationType, testHistory.OperationTime, testHistory.SyncingTime, testHistory.DeviceName, testHistory.DeviceIP})
}

func Test_chestsRepository_SelectChestByID(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	someChestID := uuid.New().String()
	someUserID := uuid.New()
	someCHest := &models.Chest{
		ID:       someChestID,
		UserID:   someUserID,
		Salt:     sha256.New().Sum([]byte("some salt")),
		Name:     "some chest",
		Data:     sha256.New().Sum([]byte("some data")),
		DataType: 0,
	}
	someHistory := &models.History{
		ID:            someChestID,
		UserID:        someUserID,
		ChestID:       someChestID,
		OperationType: 0,
		OperationTime: time.Now(),
		SyncingTime:   time.Now(),
		DeviceName:    "android",
		DeviceIP:      "10.0.0.1",
	}

	type testArgs struct {
		chestID string
		userID  uuid.UUID
	}

	type testExpected struct {
		chest            *models.Chest
		history          *models.History
		chestScanError   error
		historyScanError error
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
				chestID: someChestID,
				userID:  someUserID,
			},
			expected: testExpected{
				chest:            someCHest,
				history:          someHistory,
				chestScanError:   nil,
				historyScanError: nil,
			},
		},
		{
			name: "chest_scan_error",
			args: testArgs{
				chestID: someChestID,
				userID:  someUserID,
			},
			expected: testExpected{
				chest:            someCHest,
				history:          someHistory,
				chestScanError:   errors.New("some chest scan error"),
				historyScanError: nil,
			},
		},
		{
			name: "history_scan_error",
			args: testArgs{
				chestID: someChestID,
				userID:  someUserID,
			},
			expected: testExpected{
				chest:            someCHest,
				history:          someHistory,
				chestScanError:   nil,
				historyScanError: errors.New("some history scan error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			require.NoError(t, err, "failed while initializing pgxmock")
			repo := NewChestRepository(mock, cfg, lg)

			if tt.expected.chestScanError == nil {
				mock.ExpectQuery("SELECT (.+) FROM chests WHERE id = (.+) AND user_id = (.+)").WithArgs(&tt.args.chestID, &tt.args.userID).WillReturnRows(chestRows(tt.expected.chest))
			} else {
				mock.ExpectQuery("SELECT (.+) FROM chests WHERE id = (.+) AND user_id = (.+)").WithArgs(&tt.args.chestID, &tt.args.userID).WillReturnError(tt.expected.chestScanError)
			}

			if tt.expected.chestScanError == nil && tt.expected.historyScanError == nil {
				mock.ExpectQuery("SELECT (.+) FROM history WHERE chest_id = (.+) AND user_id = (.+)").WithArgs(&tt.args.chestID, &tt.args.userID).WillReturnRows(historyRows(tt.expected.history))
			} else if tt.expected.historyScanError != nil {
				mock.ExpectQuery("SELECT (.+) FROM history WHERE chest_id = (.+) AND user_id = (.+)").WithArgs(&tt.args.chestID, &tt.args.userID).WillReturnError(tt.expected.historyScanError)
			}

			chest, history, err := repo.SelectChestByID(context.Background(), tt.args.chestID, tt.args.userID)
			if tt.expected.chestScanError != nil || tt.expected.historyScanError != nil {
				assert.Error(t, err, "failed while waiting repository error, got nil instead")
				return
			}

			assert.NoError(t, err, "failed when whaiting result, got error instead")
			assert.NotNil(t, chest, "failed while waiting chest, got nil instead")
			assert.NotNil(t, history, "failed while waiting history, got nil instead")
		})
	}
}

func Test_chestRepository_InsertChest(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	someChestID := uuid.New().String()
	someUserID := uuid.New()
	someCHest := &models.Chest{
		ID:       someChestID,
		UserID:   someUserID,
		Salt:     sha256.New().Sum([]byte("some salt")),
		Name:     "some chest",
		Data:     sha256.New().Sum([]byte("some data")),
		DataType: 0,
	}
	someHistory := &models.History{
		ID:            someChestID,
		UserID:        someUserID,
		ChestID:       someChestID,
		OperationType: 0,
		OperationTime: time.Now(),
		SyncingTime:   time.Now(),
		DeviceName:    "android",
		DeviceIP:      "10.0.0.1",
	}

	type testArgs struct {
		chest   *models.Chest
		history *models.History
	}

	type testExpected struct {
		chestInsertError   error
		chestNotAffected   error
		historyInsertError error
		historyNotAffected error
		beginError         error
		commitError        error
		rollbackError      error
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
			expected: testExpected{},
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
				commitError: errors.New("some commit error"),
			},
		},
		{
			name: "rollback_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				commitError:   errors.New("some commit error"),
				rollbackError: errors.New("some rollback error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			require.NoError(t, err, "failed while initializing pgxmock")
			chestRepo := NewChestRepository(mock, cfg, lg)

			defer func() {
				err := chestRepo.InsertChest(context.Background(), tt.args.chest, tt.args.history)
				if tt.expected.beginError != nil ||
					tt.expected.chestInsertError != nil ||
					tt.expected.historyInsertError != nil ||
					tt.expected.commitError != nil ||
					tt.expected.rollbackError != nil ||
					tt.expected.chestNotAffected != nil ||
					tt.expected.historyNotAffected != nil {
					assert.Error(t, err, "failed while waiting repository error, got nil instead")
					return
				}

				assert.NoError(t, err, "failed when whaiting result, got error instead")
			}()

			if tt.expected.beginError != nil {
				return
			}

			defer func() {
				if tt.expected.rollbackError != nil {
					mock.ExpectRollback().WillReturnError(tt.expected.rollbackError)
				} else {
					mock.ExpectRollback()
				}
			}()

			mock.ExpectBegin()

			if tt.expected.chestInsertError != nil {
				mock.ExpectExec("INSERT INTO chests (.+) VALUES (.+)").WithArgs(&tt.args.chest.ID, &tt.args.chest.UserID, &tt.args.chest.Salt, &tt.args.chest.Name, &tt.args.chest.Data, &tt.args.chest.DataType).WillReturnError(tt.expected.chestInsertError)
				return
			} else if tt.expected.chestNotAffected != nil {
				mock.ExpectExec("INSERT INTO chests (.+) VALUES (.+)").WithArgs(&tt.args.chest.ID, &tt.args.chest.UserID, &tt.args.chest.Salt, &tt.args.chest.Name, &tt.args.chest.Data, &tt.args.chest.DataType).WillReturnResult(pgxmock.NewResult("INSERT", 0))
				return
			} else {
				mock.ExpectExec("INSERT INTO chests (.+) VALUES (.+)").WithArgs(&tt.args.chest.ID, &tt.args.chest.UserID, &tt.args.chest.Salt, &tt.args.chest.Name, &tt.args.chest.Data, &tt.args.chest.DataType).WillReturnResult(pgxmock.NewResult("INSERT", 1))
			}

			if tt.expected.historyInsertError != nil {
				mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").WithArgs(&tt.args.history.ID, &tt.args.history.UserID, &tt.args.history.ChestID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).WillReturnError(tt.expected.historyInsertError)
				return
			} else if tt.expected.historyNotAffected != nil {
				mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").WithArgs(&tt.args.history.ID, &tt.args.history.UserID, &tt.args.history.ChestID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).WillReturnResult(pgxmock.NewResult("INSERT", 0))
				return
			} else {
				mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").WithArgs(&tt.args.history.ID, &tt.args.history.UserID, &tt.args.history.ChestID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).WillReturnResult(pgxmock.NewResult("INSERT", 1))
			}

			if tt.expected.commitError != nil {
				mock.ExpectCommit().WillReturnError(tt.expected.commitError)
				return
			} else {
				mock.ExpectCommit()
			}

		})
	}
}

func Test_chestRepository_UpdateChest(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	someChestID := uuid.New().String()
	someUserID := uuid.New()
	someCHest := &models.Chest{
		ID:       someChestID,
		UserID:   someUserID,
		Salt:     sha256.New().Sum([]byte("some salt")),
		Name:     "some chest",
		Data:     sha256.New().Sum([]byte("some data")),
		DataType: 0,
	}
	someHistory := &models.History{
		ID:            someChestID,
		UserID:        someUserID,
		ChestID:       someChestID,
		OperationType: 0,
		OperationTime: time.Now(),
		SyncingTime:   time.Now(),
		DeviceName:    "android",
		DeviceIP:      "10.0.0.1",
	}

	type testArgs struct {
		chest   *models.Chest
		history *models.History
	}

	type testExpected struct {
		chestUpdateError   error
		chestNotAffected   error
		historyInsertError error
		historyNotAffected error
		beginError         error
		commitError        error
		rollbackError      error
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
			expected: testExpected{},
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
			name: "update_chest_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestUpdateError: errors.New("some chest insert error"),
			},
		},
		{
			name: "update_chest_not_affected_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				chestNotAffected: errors.New("some chest not affected error"),
			},
		},
		{
			name: "update_history_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				historyInsertError: errors.New("some history insert error"),
			},
		},
		{
			name: "update_history_not_affected_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
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
				commitError: errors.New("some commit error"),
			},
		},
		{
			name: "rollback_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				commitError:   errors.New("some commit error"),
				rollbackError: errors.New("some rollback error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			require.NoError(t, err, "failed while initializing pgxmock")
			chestRepo := NewChestRepository(mock, cfg, lg)

			defer func() {
				err := chestRepo.UpdateChest(context.Background(), tt.args.chest, tt.args.history)
				if tt.expected.beginError != nil ||
					tt.expected.chestUpdateError != nil ||
					tt.expected.historyInsertError != nil ||
					tt.expected.commitError != nil ||
					tt.expected.rollbackError != nil ||
					tt.expected.chestNotAffected != nil ||
					tt.expected.historyNotAffected != nil {
					assert.Error(t, err, "failed while waiting repository error, got nil instead")
					return
				}

				assert.NoError(t, err, "failed when whaiting result, got error instead")
			}()

			if tt.expected.beginError != nil {
				return
			}

			defer func() {
				if tt.expected.rollbackError != nil {
					mock.ExpectRollback().WillReturnError(tt.expected.rollbackError)
				} else {
					mock.ExpectRollback()
				}
			}()

			mock.ExpectBegin()

			if tt.expected.chestUpdateError != nil {
				mock.ExpectExec("UPDATE chests SET (.+) WHERE user_id = (.+) AND id = (.+)").WithArgs(&tt.args.chest.Salt, &tt.args.chest.Name, &tt.args.chest.Data, &tt.args.chest.DataType, &tt.args.chest.UserID, &tt.args.chest.ID).WillReturnError(tt.expected.chestUpdateError)
				return
			} else if tt.expected.chestNotAffected != nil {
				mock.ExpectExec("UPDATE chests SET (.+) WHERE user_id = (.+) AND id = (.+)").WithArgs(&tt.args.chest.Salt, &tt.args.chest.Name, &tt.args.chest.Data, &tt.args.chest.DataType, &tt.args.chest.UserID, &tt.args.chest.ID).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
				return
			} else {
				mock.ExpectExec("UPDATE chests SET (.+) WHERE user_id = (.+) AND id = (.+)").WithArgs(&tt.args.chest.Salt, &tt.args.chest.Name, &tt.args.chest.Data, &tt.args.chest.DataType, &tt.args.chest.UserID, &tt.args.chest.ID).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
			}

			if tt.expected.historyInsertError != nil {
				mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").WithArgs(&tt.args.history.ID, &tt.args.history.UserID, &tt.args.history.ChestID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).WillReturnError(tt.expected.historyInsertError)
				return
			} else if tt.expected.historyNotAffected != nil {
				mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").WithArgs(&tt.args.history.ID, &tt.args.history.UserID, &tt.args.history.ChestID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).WillReturnResult(pgxmock.NewResult("INSERT", 0))
				return
			} else {
				mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").WithArgs(&tt.args.history.ID, &tt.args.history.UserID, &tt.args.history.ChestID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).WillReturnResult(pgxmock.NewResult("INSERT", 1))
			}

			if tt.expected.commitError != nil {
				mock.ExpectCommit().WillReturnError(tt.expected.commitError)
				return
			} else {
				mock.ExpectCommit()
			}

		})
	}

}

func Test_chestRepository_UpsertChest(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	someChestID := uuid.New().String()
	someUserID := uuid.New()
	someCHest := &models.Chest{
		ID:       someChestID,
		UserID:   someUserID,
		Salt:     sha256.New().Sum([]byte("some salt")),
		Name:     "some chest",
		Data:     sha256.New().Sum([]byte("some data")),
		DataType: 0,
	}
	someHistory := &models.History{
		ID:            someChestID,
		UserID:        someUserID,
		ChestID:       someChestID,
		OperationType: 0,
		OperationTime: time.Now(),
		SyncingTime:   time.Now(),
		DeviceName:    "android",
		DeviceIP:      "10.0.0.1",
	}

	type testArgs struct {
		chest   *models.Chest
		history *models.History
	}

	type testExpected struct {
		chestUpsertError   error
		chestNotAffected   error
		historyInsertError error
		historyNotAffected error
		beginError         error
		commitError        error
		rollbackError      error
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
			expected: testExpected{},
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
				chestUpsertError: errors.New("some chest insert error"),
			},
		},
		{
			name: "inert_chest_not_affected_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
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
				commitError: errors.New("some commit error"),
			},
		},
		{
			name: "rollback_error",
			args: testArgs{
				chest:   someCHest,
				history: someHistory,
			},
			expected: testExpected{
				commitError:   errors.New("some commit error"),
				rollbackError: errors.New("some rollback error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			require.NoError(t, err, "failed while initializing pgxmock")
			chestRepo := NewChestRepository(mock, cfg, lg)

			defer func() {
				err := chestRepo.UpsertChest(context.Background(), tt.args.chest, tt.args.history)
				if tt.expected.beginError != nil ||
					tt.expected.chestUpsertError != nil ||
					tt.expected.historyInsertError != nil ||
					tt.expected.commitError != nil ||
					tt.expected.rollbackError != nil ||
					tt.expected.chestNotAffected != nil ||
					tt.expected.historyNotAffected != nil {
					assert.Error(t, err, "failed while waiting repository error, got nil instead")
					return
				}

				assert.NoError(t, err, "failed when whaiting result, got error instead")
			}()

			if tt.expected.beginError != nil {
				return
			}

			defer func() {
				if tt.expected.rollbackError != nil {
					mock.ExpectRollback().WillReturnError(tt.expected.rollbackError)
				} else {
					mock.ExpectRollback()
				}
			}()

			mock.ExpectBegin()

			if tt.expected.chestUpsertError != nil {
				mock.ExpectExec("INSERT INTO chests AS c (.+) VALUES (.+) ON CONFLICT (.+) DO UPDATE SET (.+) WHERE c.user_id = (.+) AND c.id = (.+)").WithArgs(&tt.args.chest.ID, &tt.args.chest.UserID, &tt.args.chest.Salt, &tt.args.chest.Name, &tt.args.chest.Data, &tt.args.chest.DataType).WillReturnError(tt.expected.chestUpsertError)
				return
			} else if tt.expected.chestNotAffected != nil {
				mock.ExpectExec("INSERT INTO chests AS c (.+) VALUES (.+) ON CONFLICT (.+) DO UPDATE SET (.+) WHERE c.user_id = (.+) AND c.id = (.+)").WithArgs(&tt.args.chest.ID, &tt.args.chest.UserID, &tt.args.chest.Salt, &tt.args.chest.Name, &tt.args.chest.Data, &tt.args.chest.DataType).WillReturnResult(pgxmock.NewResult("INSERT", 0))
				return
			} else {
				mock.ExpectExec("INSERT INTO chests AS c (.+) VALUES (.+) ON CONFLICT (.+) DO UPDATE SET (.+) WHERE c.user_id = (.+) AND c.id = (.+)").WithArgs(&tt.args.chest.ID, &tt.args.chest.UserID, &tt.args.chest.Salt, &tt.args.chest.Name, &tt.args.chest.Data, &tt.args.chest.DataType).WillReturnResult(pgxmock.NewResult("INSERT", 1))
			}

			if tt.expected.historyInsertError != nil {
				mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").WithArgs(&tt.args.history.ID, &tt.args.history.UserID, &tt.args.history.ChestID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).WillReturnError(tt.expected.historyInsertError)
				return
			} else if tt.expected.historyNotAffected != nil {
				mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").WithArgs(&tt.args.history.ID, &tt.args.history.UserID, &tt.args.history.ChestID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).WillReturnResult(pgxmock.NewResult("INSERT", 0))
				return
			} else {
				mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").WithArgs(&tt.args.history.ID, &tt.args.history.UserID, &tt.args.history.ChestID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).WillReturnResult(pgxmock.NewResult("INSERT", 1))
			}

			if tt.expected.commitError != nil {
				mock.ExpectCommit().WillReturnError(tt.expected.commitError)
				return
			} else {
				mock.ExpectCommit()
			}

		})
	}
}

func Test_chestRepository_DeleteChest(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	someChestID := uuid.New().String()
	someUserID := uuid.New()
	someHistory := &models.History{
		ID:            someChestID,
		UserID:        someUserID,
		ChestID:       someChestID,
		OperationType: 0,
		OperationTime: time.Now(),
		SyncingTime:   time.Now(),
		DeviceName:    "android",
		DeviceIP:      "10.0.0.1",
	}

	type testArgs struct {
		history *models.History
	}

	type testExpected struct {
		chestDeleteError   error
		chestNotAffected   error
		historyInsertError error
		historyNotAffected error
		beginError         error
		commitError        error
		rollbackError      error
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
			expected: testExpected{},
		},
		{
			name: "begin_error",
			args: testArgs{
				history: someHistory,
			},
			expected: testExpected{
				beginError: errors.New("some begin error"),
			},
		},
		{
			name: "delete_chest_error",
			args: testArgs{
				history: someHistory,
			},
			expected: testExpected{
				chestDeleteError: errors.New("some chest delete error"),
			},
		},
		{
			name: "delete_chest_not_affected_error",
			args: testArgs{
				history: someHistory,
			},
			expected: testExpected{
				chestNotAffected: errors.New("some chest not affected error"),
			},
		},
		{
			name: "inert_history_error",
			args: testArgs{
				history: someHistory,
			},
			expected: testExpected{
				historyInsertError: errors.New("some history insert error"),
			},
		},
		{
			name: "inert_history_not_affected_error",
			args: testArgs{
				history: someHistory,
			},
			expected: testExpected{
				historyNotAffected: errors.New("some history not affected error"),
			},
		},
		{
			name: "commit_error",
			args: testArgs{
				history: someHistory,
			},
			expected: testExpected{
				commitError: errors.New("some commit error"),
			},
		},
		{
			name: "rollback_error",
			args: testArgs{
				history: someHistory,
			},
			expected: testExpected{
				commitError:   errors.New("some commit error"),
				rollbackError: errors.New("some rollback error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			require.NoError(t, err, "failed while initializing pgxmock")
			chestRepo := NewChestRepository(mock, cfg, lg)

			defer func() {
				err := chestRepo.DeleteChest(context.Background(), tt.args.history)
				if tt.expected.beginError != nil ||
					tt.expected.chestDeleteError != nil ||
					tt.expected.historyInsertError != nil ||
					tt.expected.commitError != nil ||
					tt.expected.rollbackError != nil ||
					tt.expected.chestNotAffected != nil ||
					tt.expected.historyNotAffected != nil {
					assert.Error(t, err, "failed while waiting repository error, got nil instead")
					return
				}

				assert.NoError(t, err, fmt.Sprintf("failed while waiting repository error, got %v instead", err))
			}()

			if tt.expected.beginError != nil {
				return
			}

			defer func() {
				if tt.expected.rollbackError != nil {
					mock.ExpectRollback().WillReturnError(tt.expected.rollbackError)
				} else {
					mock.ExpectRollback()
				}
			}()

			mock.ExpectBegin()

			if tt.expected.chestDeleteError != nil {
				mock.ExpectExec("DELETE FROM chests WHERE id = (.+) AND user_id = (.+)").WithArgs(&tt.args.history.ChestID, &tt.args.history.UserID).WillReturnError(tt.expected.chestDeleteError)
				return
			} else if tt.expected.chestNotAffected != nil {
				mock.ExpectExec("DELETE FROM chests WHERE id = (.+) AND user_id = (.+)").WithArgs(&tt.args.history.ChestID, &tt.args.history.UserID).WillReturnResult(pgxmock.NewResult("DELETE", 0))
				return
			} else {
				mock.ExpectExec("DELETE FROM chests WHERE id = (.+) AND user_id = (.+)").WithArgs(&tt.args.history.ChestID, &tt.args.history.UserID).WillReturnResult(pgxmock.NewResult("DELETE", 1))
			}

			if tt.expected.historyInsertError != nil {
				mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").WithArgs(&tt.args.history.ID, &tt.args.history.UserID, &tt.args.history.ChestID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).WillReturnError(tt.expected.historyInsertError)
				return
			} else if tt.expected.historyNotAffected != nil {
				mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").WithArgs(&tt.args.history.ID, &tt.args.history.UserID, &tt.args.history.ChestID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).WillReturnResult(pgxmock.NewResult("INSERT", 0))
				return
			} else {
				mock.ExpectExec("INSERT INTO history (.+) VALUES (.+)").WithArgs(&tt.args.history.ID, &tt.args.history.UserID, &tt.args.history.ChestID, &tt.args.history.OperationType, &tt.args.history.OperationTime, &tt.args.history.SyncingTime, &tt.args.history.DeviceName, &tt.args.history.DeviceIP).WillReturnResult(pgxmock.NewResult("INSERT", 1))
			}

			if tt.expected.commitError != nil {
				mock.ExpectCommit().WillReturnError(tt.expected.commitError)
				return
			} else {
				mock.ExpectCommit()
			}

		})
	}
}

func Test_chestRepository_Errors(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	t.Run("reposiotory_error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err, "failed while initializing pgxmock")
		chestRepo := NewChestRepository(mock, cfg, lg)

		cErr := newErrChestsRepositoryError("some chest error", errors.New("some error"))
		statusErr := chestRepo.RepositoryError(cErr)
		assert.NotEmpty(t, statusErr.Error(), "failed while waiting repository error, got nil instead")
		assert.Error(t, statusErr, "failed while waiting repository error, got nil instead")

		sErr := errors.New("some error")
		statusErr = chestRepo.RepositoryError(sErr)
		assert.NoError(t, statusErr, "failed while waiting repository error, got %v instead", statusErr)
	})

	t.Run("not_affected_row_error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err, "failed while initializing pgxmock")
		chestRepo := NewChestRepository(mock, cfg, lg)

		cErr := ErrChestsRepositoryNotAffected
		statusErr := chestRepo.NotAffectedError(cErr)
		assert.Error(t, statusErr, "failed while waiting repository error, got nil instead")

		sErr := errors.New("some error")
		statusErr = chestRepo.NotAffectedError(sErr)
		assert.NoError(t, statusErr, "failed while waiting repository error, got %v instead", statusErr)
	})
}
