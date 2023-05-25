package repositories

import (
	"context"
	"errors"
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

func Test_historyRepository_SelectUSerChestsLastHistory(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	someUserID := uuid.New()
	history := []*models.History{
		{
			ID:            uuid.New().String(),
			UserID:        someUserID,
			ChestID:       uuid.New().String(),
			OperationType: 0,
			OperationTime: time.Now(),
			SyncingTime:   time.Now(),
			DeviceName:    "android",
			DeviceIP:      "10.0.0.1",
		},
		{
			ID:            uuid.New().String(),
			UserID:        someUserID,
			ChestID:       uuid.New().String(),
			OperationType: 0,
			OperationTime: time.Now(),
			SyncingTime:   time.Now(),
			DeviceName:    "android",
			DeviceIP:      "10.0.0.1",
		},
	}

	type testArgs struct {
		userID uuid.UUID
	}

	type testExpected struct {
		historyRepositoryError error
		historyScanError       error
		historyRowsError       error
		history                []*models.History
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
				userID: someUserID,
			},
			expected: testExpected{
				history: history,
			},
		},
		{
			name: "query_error",
			args: testArgs{
				userID: someUserID,
			},
			expected: testExpected{
				history:                history,
				historyRepositoryError: errors.New("some error"),
			},
		},
		{
			name: "rows_error",
			args: testArgs{
				userID: someUserID,
			},
			expected: testExpected{
				history:          history,
				historyRowsError: errors.New("some error"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			require.NoError(t, err, "failed while initializing pgxmock")
			historyRepo := NewHistoryRepository(mock, cfg, lg)

			defer func() {
				history, err := historyRepo.SelectUserChestsLastHistory(context.Background(), tt.args.userID)
				if tt.expected.historyRepositoryError != nil ||
					tt.expected.historyScanError != nil ||
					tt.expected.historyRowsError != nil {
					assert.Error(t, err, "failed while waiting repository error, got nil instead")
					return
				}

				assert.NoError(t, err, "failed when whaiting result, got error instead")
				assert.NotNil(t, history, "failed while waiting history, got nil instead")
			}()

			if tt.expected.historyRepositoryError != nil {
				mock.ExpectQuery("SELECT (.+) FROM history").WithArgs(&tt.args.userID).WillReturnError(tt.expected.historyRepositoryError)
				return
			}

			if tt.expected.historyRowsError != nil {
				hRows := []*pgxmock.Rows{
					historyRows(tt.expected.history[0]).RowError(0, tt.expected.historyRowsError),
					historyRows(tt.expected.history[0]),
				}
				mock.ExpectQuery("SELECT (.+) FROM history").WithArgs(&tt.args.userID).WillReturnRows(hRows...)
				return
			}

			hRows := []*pgxmock.Rows{
				historyRows(tt.expected.history[0]),
				historyRows(tt.expected.history[0]),
			}
			mock.ExpectQuery("SELECT (.+) FROM history").WithArgs(&tt.args.userID).WillReturnRows(hRows...)
		})
	}
}

func Test_historyRepository_Errors(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	t.Run("reposiotory_error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err, "failed while initializing pgxmock")
		historyRepo := NewHistoryRepository(mock, cfg, lg)

		cErr := newErrHistoryRepository("some chest error", errors.New("some error"))
		statusErr := historyRepo.RepositoryError(cErr)
		assert.Error(t, statusErr, "failed while waiting repository error, got nil instead")
		assert.NotEmpty(t, statusErr.Error(), "failed while waiting repository error, got nil instead")

		sErr := errors.New("some error")
		statusErr = historyRepo.RepositoryError(sErr)
		assert.NoError(t, statusErr, "failed while waiting repository error, got %v instead", statusErr)
	})
}
