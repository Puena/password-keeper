package repositories

import (
	"context"

	"github.com/Puena/password-keeper/server/config"
	"github.com/Puena/password-keeper/server/internal/models"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// historyRepository represent history repository.
type historyRepository struct {
	pgRepository
}

// NewHistoryRepository initialize history repository.
func NewHistoryRepository(pg pgxInterface, config *config.Config, logger *zap.Logger) *historyRepository {
	return &historyRepository{
		pgRepository{
			repository: newRepository(config, logger),
			pg:         pg,
		},
	}
}

// SelectHistoryByChestID select last history event for specific chest.
func (r *historyRepository) SelectUserChestsLastHistory(ctx context.Context, userID uuid.UUID) ([]*models.History, error) {

	const selectHistoryQuery = "SELECT h.id, h.user_id, h.chest_id, h.operation_type, h.operation_time, h.syncing_time, h.device_name, h.device_ip " +
		"FROM history h " +
		"INNER JOIN ( " +
		"SELECT chest_id, MAX(operation_time) as max_time " +
		"FROM history " +
		"WHERE user_id = $1 " +
		"GROUP BY chest_id) t " +
		"ON h.chest_id = t.chest_id AND h.operation_time = t.max_time " +
		"WHERE h.user_id = $1"
	rows, err := r.pg.Query(ctx, selectHistoryQuery, &userID)
	if err != nil {
		return nil, newErrHistoryRepository("failed while trying select last user history for every chest", err)
	}
	defer rows.Close()

	var result []*models.History
	for rows.Next() {
		history := &models.History{}
		err := rows.Scan(
			&history.ID,
			&history.UserID,
			&history.ChestID,
			&history.OperationType,
			&history.OperationTime,
			&history.SyncingTime,
			&history.DeviceName,
			&history.DeviceIP,
		)
		if err != nil {
			return nil, newErrHistoryRepository("failed while scanning row", err)
		}

		result = append(result, history)
	}

	err = rows.Err()
	if err != nil {
		return nil, newErrChestsRepositoryError("failed while iterating trough rows", err)
	}

	return result, nil
}
