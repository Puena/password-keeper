package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/models"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
)

type storageRepository struct {
	*baseRepository
}

// NewStorageRepository create storage repository that operate chests and history.
func NewStorageRepository(db *sqlx.DB, config *config.Config, logger *zap.Logger) *storageRepository {
	return &storageRepository{
		&baseRepository{
			logger: logger,
			config: config,
			db:     db,
		},
	}
}

// SelectLastHistoryEventForAllChests get only last history event for every chests.
func (r *storageRepository) SelectLastHistoryEventForAllChests(ctx context.Context) (history []*models.History, err error) {
	const selectHistoryQuery = "SELECT h.id, h.user_id, h.chest_id, h.operation_type, h.operation_time, h.syncing_time, h.device_name, h.device_ip " +
		"FROM history h " +
		"INNER JOIN ( " +
		"SELECT chest_id, MAX(operation_time) as max_time " +
		"FROM history " +
		"GROUP BY chest_id) t " +
		"ON h.chest_id = t.chest_id AND h.operation_time = t.max_time"

	history = make([]*models.History, 0)
	err = r.db.SelectContext(ctx, &history, selectHistoryQuery)
	if err != nil {
		err = NewStorageRepositoryError("failed while trying to select history last event for every chest", err)
		return
	}

	return
}

// SelectIdNameTypeChests get id, name, data_type of all chests.
func (r *storageRepository) SelectIdNameTypeChests(ctx context.Context) (chests []*models.Chest, err error) {
	const queryChestSql = "SELECT id, name, data_type FROM chests"

	chests = make([]*models.Chest, 0)
	err = r.db.SelectContext(ctx, &chests, queryChestSql)
	if err != nil {
		err = NewStorageRepositoryError("failed while trying select chest data", err)
		return
	}
	return
}

// SelectChestByName get chest by name.
func (r *storageRepository) SelectChestByName(ctx context.Context, name string) (chest *models.Chest, err error) {
	const queryChestSql = "SELECT id, salt, name, data, data_type FROM chests WHERE name = ?"

	chest = &models.Chest{}
	err = r.db.GetContext(ctx, chest, queryChestSql, &name)
	if err != nil {
		err = NewStorageRepositoryError("failed while trying select chest data", err)
		return
	}
	return
}

// SelectChestAndHistoryByID get chest by id and all it's history sorted by operation time in descending order.
func (r *storageRepository) SelectChestAndHistoryByID(ctx context.Context, chestID string) (chest *models.Chest, history []*models.History, err error) {
	const queryChestSql = "SELECT id, salt, name, data, data_type FROM chests WHERE id=?"
	const queryHistorySql = "SELECT id, chest_id, operation_type, operation_time, syncing_time, device_name, device_ip FROM history WHERE chest_id=? ORDER BY operation_time DESC"

	chest = &models.Chest{}
	err = r.db.GetContext(ctx, chest, queryChestSql, &chestID)
	if err != nil {
		err = NewStorageRepositoryError("failed while query chest by id", err)
		return
	}

	history = make([]*models.History, 0)
	err = r.db.SelectContext(ctx, &history, queryHistorySql, &chestID)
	if err != nil {
		err = NewStorageRepositoryError("failed while query history by id", err)
		return
	}
	return
}

// Insert do insert chest with history event.
func (r *storageRepository) Insert(ctx context.Context, chest *models.Chest, history *models.History) error {
	const chestInsertSql = "INSERT INTO chests (id, user_id, salt, name, data, data_type) VALUES ($1, $2, $3, $4, $5, $6)"
	const historyInsertSql = "INSERT INTO history (id, chest_id, user_id, operation_type, operation_time, syncing_time, device_name, device_ip) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?)"

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return NewStorageRepositoryError("failed while trying to begin trainsation for insert", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, chestInsertSql, &chest.ID, &chest.UserID, &chest.Salt, &chest.Name, &chest.Data, &chest.DataType)
	if err != nil {
		return NewStorageRepositoryError("failed while trying to exec insert chest query", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return NewStorageRepositoryError("failed while trying get affected for insert chest", err)
	}
	r.logger.Info("insert chest", zap.String("chest_id", chest.ID), zap.Int64("affected", affected))

	res, err = tx.ExecContext(ctx, historyInsertSql, &history.ID, &history.ChestID, &history.UserID, &history.OperationType, &history.OperationTime, &history.SyncingTime, &history.DeviceName, &history.DeviceIP)
	if err != nil {
		return NewStorageRepositoryError("failed while trying to exec insert history query", err)
	}
	affected, err = res.RowsAffected()
	if err != nil {
		return NewStorageRepositoryError("failed while trying get affected for insert chest", err)
	}
	r.logger.Info("insert history insert chest", zap.String("chest_id", chest.ID), zap.String("history_id", history.ID), zap.Int64("affected", affected))

	err = tx.Commit()
	if err != nil {
		return NewStorageRepositoryError("failed while trying to do commit for insert", err)
	}
	r.logger.Info("success commit insert chest", zap.String("chest_id", chest.ID), zap.String("history_id", history.ID))

	return nil
}

// Upsert do upsert chest and insert update history event.
func (r *storageRepository) Upsert(ctx context.Context, chest *models.Chest, history *models.History) error {
	const chestInsertSql = "INSERT INTO chests (id, user_id, salt, name, data, data_type) VALUES ($1, $2, $3, $4, $5, $6) " +
		"ON CONFLICT (id) DO UPDATE SET salt=$2, name=$3, data=$4, data_type=$5 WHERE id=$1"
	const historyInsertSql = "INSERT INTO history (id, chest_id, user_id, operation_type, operation_time, syncing_time, device_name, device_ip) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?)"

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return NewStorageRepositoryError("failed while trying to begin trainsation for upsert", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, chestInsertSql, &chest.ID, &chest.UserID, &chest.Salt, &chest.Name, &chest.Data, &chest.DataType)
	if err != nil {
		return NewStorageRepositoryError("failed while trying to exec upsert chest query", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return NewStorageRepositoryError("failed while trying to get affected rows for upsert chest", err)
	}
	r.logger.Info("upsert chest", zap.String("chest_id", chest.ID), zap.Int64("rows", affected))

	res, err = tx.ExecContext(ctx, historyInsertSql, &history.ID, &history.ChestID, &history.UserID, &history.OperationType, &history.OperationTime, &history.SyncingTime, &history.DeviceName, &history.DeviceIP)
	if err != nil {
		return NewStorageRepositoryError("failed while trying to exec insert history query", err)
	}
	affected, err = res.RowsAffected()
	if err != nil {
		return NewStorageRepositoryError("failed while trying to get affected rows for insert history", err)
	}
	r.logger.Info("insert update history event", zap.String("chest_id", chest.ID), zap.String("history_id", history.ID), zap.Int64("rows", affected))

	err = tx.Commit()
	if err != nil {
		return NewStorageRepositoryError("failed while trying to do commit for insert", err)
	}
	r.logger.Info("success commit upsert", zap.String("chest_id", chest.ID), zap.String("history_id", history.ID))

	return nil
}

// Update do update chest and insert update history event.
func (r *storageRepository) Update(ctx context.Context, chest *models.Chest, history *models.History) error {
	const chestInsertSql = "UPDATE chests SET id=$1, salt=$2, name=$3, data=$4, data_type=$5 WHERE id=$1"
	const historyInsertSql = "INSERT INTO history (id, chest_id, user_id, operation_type, operation_time, syncing_time, device_name, device_ip) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?)"

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return NewStorageRepositoryError("failed while trying to begin trainsation for update", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, chestInsertSql, &chest.ID, &chest.Salt, &chest.Name, &chest.Data, &chest.DataType)
	if err != nil {
		return NewStorageRepositoryError("failed while trying to exec update chest query", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return NewStorageRepositoryError("failed while trying to get affected rows for update chest query", err)
	}
	r.logger.Info("update chest", zap.String("chest_id", chest.ID), zap.Int64("affected", affected))

	res, err = tx.ExecContext(ctx, historyInsertSql, &history.ID, &history.ChestID, &history.UserID, &history.OperationType, &history.OperationTime, &history.SyncingTime, &history.DeviceName, &history.DeviceIP)
	if err != nil {
		return NewStorageRepositoryError("failed while trying to exec update history query", err)
	}
	affected, err = res.RowsAffected()
	if err != nil {
		return NewStorageRepositoryError("failed while trying to get affected rows for insert history", err)
	}
	r.logger.Info("insert update history", zap.String("chest_id", chest.ID), zap.String("history_id", history.ID), zap.Int64("affected", affected))

	err = tx.Commit()
	if err != nil {
		return NewStorageRepositoryError("failed while trying to do commit for update", err)
	}
	r.logger.Info("success commit update", zap.String("chest_id", chest.ID), zap.String("history_id", history.ID))

	return nil
}

// Delete do delete chest by id and insert corresponding history event.
func (r *storageRepository) Delete(ctx context.Context, chestID string, history *models.History) error {
	const deleteChestSql = "DELETE FROM chests WHERE id=?"
	const historyInsertSql = "INSERT INTO history (id, chest_id, user_id, operation_type, operation_time, syncing_time, device_name, device_ip) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?)"

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return NewStorageRepositoryError("failed while trying to begin trainsation for delete", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, deleteChestSql, &chestID)
	if err != nil {
		return NewStorageRepositoryError("failed while trying to exec delete chest query", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return NewStorageRepositoryError("failed while trying to get affected rows for delete chest query", err)
	}
	r.logger.Info("delete chest", zap.String("chest_id", chestID), zap.Int64("affected", affected))

	res, err = tx.ExecContext(ctx, historyInsertSql, &history.ID, &history.ChestID, &history.UserID, &history.OperationType, &history.OperationTime, &history.SyncingTime, &history.DeviceName, &history.DeviceIP)
	if err != nil {
		return NewStorageRepositoryError("failed while trying to exec delete history query", err)
	}
	affected, err = res.RowsAffected()
	if err != nil {
		return NewStorageRepositoryError("failed while trying to get affected rows for delete chest query", err)
	}
	r.logger.Info("insert delete history", zap.String("history_id", history.ID), zap.String("chest_id", chestID), zap.Int64("affected", affected))

	err = tx.Commit()
	if err != nil {
		return NewStorageRepositoryError("failed while trying to do commit for delete", err)
	}
	r.logger.Info("commit success", zap.String("chest_id", chestID), zap.String("history_id", history.ID))

	return nil
}

func (r *storageRepository) UpdateHistorySyncData(ctx context.Context, history *models.History) error {
	const historyUpdateSql = "UPDATE history SET syncing_time=?, device_ip=?, user_id=? WHERE id=?"

	res, err := r.db.ExecContext(ctx, historyUpdateSql, &history.SyncingTime, &history.DeviceIP, &history.UserID, &history.ID)
	if err != nil {
		return NewStorageRepositoryError("failed while trying to exec update history query", err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return NewStorageRepositoryError("failed while trying to get rows affected", err)
	}

	r.logger.Info("update history syncing time", zap.String("history_id", history.ID), zap.Int64("rowsAffected", rowsAffected))

	return nil
}

type storageRepostioryError struct {
	*baseRepositoryError
}

// Error inmplements error interface for [storageRepostioryError].
func (re *storageRepostioryError) Error() string {
	return fmt.Sprintf("storage repository error: %s %s", re.message, re.err)
}

// NewStorageRepositoryError create storage repository error.
func NewStorageRepositoryError(message string, err error) *storageRepostioryError {
	return &storageRepostioryError{
		newBaseRepositoryError(message, err),
	}
}

// IsStorageRepositoryError chest if it is storage repository.
func (r *storageRepository) IsStorageRepositoryError(err error) bool {
	var sreerr *storageRepostioryError
	return errors.As(err, &sreerr)
}
