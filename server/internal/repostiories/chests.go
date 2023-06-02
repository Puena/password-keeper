package repositories

import (
	"context"
	"errors"

	"github.com/Puena/password-keeper/server/config"
	"github.com/Puena/password-keeper/server/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"
)

type chestsRepository struct {
	pgRepository
}

const chestFieldsForSelect = "id, user_id, salt, name, data, data_type"
const historyFieldsForSelect = "id, user_id, chest_id, operation_type, operation_time, syncing_time, device_name, device_ip"

// scanHistory scan to chest model. Sequence is METTER!!!
func scanChest(row pgx.Row) (*models.Chest, error) {
	chest := &models.Chest{}
	err := row.Scan(
		&chest.ID,
		&chest.UserID,
		&chest.Salt,
		&chest.Name,
		&chest.Data,
		&chest.DataType,
	)
	if err != nil {
		return nil, err
	}
	return chest, nil
}

// scanHistory scan to history model. Sequence is METTER!!!
func scanHistory(row pgx.Row) (*models.History, error) {
	chest := &models.History{}
	err := row.Scan(
		&chest.ID,
		&chest.UserID,
		&chest.ChestID,
		&chest.OperationType,
		&chest.OperationTime,
		&chest.SyncingTime,
		&chest.DeviceName,
		&chest.DeviceIP,
	)
	if err != nil {
		return nil, err
	}
	return chest, nil
}

// NewChestRepository initialize chests repository.
func NewChestRepository(pg pgxInterface, config *config.Config, logger *zap.Logger) *chestsRepository {
	return &chestsRepository{
		pgRepository: newPgRepository(pg, config, logger),
	}
}

// SelectChestByID retrive chest by id, error if not found or database error.
func (r *chestsRepository) SelectChestByID(ctx context.Context, chestID string, userID uuid.UUID) (*models.Chest, *models.History, error) {
	const selectChestQuery = "SELECT " + chestFieldsForSelect + " FROM chests WHERE id = $1 AND user_id = $2"
	const selectHistoryQuery = "SELECT " + historyFieldsForSelect + " FROM history WHERE chest_id = $1 AND user_id = $2"

	row := r.pg.QueryRow(ctx, selectChestQuery, &chestID, &userID)
	chest, err := scanChest(row)
	if err != nil {
		return nil, nil, newErrChestsRepositoryError("failed while scanning chest to model", err)
	}

	row = r.pg.QueryRow(ctx, selectHistoryQuery, &chestID, &userID)
	history, err := scanHistory(row)
	if err != nil {
		return nil, nil, newErrChestsRepositoryError("failed while scanning history to model", err)
	}

	return chest, history, nil
}

// AddChest add chest to the database, then add history information obout this action and return it as history model or error if fail.
func (r *chestsRepository) InsertChest(ctx context.Context, chest *models.Chest, history *models.History) (err error) {

	const insertChestQuery = "INSERT INTO chests " +
		"(id, user_id, salt, name, data, data_type) " +
		"VALUES ($1, $2, $3, $4, $5, $6)"

	tx, txErr := r.pg.Begin(ctx)
	if txErr != nil {
		err = newErrChestsRepositoryError("failed while begining tx", txErr)
		return err
	}
	defer func() {
		rErr := tx.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			err = errors.Join(err, newErrChestsRepositoryError("failed when defer tx while rolling back", rErr))
		}
	}()

	res, exErr := tx.Exec(ctx, insertChestQuery,
		&chest.ID,
		&chest.UserID,
		&chest.Salt,
		&chest.Name,
		&chest.Data,
		&chest.DataType,
	)
	if exErr != nil {
		err = newErrChestsRepositoryError("failed while inserting into chests table", exErr)
		return
	}

	affected := res.RowsAffected()
	r.logger.Info("inserted chest", zap.String("id", chest.ID), zap.Int64("row affected", affected))
	if affected == 0 {
		err = newErrChestsRepositoryError("failed insert operation into chests table, table not affected", ErrChestsRepositoryNotAffected)
		return
	}

	res, exErr = insertHistory(ctx, tx, history)
	if exErr != nil {
		err = newErrChestsRepositoryError("failed while inserting into history table", exErr)
		return
	}

	affected = res.RowsAffected()
	r.logger.Info("inserted history", zap.String("id", history.ID), zap.Int64("row affected", affected))
	if affected == 0 {
		err = newErrChestsRepositoryError("failed insert operation into history table, table not affected value is 0", ErrChestsRepositoryNotAffected)
		return
	}

	txErr = tx.Commit(ctx)
	if txErr != nil {
		err = newErrChestsRepositoryError("failed while commiting", txErr)
		return
	}

	return
}

// UpsertChestData insert chest or update chest data in database, then add history information obout this action and return it as history model or error if fail.
func (r *chestsRepository) UpsertChest(ctx context.Context, chest *models.Chest, history *models.History) (err error) {
	const upsertChestQuery = "INSERT INTO chests AS c " +
		"(id, user_id, salt, name, data, data_type) " +
		"VALUES ($1, $2, $3, $4, $5, $6) " +
		"ON CONFLICT (user_id, id) DO " +
		"UPDATE SET salt = $3, name = $4, data = $5, data_type = $6 WHERE c.user_id = $2 AND c.id = $1"

	tx, txErr := r.pg.Begin(ctx)
	if txErr != nil {
		err = newErrChestsRepositoryError("failed while begining tx", txErr)
		return
	}
	defer func() {
		rErr := tx.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			err = errors.Join(err, newErrChestsRepositoryError("failed when defer tx while rolling back", rErr))
		}
	}()

	res, exErr := tx.Exec(ctx, upsertChestQuery,
		&chest.ID,
		&chest.UserID,
		&chest.Salt,
		&chest.Name,
		&chest.Data,
		&chest.DataType,
	)
	if exErr != nil {
		err = newErrChestsRepositoryError("failed while updating chests table", exErr)
		return
	}

	affected := res.RowsAffected()
	r.logger.Info("update chest", zap.String("id", chest.ID), zap.Int64("row affected", affected))
	if affected == 0 {
		err = newErrChestsRepositoryError("failed updating operation chests table, table not affected", ErrChestsRepositoryNotAffected)
		return
	}

	res, exErr = insertHistory(ctx, tx, history)
	if exErr != nil {
		err = newErrChestsRepositoryError("failed while inserting into history table", exErr)
		return
	}

	affected = res.RowsAffected()
	r.logger.Info("insert update history", zap.String("id", history.ID), zap.Int64("row affected", affected))
	if affected == 0 {
		err = newErrChestsRepositoryError("failed insert operation into history table, table not affected value is 0", ErrChestsRepositoryNotAffected)
		return
	}

	txErr = tx.Commit(ctx)
	if txErr != nil {
		err = newErrChestsRepositoryError("failed while commiting", txErr)
		return
	}

	return
}

// UpdateChestData update chest data in database, then add history information obout this action and return it as history model or error if fail.
func (r *chestsRepository) UpdateChest(ctx context.Context, chest *models.Chest, history *models.History) (err error) {

	const updateChestQuery = "UPDATE chests SET salt = $1, name = $2, data = $3, data_type = $4 WHERE user_id = $5 AND id = $6"

	tx, txErr := r.pg.Begin(ctx)
	if txErr != nil {
		err = newErrChestsRepositoryError("failed while begining tx", txErr)
		return
	}
	defer func() {
		rErr := tx.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			err = errors.Join(err, newErrChestsRepositoryError("failed when defer tx while rolling back", rErr))
		}
	}()

	res, exErr := tx.Exec(ctx, updateChestQuery,
		&chest.Salt,
		&chest.Name,
		&chest.Data,
		&chest.DataType,
		&chest.UserID,
		&chest.ID,
	)
	if exErr != nil {
		err = newErrChestsRepositoryError("failed while updating chests table", exErr)
		return
	}

	affected := res.RowsAffected()
	r.logger.Info("update chest", zap.String("id", chest.ID), zap.Int64("row affected", affected))
	if affected == 0 {
		err = newErrChestsRepositoryError("failed updating operation chests table, table not affected", ErrChestsRepositoryNotAffected)
		return
	}

	res, exErr = insertHistory(ctx, tx, history)
	if exErr != nil {
		err = newErrChestsRepositoryError("failed while inserting into history table", exErr)
		return
	}

	affected = res.RowsAffected()
	r.logger.Info("insert update history", zap.String("id", history.ID), zap.Int64("row affected", affected))
	if affected == 0 {
		err = newErrChestsRepositoryError("failed insert operation into history table, table not affected value is 0", ErrChestsRepositoryNotAffected)
		return
	}

	txErr = tx.Commit(ctx)
	if txErr != nil {
		err = newErrChestsRepositoryError("failed while commiting", txErr)
		return
	}

	return
}

// DeleteChestData delete chest data in database, ignore if not found, then add history information obout this action and return it as history model or error if fail.
func (r *chestsRepository) DeleteChest(ctx context.Context, history *models.History) (err error) {

	const deleteChestQuery = "DELETE FROM chests WHERE id = $1 AND user_id = $2"

	tx, txErr := r.pg.Begin(ctx)
	if txErr != nil {
		err = newErrChestsRepositoryError("failed while begining tx", txErr)
		return
	}
	defer func() {
		rErr := tx.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			err = errors.Join(err, newErrChestsRepositoryError("failed when defer tx while rolling back", rErr))
		}
	}()

	res, exErr := tx.Exec(ctx, deleteChestQuery,
		&history.ChestID,
		&history.UserID,
	)
	if exErr != nil {
		err = newErrChestsRepositoryError("failed while deleting chests table", exErr)
		// ignore not found error, then insert just history, because user can create and delete chest localy then call sync and we have last history - delete event, but dont have chest data remote.
		if r.NotFoundError(err) != nil {
			err = nil
			return
		}
	}

	affected := res.RowsAffected()
	r.logger.Info("delete chest", zap.String("chest id", history.ChestID), zap.Int64("affected", affected))
	if affected == 0 {
		err = newErrChestsRepositoryError("failed deleting operation chests table, table not affected", ErrChestsRepositoryNotAffected)
		return
	}

	res, exErr = insertHistory(ctx, tx, history)
	if exErr != nil {
		err = newErrChestsRepositoryError("failed while inserting into history table", exErr)
		return
	}

	affected = res.RowsAffected()
	r.logger.Info("insert delete history", zap.String("history id", history.ID), zap.Int64("affected", affected))
	if affected == 0 {
		err = newErrChestsRepositoryError("failed insert operation into history table, table not affected value is 0", ErrChestsRepositoryNotAffected)
		return
	}

	txErr = tx.Commit(ctx)
	if txErr != nil {
		err = newErrChestsRepositoryError("failed while commiting", txErr)
		return
	}

	return
}

func insertHistory(ctx context.Context, tx pgx.Tx, history *models.History) (commandTag pgconn.CommandTag, err error) {
	const insertHistoryQuery = "INSERT INTO history " +
		"(id, user_id, chest_id, operation_type, operation_time, syncing_time, device_name, device_ip) " +
		"VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
	return tx.Exec(ctx, insertHistoryQuery,
		&history.ID,
		&history.UserID,
		&history.ChestID,
		&history.OperationType,
		&history.OperationTime,
		&history.SyncingTime,
		&history.DeviceName,
		&history.DeviceIP,
	)
}
