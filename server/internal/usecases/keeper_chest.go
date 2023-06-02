package usecases

import (
	"context"
	"time"

	"github.com/Puena/password-keeper/server/internal/dto"
	"github.com/Puena/password-keeper/server/internal/models"
	"github.com/google/uuid"
)

// composeChestDto convert chest model to chest dto.
func composeChestDto(model *models.Chest) *dto.Chest {
	return &dto.Chest{
		ID:       model.ID,
		Salt:     model.Salt,
		Name:     model.Name,
		Data:     model.Data,
		DataType: model.DataType,
	}
}

// composeHistoryDto convert history model to history dto.
func composeHistoryDto(model *models.History) *dto.History {
	return &dto.History{
		ID:            model.ID,
		UserID:        model.UserID,
		ChestID:       model.ChestID,
		OperationType: model.OperationType,
		OperationTime: model.OperationTime,
		SyncingTime:   &model.SyncingTime,
		DeviceName:    model.DeviceName,
		DeviceIP:      model.DeviceIP,
	}
}

// composeHistorModel conver history dto to history model.
func composeHistorModel(dto *dto.History) *models.History {
	history := &models.History{
		ID:            dto.ID,
		UserID:        dto.UserID,
		ChestID:       dto.ChestID,
		OperationType: dto.OperationType,
		OperationTime: dto.OperationTime,
		DeviceName:    dto.DeviceName,
		DeviceIP:      dto.DeviceIP,
	}
	if dto.SyncingTime != nil {
		history.SyncingTime = *dto.SyncingTime
	} else {
		history.SyncingTime = time.Now().UTC()
	}
	return history
}

// composeChestModel conver chest dto to chest model.
func composeChestModel(dto *dto.Chest, userID uuid.UUID) *models.Chest {
	return &models.Chest{
		ID:       dto.ID,
		UserID:   userID,
		Salt:     dto.Salt,
		Name:     dto.Name,
		Data:     dto.Data,
		DataType: dto.DataType,
	}
}

// GetChestByID retrive chest data from database.
func (u *keeperUseCases) GetChestByID(ctx context.Context, chestID string, userID uuid.UUID) (*dto.Chest, *dto.History, error) {

	chest, history, err := u.chestsRepository.SelectChestByID(ctx, chestID, userID)
	if err != nil {
		if u.chestsRepository.NotFoundError(err) != nil {
			return nil, nil, newErrKeeperUseCases("chest with this id not found", errKeeperUseCasesNotFound, err)
		}
		return nil, nil, newErrKeeperUseCases("inernal error while selecting chest by id", errKeeperUseCasesInternal, err)
	}

	return composeChestDto(chest), composeHistoryDto(history), nil
}

// AddChest add chest and add corresponding evene to history. Then return this history event.
func (u *keeperUseCases) AddChest(ctx context.Context, chest *dto.Chest, history *dto.History) (*dto.History, error) {

	// validate input chest data
	err := validation.Struct(chest)
	if err != nil {
		return nil, newErrKeeperUseCases("bad chest data", errKeeperUseCasesValidation, err)
	}

	// validate input history data
	err = validation.Struct(history)
	if err != nil {
		return nil, newErrKeeperUseCases("bad history data", errKeeperUseCasesValidation, err)
	}

	// mapping to models
	historyModel := composeHistorModel(history)
	chestModel := composeChestModel(chest, history.UserID)

	// repository call
	err = u.chestsRepository.UpsertChest(ctx, chestModel, historyModel)
	if err != nil {
		if u.chestsRepository.ConflictError(err) != nil {
			return nil, newErrKeeperUseCases("this chest data already exists", errKeeperUseCasesConflict, err)
		}
		return nil, newErrKeeperUseCases("inernal error while inserting chest", errKeeperUseCasesInternal, err)
	}

	// if not error return history model
	return composeHistoryDto(historyModel), nil
}

// UpsertChest update chest data and add coresponding event to history. Then return this history event.
func (u *keeperUseCases) UpsertChest(ctx context.Context, chest *dto.Chest, history *dto.History) (*dto.History, error) {
	// validate input chest data
	err := validation.Struct(chest)
	if err != nil {
		return nil, newErrKeeperUseCases("bad chest data", errKeeperUseCasesValidation, err)
	}

	// validate input history data
	err = validation.Struct(history)
	if err != nil {
		return nil, newErrKeeperUseCases("bad history data", errKeeperUseCasesValidation, err)
	}

	// mapping to models
	historyModel := composeHistorModel(history)
	chestModel := composeChestModel(chest, history.UserID)

	// repository call
	err = u.chestsRepository.UpsertChest(ctx, chestModel, historyModel)
	if err != nil {
		return nil, newErrKeeperUseCases("inernal error while upserting chest", errKeeperUseCasesInternal, err)
	}

	// if not error return history model
	return composeHistoryDto(historyModel), nil
}

// DeleteChest delete chest and add coresponding event to history. Then return this history event.
func (u *keeperUseCases) DeleteChest(ctx context.Context, history *dto.History) (*dto.History, error) {
	// validate input history data
	err := validation.Struct(history)
	if err != nil {
		return nil, newErrKeeperUseCases("bad history data", errKeeperUseCasesValidation, err)
	}

	// mapping to models
	historyModel := composeHistorModel(history)

	// repository call
	err = u.chestsRepository.DeleteChest(ctx, historyModel)
	if err != nil { // can not be not found
		return nil, newErrKeeperUseCases("internal error while deleting chest", errKeeperUseCasesInternal, err)
	}

	// if not error return history model
	return composeHistoryDto(historyModel), nil
}
