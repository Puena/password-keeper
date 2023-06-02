package usecases

import (
	"context"

	"github.com/Puena/password-keeper/server/internal/dto"
	"github.com/google/uuid"
)

// Sync get user history events from client than extract user history event from storage, compare than and compose output history that contains not sync items.
func (u *keeperUseCases) Sync(ctx context.Context, history []*dto.History, userID uuid.UUID) ([]*dto.History, error) {

	// map dto to model, use map for better search performance.
	inHistory := make(map[string]*dto.History)
	for _, h := range history {
		h := h

		// validate input history data
		err := validation.Struct(h)
		if err != nil {
			return nil, newErrKeeperUseCases("bad history input data", errKeeperUseCasesValidation, err)
		}

		inHistory[h.ChestID] = h
	}

	// get last history event for every chest for this user.
	databaseHistory, err := u.historyRepository.SelectUserChestsLastHistory(ctx, userID)
	if err != nil {
		if u.historyRepository.NotFoundError(err) != nil {
			return nil, newErrKeeperUseCases("history with this userID not found", errKeeperUseCasesNotFound, err)
		}
		return nil, newErrKeeperUseCases("inernal error while selecting history", errKeeperUseCasesInternal, err)
	}

	// check operation time of input history and database history.
	var outHistory []*dto.History
	for _, dh := range databaseHistory {
		if ih, ok := inHistory[dh.ChestID]; ok { // if database history event exists in input history do some comparison to decide which history event are latest.
			if ih.OperationTime.After(dh.OperationTime) { // check if input history operation time after database operation time, than add input history event.
				outHistory = append(outHistory, ih)
			} else if ih.OperationTime.Before(dh.OperationTime) { // check if input history operation time before database operation time, than add database history event.
				outHistory = append(outHistory, composeHistoryDto(dh))
			}
			// if equal do nothing

			// remove handled key from input hisory
			delete(inHistory, dh.ChestID)

		} else { // if database history event not in input history event just add to output result.
			outHistory = append(outHistory, composeHistoryDto(dh))
		}
	}

	// check that we handle all input history event and if not add remaining to output history because they will be new.
	for _, ih := range inHistory {
		ih := ih
		outHistory = append(outHistory, ih)
	}

	return outHistory, nil
}
