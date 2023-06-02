package dto

import (
	"time"

	"github.com/google/uuid"
)

// History is a struct that represents the history table in the usecase.
type History struct {
	ID            string    `validate:"required"`
	UserID        uuid.UUID `validate:"required"`
	ChestID       string    `validate:"required"`
	OperationType int32     `validate:"gte=0"`
	OperationTime time.Time `validate:"required"`
	SyncingTime   *time.Time
	DeviceName    string `validate:"required"`
	DeviceIP      string `validate:"required"`
}
