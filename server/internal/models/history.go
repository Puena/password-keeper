package models

import (
	"time"

	"github.com/google/uuid"
)

type History struct {
	ID            string
	UserID        uuid.UUID
	ChestID       string
	OperationType int32
	OperationTime time.Time
	SyncingTime   time.Time
	DeviceName    string
	DeviceIP      string
}
