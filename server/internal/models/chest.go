package models

import "github.com/google/uuid"

// Chest represents data from chests table.
type Chest struct {
	ID       string
	UserID   uuid.UUID
	Salt     []byte
	Name     string
	Data     []byte
	DataType int32
}
