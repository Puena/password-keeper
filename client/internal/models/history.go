package models

type HistoryOperationType int

const (
	HistoryCreateOperation HistoryOperationType = iota
	HistoryUpdateOperation
	HistoryDeleteOperation
)

type History struct {
	ID            string               `db:"id"`
	ChestID       string               `db:"chest_id"`
	UserID        *string              `db:"user_id"`
	OperationType HistoryOperationType `db:"operation_type"`
	OperationTime int64                `db:"operation_time"`
	SyncingTime   *int64               `db:"syncing_time"`
	DeviceName    string               `db:"device_name"`
	DeviceIP      *string              `db:"device_ip"`
}
