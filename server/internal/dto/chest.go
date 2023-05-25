package dto

// Chest is a struct that represents the chest table in the usecase.
type Chest struct {
	ID       string `validate:"required"`
	UserID   *string
	Salt     []byte `validate:"required"`
	Name     string `validate:"required"`
	Data     []byte `validate:"required"`
	DataType int32  `validate:"gte=0"`
}
