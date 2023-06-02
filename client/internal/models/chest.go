package models

type ChestDataType int

const (
	ChestPasswordData ChestDataType = iota
	ChestCreditCardData
	ChestFileData
	ChestBinaryData
)

// chestDataTypeString is string representation of [ChestDataType].
// be carefule when modifing, order is metter.
var chestDataTypeString = []string{
	"password",
	"credit card",
	"file data",
	"binary data",
}

// String return string representation of [ChestDataType].
func (t ChestDataType) String() string {
	typeCode := int(t)
	if typeCode >= len(chestDataTypeString) {
		return "uknown"
	}
	return chestDataTypeString[typeCode]
}

type Chest struct {
	ID       string        `db:"id"`
	UserID   *string       `db:"user_id"`
	Salt     []byte        `db:"salt"`
	Name     string        `db:"name"`
	Data     []byte        `db:"data"`
	DataType ChestDataType `db:"data_type"`
}
