package models

import (
	"fmt"
	"strings"
)

type Card struct {
	Number  string // card number
	Owner   string // card owner
	Expired string // card expire date
	Cvv     string // card cvv
}

func (c *Card) String() string {
	view := fmt.Sprintf("number: %s\nowner: %s\nexpired: %s\tcvv: %s\n", c.getFormattedNumber(), c.Owner, c.Expired, c.Cvv)
	return view
}

func (c *Card) getFormattedNumber() string {
	tempNumber := strings.ReplaceAll(c.Number, " ", "")
	return fmt.Sprintf("%s %s %s %s", tempNumber[:4], tempNumber[4:8], tempNumber[8:12], tempNumber[12:])
}
