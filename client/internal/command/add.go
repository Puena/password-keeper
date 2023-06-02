package command

import (
	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name AddUsecases
type AddUsecases interface {
	AddPasswordUsecase
	AddCreditCardUsecase
	AddFileUsecase
}

type addCmd struct {
	*baseCommand
	usecases AddUsecases
}

// Create add comman.
func NewAddCmd(logger *zap.Logger, config *config.Config, usecases AddUsecases) *addCmd {
	acmd := &addCmd{
		usecases: usecases,
	}
	acmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:   "add",
		Short: "Command to add some sensivity data to the storage.",
		Long:  "Command to add some sensivity data to the storage.",
	}, logger, config)

	acmd.AddCommand(
		NewAddPasswordCmd(logger, config, usecases),
		NewAddCreditCardCmd(usecases, config, logger),
		NewAddFileCmd(usecases, config, logger),
	)

	return acmd
}
