package command

import (
	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name GetUsecases
type GetUsecases interface {
	GetFileUsecase
	GetCreditCardUsecase
	GetPasswordUsecase
}

type getCmd struct {
	*baseCommand
	usecases GetUsecases
}

// Create add comman.
func NewGetCmd(usecases GetUsecases, config *config.Config, logger *zap.Logger) *getCmd {
	gcmd := &getCmd{
		usecases: usecases,
	}
	gcmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:   "get",
		Short: "Command to get some data.",
		Long:  "Command to get some data.",
	}, logger, config)

	gcmd.AddCommand(
		NewGetPasswordCmd(usecases, config, logger),
		NewGetCreditCardCmd(usecases, config, logger),
		NewGetFileCmd(usecases, config, logger),
	)

	return gcmd
}
