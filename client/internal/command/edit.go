package command

import (
	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name EditUsecases
type EditUsecases interface {
	EditPassowrdUsecase
	EditCreditCardUsecase
	EditFileUsecase
}

type editCmd struct {
	*baseCommand
	usecases EditUsecases
}

func NewEditCmd(usecases EditUsecases, config *config.Config, logger *zap.Logger) *editCmd {
	ecmd := &editCmd{
		usecases: usecases,
	}
	ecmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:   "edit",
		Short: "Command to edit your sensivity data.",
		Long:  "Command to edit your sensivity data.",
		Args:  cobra.MaximumNArgs(1),
		PostRunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("data have been saved.")
			return nil
		},
	}, logger, config)

	ecmd.baseCommand.AddCommand(
		NewEditPasswordCmd(usecases, config, logger),
		NewEditCreditCardCmd(usecases, config, logger),
		NewEditFileCmd(usecases, config, logger),
	)

	return ecmd
}
