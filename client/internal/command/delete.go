package command

import (
	"context"
	"time"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name DeleteUsecases
type DeleteUsecases interface {
	DeleteChest(ctx context.Context, name string, lockPassword string) error
	ExtractUserError(err error) error
}

type deleteCmd struct {
	*baseCommand
	usecases DeleteUsecases
}

// Create delete command.
func NewDeleteCmd(usecases DeleteUsecases, config *config.Config, logger *zap.Logger) *deleteCmd {
	dcmd := &deleteCmd{
		usecases: usecases,
	}
	dcmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "delete",
		Short:   "Command to delete data from storage by name.",
		Long:    "Command to delete data from storage by name. To show saved data use 'list' command.",
		Example: "delete sberbank",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// ask user to promt lock password.
			lockPassword := askLockPassword(cmd)
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			err := usecases.DeleteChest(ctx, args[0], lockPassword)
			if err != nil {
				logger.Error("delete password command", zap.Error(err))
				return usecases.ExtractUserError(err)
			}

			cmd.Println("Data deleted successfully.")

			return nil

		},
	}, logger, config)

	return dcmd
}
