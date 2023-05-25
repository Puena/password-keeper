package command

import (
	"context"
	"time"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name AddPasswordUsecase
type AddPasswordUsecase interface {
	AddPassword(ctx context.Context, name string, passowrd string, lockPassword string) error
	ExtractUserError(err error) error
}

type addPasswordCmd struct {
	*baseCommand
	usecase AddPasswordUsecase
}

func NewAddPasswordCmd(logger *zap.Logger, config *config.Config, usecase AddPasswordUsecase) *addPasswordCmd {
	pcmd := &addPasswordCmd{
		usecase: usecase,
	}
	pcmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "password",
		Short:   "Command for adding password",
		Long:    "Command for adding password",
		Example: "add password yandex-disk my-strong-password",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			password := args[1]
			lockPassword := askLockPassword(cmd)

			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			err := usecase.AddPassword(ctx, name, password, lockPassword)
			if err != nil {
				logger.Error("add password command error", zap.Error(err))
				return usecase.ExtractUserError(err)
			}

			cmd.Println("Password added successfully.")

			return nil
		},
	}, logger, config)
	return pcmd
}
