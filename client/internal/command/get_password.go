package command

import (
	"context"
	"fmt"
	"time"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name GetPasswordUsecase
type GetPasswordUsecase interface {
	GetPasswordByName(ctx context.Context, name string, lockPassword string) (string, error)
	ExtractUserError(err error) error
}

type getPasswordCmd struct {
	*baseCommand
	usecase GetPasswordUsecase
}

func NewGetPasswordCmd(usecase GetPasswordUsecase, config *config.Config, logger *zap.Logger) *getPasswordCmd {
	gpcmd := &getPasswordCmd{
		usecase: usecase,
	}
	gpcmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "password",
		Short:   "Command for get password by resource name",
		Long:    "Command for get password by resource name",
		Example: "get password yandex-disk",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			name := args[0]
			lockPassword := askLockPassword(cmd)

			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			data, err := usecase.GetPasswordByName(ctx, name, lockPassword)
			if err != nil {
				logger.Error("get password command", zap.Error(err))
				return usecase.ExtractUserError(err)
			}

			cmd.Println(fmt.Sprintf("name: %s, password: %s", name, data))
			return nil
		},
	}, logger, config)
	gpcmd.GetCommand().Flags().StringP("name", "n", "", "name of password resource.")
	return gpcmd
}
