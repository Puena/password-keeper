package command

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name EditPassowrdUsecase
type EditPassowrdUsecase interface {
	EditPassword(ctx context.Context, name string, newName string, newPassword string, lockPassword string) error
	ExtractUserError(err error) error
}

type editPasswordCmd struct {
	*baseCommand
	usecase EditPassowrdUsecase
}

func NewEditPasswordCmd(usecase EditPassowrdUsecase, config *config.Config, logger *zap.Logger) *editPasswordCmd {
	epcmd := &editPasswordCmd{
		usecase: usecase,
	}
	epcmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "password",
		Short:   "Password editing",
		Long:    "Password editing",
		Example: "edit password mail@mail.ru -n ya@mail.ru -p some-new-password-or-not",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			newName, err := cmd.Flags().GetString("name")
			if err != nil {
				logger.Error("error while get name flag", zap.Error(err))
				return fmt.Errorf("name is required")
			}
			newName = strings.TrimSpace(newName)
			newPassword, err := cmd.Flags().GetString("password")
			if err != nil {
				logger.Error("error while get password flag", zap.Error(err))
				return fmt.Errorf("password is required")
			}
			newPassword = strings.TrimSpace(newPassword)

			lockPassword := askLockPassword(cmd)

			oldName := args[0]
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			err = usecase.EditPassword(ctx, oldName, newName, newPassword, lockPassword)
			if err != nil {
				logger.Error("edit password command", zap.Error(err))
				return usecase.ExtractUserError(err)
			}

			cmd.Println("Password edited successfully")

			return nil
		},
	}, logger, config)
	epcmd.GetCommand().Flags().StringP("name", "n", "", "edit name")
	epcmd.GetCommand().Flags().StringP("password", "p", "", "edit password")
	return epcmd
}
