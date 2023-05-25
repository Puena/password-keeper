package command

import (
	"context"
	"fmt"
	"strings"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name RegisterUsecase
type RegisterUsecase interface {
	Registration(ctx context.Context, login string, password string) error
	ExtractUserError(err error) error
}

type registerCmd struct {
	*baseCommand
	usecase RegisterUsecase
}

func NewRegisterCmd(usecase RegisterUsecase, config *config.Config, logger *zap.Logger) *registerCmd {
	rcmd := &registerCmd{
		usecase: usecase,
	}

	rcmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "registrate",
		Short:   "Command to register a new user",
		Long:    "With this command you can register new account for sync your chests.",
		Example: "registrate -l my-login -p my-strong-password",
		RunE:    rcmd.ComposeRunE(config, logger),
	}, logger, config)

	rcmd.GetCommand().Flags().StringP("login", "l", "", "Login for the new user")
	rcmd.GetCommand().Flags().StringP("password", "p", "", "Password for the new user")
	rcmd.GetCommand().MarkFlagsRequiredTogether("login", "password")

	return rcmd
}

func (c *registerCmd) ComposeRunE(config *config.Config, logger *zap.Logger) CobraRunE {
	return func(cmd *cobra.Command, args []string) error {
		login, err := cmd.Flags().GetString("login")
		if err != nil {
			return fmt.Errorf("login is required: %w", err)
		}

		password, err := cmd.Flags().GetString("password")
		if err != nil {
			return fmt.Errorf("password is required: %w", err)
		}

		err = c.usecase.Registration(cmd.Context(), strings.TrimSpace(login), strings.TrimSpace(password))
		if err != nil {
			logger.Error("registrate command registartion error", zap.Error(err))
			return c.usecase.ExtractUserError(err)
		}

		return nil
	}
}
