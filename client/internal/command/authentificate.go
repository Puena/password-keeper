package command

import (
	"context"
	"fmt"
	"strings"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name AuthentificateUsecase
type AuthentificateUsecase interface {
	Authentification(ctx context.Context, login string, password string) error
	ExtractUserError(err error) error
}

type authentificateCmd struct {
	*baseCommand
	usecase AuthentificateUsecase
}

func NewAuthentificateCmd(usecase AuthentificateUsecase, config *config.Config, logger *zap.Logger) *authentificateCmd {
	acmd := &authentificateCmd{
		usecase: usecase,
	}

	acmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "auth",
		Short:   "Command to authentification.",
		Long:    "With this command you can log in to your account.",
		Example: "auth -l my-login -p my-strong-password",
		RunE:    acmd.ComposeRunE(config, logger),
	}, logger, config)

	acmd.GetCommand().Flags().StringP("login", "l", "", "Login for the new user")
	acmd.GetCommand().Flags().StringP("password", "p", "", "Password for the new user")
	acmd.GetCommand().MarkFlagsRequiredTogether("login", "password")

	return acmd
}

func (c *authentificateCmd) ComposeRunE(config *config.Config, logger *zap.Logger) CobraRunE {
	return func(cmd *cobra.Command, args []string) error {
		login, err := cmd.Flags().GetString("login")
		if err != nil {
			return fmt.Errorf("login is required: %w", err)
		}
		login = strings.TrimSpace(login)

		password, err := cmd.Flags().GetString("password")
		if err != nil {
			return fmt.Errorf("password is required: %w", err)
		}
		password = strings.TrimSpace(password)

		err = c.usecase.Authentification(cmd.Context(), login, password)
		if err != nil {
			logger.Error("authentificate command registartion error", zap.Error(err))
			return c.usecase.ExtractUserError(err)
		}

		cmd.Println("Authentification successfully.")

		return nil
	}
}
