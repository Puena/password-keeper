package command

import (
	"os"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const (
	loginFlag = "login"
	showFlag  = "show"
)

type configCommand struct {
	*baseCommand
}

// NewConfigCmd create command that allow you set some configuration.
func NewConfigCmd(logger *zap.Logger, config *config.Config) *configCommand {
	ccmd := &configCommand{}
	ccmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "config",
		Short:   "Command to set app configuration",
		Long:    "Command to set app configuration, authentification data and etc.",
		Example: "config --login 'mail@mail.ru'",
		RunE:    ccmd.composeRunE(logger, config),
		Args:    cobra.ExactArgs(0),
	}, logger, config)
	ccmd.GetCommand().Flags().StringP(loginFlag, "l", "", "your login for authentification on the server.")
	ccmd.GetCommand().Flags().BoolP(showFlag, "s", false, "show content of config.")
	viper.BindPFlag(loginFlag, ccmd.GetCommand().Flags().Lookup(loginFlag))
	return ccmd
}

func (c *configCommand) composeRunE(logger *zap.Logger, config *config.Config) CobraRunE {
	return func(cmd *cobra.Command, args []string) error {
		f, err := cmd.Flags().GetString(loginFlag)
		if err != nil {
			logger.Info("error while getting login flag", zap.Error(err))
			return err
		}
		if f != "" {
			err = viper.WriteConfig()
			if err != nil {
				return err
			}
			cmd.Println("Config updated successfully.")
		}

		show, err := cmd.Flags().GetBool(showFlag)
		if err != nil {
			logger.Info("error while getting show flag", zap.Error(err))
			return err
		}

		if show {
			file, err := os.ReadFile(viper.ConfigFileUsed())
			if err != nil {
				return err
			}

			_, err = cmd.OutOrStdout().Write(file)
			if err != nil {
				return err
			}
		}
		return nil
	}
}
