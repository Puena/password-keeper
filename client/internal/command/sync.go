package command

import (
	"context"
	"io"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name SyncUsecase
type SyncUsecase interface {
	Sync(ctx context.Context, statusOutput io.Writer) error
	ExtractUserError(err error) error
}

type syncCmd struct {
	*baseCommand
	usecase SyncUsecase
}

func NewSyncCmd(usecase SyncUsecase, config *config.Config, logger *zap.Logger) *syncCmd {
	scmd := &syncCmd{
		usecase: usecase,
	}

	scmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "sync",
		Short:   "Command to sync your data to the remote server.",
		Long:    "Command to sync your data to the remote server. Your data stay encrypted. We don't have access to your data.",
		Example: "sync",
		RunE:    scmd.ComposeRunE(config, logger),
	}, logger, config)

	return scmd
}

func (c *syncCmd) ComposeRunE(config *config.Config, logger *zap.Logger) CobraRunE {
	return func(cmd *cobra.Command, args []string) error {
		err := c.usecase.Sync(cmd.Context(), cmd.OutOrStdout())
		if err != nil {
			logger.Error("sync command error", zap.Error(err))
			return c.usecase.ExtractUserError(err)
		}

		cmd.Println("Sync completed successfully.")
		return nil
	}
}
