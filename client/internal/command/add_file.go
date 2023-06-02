package command

import (
	"context"
	"strings"
	"time"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name AddFileUsecase
type AddFileUsecase interface {
	AddFile(ctx context.Context, name string, data []byte, lockPassword string) error
	ReadFile(ctx context.Context, path string) ([]byte, error)
	ExtractUserError(err error) error
}

type addFileCmd struct {
	*baseCommand
	usecase AddFileUsecase
}

func NewAddFileCmd(usecase AddFileUsecase, config *config.Config, logger *zap.Logger) *addFileCmd {
	afcmd := &addFileCmd{
		usecase: usecase,
	}
	afcmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "file",
		Short:   "Command for adding file or byte data.",
		Long:    "Command for adding file or byte data.",
		Example: "add file driver-licend-scan -p 'path/to/file'",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := cmd.Flag("path").Value.String()
			path = strings.TrimSpace(path)
			name := args[0]

			data, err := usecase.ReadFile(cmd.Context(), path)
			if err != nil {
				logger.Error("add file command error while reading", zap.Error(err))
				return usecase.ExtractUserError(err)
			}

			lockPassword := askLockPassword(cmd)
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			err = usecase.AddFile(ctx, name, data, lockPassword)
			if err != nil {
				logger.Error("add file command error while adding", zap.Error(err))
				return usecase.ExtractUserError(err)
			}

			cmd.Println("File added successfully.")

			return nil
		},
	}, logger, config)
	afcmd.GetCommand().Flags().StringP("path", "p", "", "Path to file.")
	afcmd.GetCommand().MarkFlagRequired("path")
	return afcmd
}
