package command

import (
	"context"
	"strings"
	"time"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name EditFileUsecase
type EditFileUsecase interface {
	EditFile(ctx context.Context, name string, newName string, newData []byte, lockPassword string) error
	ReadFile(ctx context.Context, path string) ([]byte, error)
	ExtractUserError(err error) error
}

type editFileCmd struct {
	*baseCommand
	usecase EditFileUsecase
}

func NewEditFileCmd(usecase EditFileUsecase, config *config.Config, logger *zap.Logger) *editFileCmd {
	gflcmd := &editFileCmd{
		usecase: usecase,
	}
	gflcmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "file",
		Short:   "Command for update file context.",
		Long:    "Command for update file context from path or just other app output.",
		Example: "edit file driver-licend-scan -p 'path/to/file'",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := cmd.Flag("path").Value.String()
			path = strings.TrimSpace(path)
			var data []byte
			if path != "" {
				var err error
				data, err = usecase.ReadFile(cmd.Context(), path)
				if err != nil {
					logger.Error("add file command error", zap.Error(err))
					return usecase.ExtractUserError(err)
				}
			}
			name := args[0]
			newName := cmd.Flag("name").Value.String()
			newName = strings.TrimSpace(newName)
			lockPassword := askLockPassword(cmd)

			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			err := usecase.EditFile(ctx, name, newName, data, lockPassword)
			if err != nil {
				logger.Error("add file command error", zap.Error(err))
				return usecase.ExtractUserError(err)
			}

			cmd.Println("File updated successfully.")

			return nil
		},
	}, logger, config)
	gflcmd.GetCommand().Flags().StringP("path", "p", "", "Path to file.")
	gflcmd.GetCommand().Flags().StringP("name", "n", "", "New name for file.")
	return gflcmd
}
