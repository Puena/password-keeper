package command

import (
	"context"
	"strings"
	"time"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name GetFileUsecase
type GetFileUsecase interface {
	GetFileByName(ctx context.Context, name string, lockPassword string) ([]byte, error)
	WriteFile(ctx context.Context, path string, data []byte) error
	ExtractUserError(err error) error
}

type getFileCmd struct {
	*baseCommand
	usecase GetFileUsecase
}

func NewGetFileCmd(usecase GetFileUsecase, config *config.Config, logger *zap.Logger) *getFileCmd {
	gflcmd := &getFileCmd{
		usecase: usecase,
	}
	gflcmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "file",
		Short:   "Command for get file by resource name",
		Long:    "Command for get file by resource name",
		Example: "get file my-driver-license -o '/home/user/my-driver-license.jpg' OR get file my-driver-licence",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			lockPassword := askLockPassword(cmd)
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			data, err := usecase.GetFileByName(ctx, name, lockPassword)
			if err != nil {
				logger.Error("get password command", zap.Error(err))
				return usecase.ExtractUserError(err)
			}

			output := cmd.Flag("output").Value.String()
			output = strings.TrimSpace(output)

			if output != "" {
				err = usecase.WriteFile(ctx, output, data)
				if err != nil {
					logger.Error("get password command", zap.Error(err))
					return usecase.ExtractUserError(err)
				}
			} else {
				cmd.Println(string(data))
			}

			return nil
		},
	}, logger, config)
	gflcmd.GetCommand().Flags().StringP("output", "o", "", "output file path.")
	return gflcmd
}
