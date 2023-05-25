package command

import (
	"fmt"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type RootUsecases interface {
	AddUsecases
	EditUsecases
	GetUsecases
	ListUsecases
	DeleteUsecases
	RegisterUsecase
	AuthentificateUsecase
	SyncUsecase
}

type rootCmd struct {
	*baseCommand
}

func NewRootCmd(usecases RootUsecases, config *config.Config, logger *zap.Logger) *rootCmd {
	root := &rootCmd{
		baseCommand: NewBaseCommand(&cobra.Command{
			Use:   "keeper",
			Short: "Keeper is the best password manager in the world :shy: !",
			Long: `Keeper is password manager that safe your data carefully,
						we use client side encryption and don't have any access to your
						sensivity data, we are respect privacy. You can use it local or sync it with our backend.`,
			Example:   "",
			ValidArgs: []string{"list", "add", "remove", "edit", "sync", "config"},
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Fprintf(cmd.OutOrStdout(), "hello from keeper command")
				return nil
			},
		}, logger, config),
	}

	root.AddCommand(
		NewConfigCmd(logger, config),
		NewRegisterCmd(usecases, config, logger),
		NewAuthentificateCmd(usecases, config, logger),
		NewAddCmd(logger, config, usecases),
		NewEditCmd(usecases, config, logger),
		NewGetCmd(usecases, config, logger),
		NewListCmd(usecases, config, logger),
		NewDeleteCmd(usecases, config, logger),
		NewSyncCmd(usecases, config, logger),
		NewVersionCmd(logger, config),
	)
	return root
}
