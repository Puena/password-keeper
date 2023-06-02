package command

import (
	"context"
	"time"

	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/models"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name GetCreditCardUsecase
type GetCreditCardUsecase interface {
	GetCardByName(ctx context.Context, name string, lockPassword string) (*models.Card, error)
	ExtractUserError(err error) error
}

type getCreditCardCmd struct {
	*baseCommand
	usecase GetCreditCardUsecase
}

func NewGetCreditCardCmd(usecase GetCreditCardUsecase, config *config.Config, logger *zap.Logger) *getCreditCardCmd {
	gcccmd := &getCreditCardCmd{
		usecase: usecase,
	}
	gcccmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "card",
		Short:   "Command for get credit card data.",
		Long:    "Command for get credit card data.",
		Example: "get card sberbank",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			lockPassword := askLockPassword(cmd)

			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			data, err := usecase.GetCardByName(ctx, name, lockPassword)
			if err != nil {
				logger.Error("get password command", zap.Error(err))
				return usecase.ExtractUserError(err)
			}

			cmd.Println(data)
			return nil
		},
	}, logger, config)
	return gcccmd
}
