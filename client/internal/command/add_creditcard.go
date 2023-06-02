package command

import (
	"context"
	"strings"
	"time"

	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/models"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name AddCreditCardUsecase
type AddCreditCardUsecase interface {
	AddCard(ctx context.Context, name string, card *models.Card, lockPassword string) error
	ExtractUserError(err error) error
}

type addCreditCardCmd struct {
	*baseCommand
	usecase AddCreditCardUsecase
}

func NewAddCreditCardCmd(usecase AddCreditCardUsecase, config *config.Config, logger *zap.Logger) *addCreditCardCmd {
	acccmd := &addCreditCardCmd{
		usecase: usecase,
	}
	acccmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "card",
		Short:   "Command for adding credit card",
		Long:    "Command for adding credit card",
		Args:    cobra.ExactArgs(1),
		Example: "add card sberbank --number 1234567890123456 --owner 'Alexander Ivanov' --expired 12/24 --cvv 123",
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			lockPassword := askLockPassword(cmd)

			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			err := usecase.AddCard(ctx, name, &models.Card{
				Number:  strings.TrimSpace(cmd.Flag("number").Value.String()),
				Owner:   strings.TrimSpace(cmd.Flag("owner").Value.String()),
				Expired: strings.TrimSpace(cmd.Flag("expired").Value.String()),
				Cvv:     strings.TrimSpace(cmd.Flag("cvv").Value.String()),
			}, lockPassword)
			if err != nil {
				logger.Error("add card error", zap.Error(err))
				return usecase.ExtractUserError(err)
			}

			cmd.Println("Card added successfully.")

			return nil
		},
	}, logger, config)
	acccmd.GetCommand().Flags().StringP("number", "n", "", "card number")
	acccmd.GetCommand().Flags().StringP("owner", "o", "", "card owner")
	acccmd.GetCommand().Flags().StringP("expired", "e", "", "card expired date")
	acccmd.GetCommand().Flags().StringP("cvv", "c", "", "card cvv code")
	acccmd.GetCommand().MarkFlagsRequiredTogether("number", "owner", "expired", "cvv")
	return acccmd
}
