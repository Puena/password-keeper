package command

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/models"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:generate mockery --name EditCreditCardUsecase
type EditCreditCardUsecase interface {
	EditCard(ctx context.Context, name string, newName string, newCard *models.Card, lockPassword string) error
	ExtractUserError(err error) error
}

type editCreditCardCmd struct {
	*baseCommand
	usecase EditCreditCardUsecase
}

func NewEditCreditCardCmd(usecase EditCreditCardUsecase, config *config.Config, logger *zap.Logger) *editCreditCardCmd {
	ecccmd := &editCreditCardCmd{
		usecase: usecase,
	}
	ecccmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "card",
		Short:   "Credit card editing",
		Long:    "Credit card editing",
		Example: "edit card sberbank -name sberbank -n 1234567890123456 -o 'Ivan Ivanov' -e 07/22 -cvc 123 (note: all flags are optional))",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			name := args[0]
			newName := cmd.Flag("name").Value.String()
			fmt.Println("newName: ", newName)
			newCard := &models.Card{
				Number:  strings.TrimSpace(cmd.Flag("number").Value.String()),
				Owner:   strings.TrimSpace(cmd.Flag("owner").Value.String()),
				Expired: strings.TrimSpace(cmd.Flag("expired").Value.String()),
				Cvv:     strings.TrimSpace(cmd.Flag("cvv").Value.String()),
			}
			lockPassword := askLockPassword(cmd)

			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			err := usecase.EditCard(ctx, name, newName, newCard, lockPassword)
			if err != nil {
				logger.Error("edit card command", zap.Error(err))
				return usecase.ExtractUserError(err)
			}

			cmd.Println("Card updated successfully.")

			return nil
		},
	}, logger, config)
	ecccmd.GetCommand().Flags().String("name", "", "edit name")
	ecccmd.GetCommand().Flags().StringP("number", "n", "", "card number")
	ecccmd.GetCommand().Flags().StringP("owner", "o", "", "card owner")
	ecccmd.GetCommand().Flags().StringP("expired", "e", "", "card expired date")
	ecccmd.GetCommand().Flags().StringP("cvv", "c", "", "card cvv code")

	return ecccmd
}
