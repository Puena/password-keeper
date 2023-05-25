package command

import (
	"context"
	"fmt"

	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/models"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// ListUsecases interface for list command
//
//go:generate mockery --name ListUsecases
type ListUsecases interface {
	GetAllChests(ctx context.Context) (chest []*models.Chest, err error)
	ExtractUserError(err error) error
}

type listCmd struct {
	*baseCommand
	usecases ListUsecases
}

// Create list command.
func NewListCmd(usecases ListUsecases, config *config.Config, logger *zap.Logger) *listCmd {
	lcmd := &listCmd{
		usecases: usecases,
	}
	lcmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "list",
		Short:   "List all saved data.", // passwords will be hidden as ****
		Long:    "List all saved data with available filters.",
		Example: "list (-p -c -f are optional filtration, can be combined)",
		RunE:    lcmd.composeRunE(),
	}, logger, config)

	lcmd.cmd.Flags().BoolP("password", "p", false, "list only passwords.")
	lcmd.cmd.Flags().BoolP("card", "c", false, "list only credit cards.")
	lcmd.cmd.Flags().BoolP("file", "f", false, "list only files.")

	return lcmd
}

func (c *listCmd) composeRunE() CobraRunE {
	return func(cmd *cobra.Command, args []string) error {
		chests, err := c.usecases.GetAllChests(cmd.Context())
		if err != nil {
			c.logger.Info("list command", zap.Error(err))
			return c.usecases.ExtractUserError(err)
		}

		passwordFilter, err := cmd.Flags().GetBool("password")
		if err != nil {
			c.logger.Error("error while getting password flag")
			return err
		}
		cardFilter, err := cmd.Flags().GetBool("card")
		if err != nil {
			c.logger.Error("error while getting card flag")
			return err
		}
		fileFilter, err := cmd.Flags().GetBool("file")
		if err != nil {
			c.logger.Error("error while getting file flag")
			return err
		}

		for _, chest := range chests {
			chest := chest
			if passwordFilter && chest.DataType == models.ChestPasswordData {
				cmd.Println(c.formatChest(chest))
			} else if cardFilter && chest.DataType == models.ChestCreditCardData {
				cmd.Println(c.formatChest(chest))
			} else if fileFilter && chest.DataType == models.ChestFileData {
				cmd.Println(c.formatChest(chest))
			} else if !passwordFilter && !cardFilter && !fileFilter {
				cmd.Println(c.formatChest(chest))
			}
		}

		return nil
	}
}

func (c *listCmd) formatChest(chest *models.Chest) string {
	return fmt.Sprintf("data: **** | data type: %s | resourse name: %s", chest.DataType, chest.Name)
}
