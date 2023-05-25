package command

import (
	"bufio"
	"context"
	"strings"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// CobraRunE allias for cobra command RunE fucntion.
type CobraRunE func(cmd *cobra.Command, args []string) error

type baseCommand struct {
	logger *zap.Logger
	config *config.Config
	cmd    *cobra.Command
}

type buildCommand interface {
	GetCommand() *cobra.Command
	ExecuteContext(ctx context.Context)
}

func NewBaseCommand(cmd *cobra.Command, logger *zap.Logger, config *config.Config) *baseCommand {
	return &baseCommand{
		logger: logger,
		config: config,
		cmd:    cmd,
	}
}

// GetCommand implementation for some interfaces.
func (c *baseCommand) GetCommand() *cobra.Command {
	return c.cmd
}

func (c *baseCommand) AddCommand(cmds ...buildCommand) {
	for _, cmd := range cmds {
		c.GetCommand().AddCommand(cmd.GetCommand())
	}
}

// ExecuteContext is command executer with context.
func (c *baseCommand) ExecuteContext(ctx context.Context) {
	err := c.cmd.ExecuteContext(ctx)
	if err != nil {
		c.logger.Error("command error", zap.Error(err))
	}
}

func newScanner(cmd *cobra.Command) *bufio.Scanner {
	return bufio.NewScanner(cmd.InOrStdin())
}

func readString(scanner *bufio.Scanner) string {
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

func askLockPassword(cmd *cobra.Command) string {
	cmd.Println("Enter lock password:")
	scanner := newScanner(cmd)
	lockPassword := readString(scanner)
	cmd.Printf("\033[2A\033[0J") // clear last two lines - question and answer
	return lockPassword
}
