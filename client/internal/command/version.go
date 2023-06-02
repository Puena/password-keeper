package command

import (
	"runtime/debug"

	"github.com/Puena/password-keeper/client/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type versionCmd struct {
	*baseCommand
}

// NewVersionCmd create command that show version of app and build info.
func NewVersionCmd(logger *zap.Logger, cfg *config.Config) *versionCmd {

	vcmd := &versionCmd{}
	vcmd.baseCommand = NewBaseCommand(&cobra.Command{
		Use:     "version",
		Aliases: []string{"v"},
		Short:   "Print the version of Keeper",
		Long:    "Print the version of Keeper",
		Example: "keeper version",
		RunE:    vcmd.composeRunE(logger, cfg),
	}, logger, cfg)
	return vcmd
}

func (v *versionCmd) composeRunE(logger *zap.Logger, config *config.Config) CobraRunE {
	return func(cmd *cobra.Command, args []string) error {
		bi, _ := debug.ReadBuildInfo()
		var host string
		var arch string
		for _, v := range bi.Settings {
			switch v.Key {
			case "GOOS":
				host = v.Value
			case "GOARCH":
				arch = v.Value
			}
		}
		cmd.Printf("Keeper version keeper%s, buid: %s %s/%s\n", config.GetBuildInfo().Version, config.GetBuildInfo().Time, host, arch)
		return nil
	}
}
