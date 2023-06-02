package app

import (
	"context"
	"fmt"
	"os"

	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/adapter"
	"github.com/Puena/password-keeper/client/internal/command"
	"github.com/Puena/password-keeper/client/internal/database"
	"github.com/Puena/password-keeper/client/internal/repository"
	"github.com/Puena/password-keeper/client/internal/usecase"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type DatabaseHelper interface {
	UpMigration() error
	DownMigration() error
}

type App struct {
	config   *config.Config
	logger   *zap.Logger
	rootCmd  *cobra.Command
	database DatabaseHelper
}

func initLogger(config *config.Config) (log *zap.Logger, err error) {
	if config.GetBuildInfo().Release {
		log, err = zap.NewProduction()
	} else {
		allLevels := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
			return true
		})
		zapConfig := zap.NewDevelopmentEncoderConfig()
		fileEncoder := zapcore.NewJSONEncoder(zapConfig)
		viperConfig, err := config.ReadViperConfig()
		if err != nil {
			return nil, err
		}
		logFilePath := fmt.Sprintf("%s/%s", viperConfig.LogPath, "logs.log")
		logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0744)
		if err != nil {
			return nil, err
		}
		fileSyncer := zapcore.AddSync(logFile)
		zapFile := zapcore.NewTee(
			zapcore.NewCore(fileEncoder, fileSyncer, allLevels),
		)
		return zap.New(zapFile), nil
	}

	return log, err
}

// New create pre configured new app.
func New(config *config.Config) (*App, error) {
	logger, err := initLogger(config)
	if err != nil {
		return nil, err
	}

	db, err := database.NewDatabase(config, logger)
	if err != nil {
		return nil, err
	}
	err = db.UpMigration()
	if err != nil {
		return nil, err
	}

	repositories := repository.NewRepositories(db.GetDB(), viper.GetViper(), config, logger)
	usecases := usecase.NewUsecases(adapter.NewUsecaesRepositoriesAdapter(repositories), config, logger)
	rootCmd := command.NewRootCmd(usecases, config, logger).GetCommand()

	return &App{
		config:   config,
		logger:   logger,
		rootCmd:  rootCmd,
		database: db,
	}, nil
}

// GetCommand return root cobra command from app.
func (a *App) GetCommand() *cobra.Command {
	return a.rootCmd
}

func (a *App) GetDatabase() DatabaseHelper {
	return a.database
}

func (a *App) GenMarkdownDoc(path string) error {
	return doc.GenMarkdownTree(a.rootCmd, path)
}

// Run app.
func (a *App) Run() error {
	defer a.logger.Sync()
	go func() {
		viper.GetViper().OnConfigChange(func(in fsnotify.Event) {
			a.logger.Debug("config file changed:", zap.Any("event", in))
		})
		viper.WatchConfig()
	}()

	ctx := context.Background()
	a.rootCmd.ExecuteContext(ctx)
	return nil
}
