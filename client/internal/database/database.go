package database

import (
	"context"
	"embed"
	"fmt"
	"os"
	"time"

	"github.com/Puena/password-keeper/client/config"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"
	"go.uber.org/zap"
)

//go:embed migration/*.sql
var embedMigrations embed.FS

const dabaseFileName = "keeper.db"
const driver = "sqlite3"
const dialect = "sqlite3"

type database struct {
	config *config.Config
	logger *zap.Logger
	db     *sqlx.DB
}

// Create new sqlite database.
func NewDatabase(config *config.Config, logger *zap.Logger) (*database, error) {

	p, err := config.ReadViperConfig()
	if err != nil {
		return nil, fmt.Errorf("failed whlie read viper config %w", err)
	}

	CreateDatabasePath(p.DatabasePath)

	sqlite, err := sqlx.Open(driver, fmt.Sprintf("%s/%s", p.DatabasePath, dabaseFileName))
	if err != nil {
		return nil, fmt.Errorf("failed while trying to open database %w", err)
	}
	sqlite.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = sqlite.PingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed while trying ping database %w", err)
	}

	return &database{
		config: config,
		logger: logger,
		db:     sqlite,
	}, nil
}

// GetDB getter for db.
func (d *database) GetDB() *sqlx.DB {
	return d.db
}

func CreateDatabasePath(filepath string) error {

	return os.MkdirAll(filepath, 0744)
}

func RemoveDataBase(filepath string) error {

	return os.Remove(fmt.Sprintf("%s/%s", filepath, dabaseFileName))
}

func (d *database) UpMigration() error {
	d.logger.Debug("start migration", zap.String("driver", driver), zap.String("dialect", dialect))

	if d.config.GetBuildInfo().Release {
		goose.SetLogger(goose.NopLogger())
	}

	goose.SetBaseFS(embedMigrations)

	err := goose.SetDialect(dialect)
	if err != nil {
		d.logger.Error("goose set deialect error", zap.Error(err))
		return err
	}

	err = goose.Up(d.db.DB, "migration") // shoud be equal embeded variable.
	if err != nil {
		d.logger.Error("goose up error", zap.Error(err))
		return err
	}

	d.logger.Info("migration done successfully")

	return nil
}

func (d *database) DownMigration() error {
	d.logger.Debug("down migration")

	goose.SetBaseFS(embedMigrations)

	err := goose.SetDialect(dialect)
	if err != nil {
		d.logger.Error("goose set deialect error", zap.Error(err))
		return err
	}

	err = goose.Down(d.db.DB, "migration") // shoud be equal embeded variable.
	if err != nil {
		d.logger.Error("goose up error", zap.Error(err))
		return err
	}

	d.logger.Info("migration down successfully")

	return nil

}
