package database

import (
	"context"
	"embed"

	"database/sql"
	"time"

	"github.com/Puena/password-keeper/server/config"
	_ "github.com/jackc/pgx/stdlib"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"go.uber.org/zap"
)

//go:embed migration/*.sql
var embedMigrations embed.FS

const (
	driver  = "pgx"
	dialect = "postgres"
)

// Database is a struct that represents the database instance.
type Database struct {
	config *config.Config
	logger *zap.Logger
}

// Init initialize database instance.
func Init(config *config.Config, logger *zap.Logger) *Database {
	if config.PostgresConnectionString == "" {
		panic("database required config.PostgresConnectionString")
	}
	return &Database{
		config: config,
		logger: logger,
	}
}

// Connect handle connect to postgres instance and check connection by ping.
// Required PostgresConnectionString in config.
func (d *Database) Connect(ctx context.Context) (*pgxpool.Pool, error) {
	d.logger.Info("start database connection")
	pool, err := pgxpool.New(ctx, d.config.PostgresConnectionString)
	if err != nil {
		d.logger.Error("open connetion error", zap.Error(err))
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = pool.Ping(pingCtx)
	if err != nil {
		d.logger.Error("ping to database error", zap.Error(err))
		return nil, err
	}
	d.logger.Info("connection established")
	return pool, nil
}

// UpMigration migrate postgres from folder that specified in config.
func (d *Database) UpMigration() error {
	d.logger.Debug("start migration", zap.String("driver", driver), zap.String("dialect", dialect), zap.String("connection string", d.config.PostgresConnectionString))

	db, err := sql.Open(driver, d.config.PostgresConnectionString)
	if err != nil {
		d.logger.Error("open db error", zap.Error(err))
		return err
	}

	goose.SetBaseFS(embedMigrations)

	err = goose.SetDialect(dialect)
	if err != nil {
		d.logger.Error("goose set deialect error", zap.Error(err))
		return err
	}

	err = goose.Up(db, "migration")
	if err != nil {
		d.logger.Error("goose up error", zap.Error(err))
		return err
	}

	d.logger.Info("migration done successfully")

	err = db.Close()
	if err != nil {
		d.logger.Error("error while closing db after migration")
		return err
	}

	return nil
}
