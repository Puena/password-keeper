package repository

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Puena/password-keeper/client/config"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestRepositories(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	t.Run("create repositories", func(t *testing.T) {
		db, _, err := sqlmock.New()
		require.NoError(t, err, "failed while init sqlmock")
		dbMock := sqlx.NewDb(db, "sqlmock")
		repos := NewRepositories(dbMock, viper.GetViper(), cfg, lg)
		require.NotNil(t, repos, "repositories is nil")
	})
}
