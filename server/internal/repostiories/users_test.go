package repositories

import (
	"context"
	"errors"
	"testing"

	"github.com/Puena/password-keeper/server/config"
	"github.com/Puena/password-keeper/server/internal/models"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// $go test -v -run "^TestInsertUser"
func TestInsertUser(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "not expected error while initializing logger")

	testData, err := models.NewUserModel("mail@mail.ru", "some-strong-password")
	require.NoError(t, err, "failed when init new user model")

	t.Run("success_insert", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err, "not expected error while creating new pgx pool")
		mock.ExpectQuery("INSERT INTO users").
			WithArgs(&testData.Id, &testData.Login, &testData.PasswordHash, &testData.CreatedAt).
			WillReturnRows(
				pgxmock.NewRows([]string{"id"}).AddRow(testData.Id),
			)
		defer mock.Close()

		repo := NewUsersRepository(mock, cfg, lg)
		id, err := repo.InsertUser(context.Background(), testData)
		assert.NoError(t, err, "failed while inserting user")
		assert.Equal(t, testData.Id, *id, "failed while comparing ids")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err, "failed when check expectation of query")
	})

	t.Run("some_internal_error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err, "not expected error while creating new pgx pool")
		mock.ExpectQuery("INSERT INTO users").
			WithArgs(&testData.Id, &testData.Login, &testData.PasswordHash, &testData.CreatedAt).
			WillReturnError(errors.New("some internal error"))

		defer mock.Close()

		repo := NewUsersRepository(mock, cfg, lg)
		id, err := repo.InsertUser(context.Background(), testData)
		assert.Error(t, err, "failed while expecting error")
		var expectingError *errUserRepository
		assert.ErrorAs(t, err, &expectingError, "failed when expecting user repo error type")
		assert.Nil(t, id, "failed while expecting nil for id")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err, "failed when check expectation of query")
	})

	t.Run("error_when_result_is_empty", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err, "not expected error while creating new pgx pool")
		mock.ExpectQuery("INSERT INTO users").
			WithArgs(&testData.Id, &testData.Login, &testData.PasswordHash, &testData.CreatedAt).
			WillReturnError(pgx.ErrNoRows)

		defer mock.Close()

		repo := NewUsersRepository(mock, cfg, lg)
		id, err := repo.InsertUser(context.Background(), testData)
		assert.Error(t, err, "failed while expecting error")
		assert.NotNil(t, repo.NotFoundError(err), "failed when expecint not found error from insert query")
		assert.Nil(t, id, "failed while expecting nil for id")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err, "failed when check expectation of query")
	})

	t.Run("error_conflict_when_insert", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err, "not expected error while creating new pgx pool")
		mock.ExpectQuery("INSERT INTO users").
			WithArgs(&testData.Id, &testData.Login, &testData.PasswordHash, &testData.CreatedAt).
			WillReturnError(&pgconn.PgError{
				Code: pgerrcode.UniqueViolation,
			})

		defer mock.Close()

		repo := NewUsersRepository(mock, cfg, lg)
		id, err := repo.InsertUser(context.Background(), testData)
		assert.Error(t, err, "failed while expecting error")
		assert.NotNil(t, repo.ConflictError(err), "failed when expecting conflict error from insert query")
		assert.Nil(t, id, "failed while expecting nil for id")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err, "failed when check expectation of query")
	})

}

// $go test -v -run "^TestSelectUserByID"
func TestSelectUserByID(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "not expected error while initializing logger")

	testData, err := models.NewUserModel("mail@mail.ru", "some-strong-password")
	require.NoError(t, err, "failed when init new user model")

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err, "not expected error while creating new pgx pool")

		mock.ExpectQuery("SELECT (.+) FROM users").
			WithArgs(&testData.Id).
			WillReturnRows(pgxmock.NewRows([]string{"id", "login", "password", "created_at"}).
				AddRow(testData.Id, testData.Login, testData.PasswordHash, testData.CreatedAt))
		defer mock.Close()

		repo := NewUsersRepository(mock, cfg, lg)
		user, err := repo.SelectUserByID(context.Background(), testData.Id)
		assert.NoError(t, err, "failed while selecing user by id, not expecting err for succesfull query")
		assert.NotNil(t, user, "failed while selecting user by id, not expecting user as nil")
		assert.Equal(t, testData.Login, user.Login, "failed when compare logins")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err, "failed when check expectation of query")
	})

	t.Run("some_internal_error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err, "not expected error while creating new pgx pool")

		mock.ExpectQuery("SELECT (.+) FROM users").
			WithArgs(&testData.Id).
			WillReturnError(errors.New("some internal error"))
		defer mock.Close()

		repo := NewUsersRepository(mock, cfg, lg)
		user, err := repo.SelectUserByID(context.Background(), testData.Id)
		assert.Error(t, err, "failed while expecing an error from select user by id query")
		assert.NotNil(t, repo.RepositoryError(err), "failed while expecting error type as ErrUserRepository")
		assert.Nil(t, user, "failed while expecing a nil for user model from select by user id query")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err, "failed when check expectation of query")
	})

	t.Run("error_when_result_is_empty", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err, "not expected error while creating new pgx pool")

		mock.ExpectQuery("SELECT (.+) FROM users").
			WithArgs(&testData.Id).
			WillReturnError(pgx.ErrNoRows)
		defer mock.Close()

		repo := NewUsersRepository(mock, cfg, lg)
		user, err := repo.SelectUserByID(context.Background(), testData.Id)
		assert.Error(t, err, "failed while expecing an error from select user by id query")
		assert.NotNil(t, repo.NotFoundError(err), "failed while expecting error type as ErrUserRepository")
		assert.Nil(t, user, "failed while expecing a nil for user model from select by user id query")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err, "failed when check expectation of query")
	})
}

// $go test -v -run "^TestSelectUserByLogin"
func TestSelectUserByLogin(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "not expected error while initializing logger")

	testData, err := models.NewUserModel("mail@mail.ru", "some-strong-password")
	require.NoError(t, err, "failed when init new user model")

	t.Run("success", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err, "not expected error while creating new pgx pool")

		mock.ExpectQuery("SELECT (.+) FROM users").
			WithArgs(&testData.Login).
			WillReturnRows(pgxmock.NewRows([]string{"id", "login", "password", "created_at"}).
				AddRow(testData.Id, testData.Login, testData.PasswordHash, testData.CreatedAt))
		defer mock.Close()

		repo := NewUsersRepository(mock, cfg, lg)
		user, err := repo.SelectUserByLogin(context.Background(), testData.Login)
		assert.NoError(t, err, "failed while selecing user by id, not expecting err for succesfull query")
		assert.NotNil(t, user, "failed while selecting user by id, not expecting user as nil")
		assert.Equal(t, testData.Login, user.Login, "failed when compare logins")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err, "failed when check expectation of query")
	})

	t.Run("some_internal_error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err, "not expected error while creating new pgx pool")

		mock.ExpectQuery("SELECT (.+) FROM users").
			WithArgs(&testData.Login).
			WillReturnError(errors.New("some internal error"))
		defer mock.Close()

		repo := NewUsersRepository(mock, cfg, lg)
		user, err := repo.SelectUserByLogin(context.Background(), testData.Login)
		assert.Error(t, err, "failed while expecing an error from select user by id query")
		assert.NotNil(t, repo.RepositoryError(err), "failed while expecting error type as ErrUserRepository")
		assert.Nil(t, user, "failed while expecing a nil for user model from select by user id query")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err, "failed when check expectation of query")
	})

	t.Run("error_when_result_is_empty", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err, "not expected error while creating new pgx pool")

		mock.ExpectQuery("SELECT (.+) FROM users").
			WithArgs(&testData.Login).
			WillReturnError(pgx.ErrNoRows)
		defer mock.Close()

		repo := NewUsersRepository(mock, cfg, lg)
		user, err := repo.SelectUserByLogin(context.Background(), testData.Login)
		assert.Error(t, err, "failed while expecing an error from select user by id query")
		assert.NotNil(t, repo.NotFoundError(err), "failed while expecting error type as ErrUserRepository")
		assert.Nil(t, user, "failed while expecing a nil for user model from select by user id query")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err, "failed when check expectation of query")
	})
}

// $go test -v -run "^TestUserRepositoryError"
func TestUserRepositoryError(t *testing.T) {

	testError := errors.New("test error")
	testErrorMessage := "some error"

	someError := newErrUserRepository(testErrorMessage, testError)
	assert.NotNil(t, someError, "failed while initializing user repository error")
	assert.ErrorIs(t, someError, testError, "failed while comparing errors")
	assert.NotEmpty(t, someError.Error(), "failed while get error of some error")
}

func Test_UserRepository_Errors(t *testing.T) {
	cfg := &config.Config{}
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while initializing zap logger")

	t.Run("reposiotory_error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err, "failed while initializing pgxmock")
		userRepo := NewUsersRepository(mock, cfg, lg)

		cErr := newErrUserRepository("some error", errors.New("some error"))
		statusErr := userRepo.RepositoryError(cErr)
		assert.Error(t, statusErr, "failed while waiting repository error, got nil instead")
		assert.NotEmpty(t, statusErr.Error(), "failed while waiting repository error, got nil instead")

		sErr := errors.New("some error")
		statusErr = userRepo.RepositoryError(sErr)
		assert.NoError(t, statusErr, "failed while waiting repository error, got %v instead", statusErr)
	})

	t.Run("confilct_reposiotory_error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err, "failed while initializing pgxmock")
		userRepo := NewUsersRepository(mock, cfg, lg)

		cErr := &pgconn.PgError{Code: pgerrcode.UniqueViolation}
		statusErr := userRepo.ConflictError(cErr)
		assert.Error(t, statusErr, "failed while waiting repository error, got nil instead")
		assert.NotEmpty(t, statusErr.Error(), "failed while waiting repository error, got nil instead")

		sErr := errors.New("some error")
		statusErr = userRepo.ConflictError(sErr)
		assert.NoError(t, statusErr, "failed while waiting repository error, got %v instead", statusErr)
	})
}
