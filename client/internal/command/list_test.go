package command

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestListCmd(t *testing.T) {

	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	type testArgs struct {
		input []string
	}

	type testExpected struct {
		result            []*models.Chest
		usecaseError      error
		passwordFlagError error
		cardFlagError     error
		fileFlagError     error
	}

	type testData struct {
		name     string
		args     testArgs
		expected testExpected
	}

	data := []testData{
		{
			name: "success list all items",
			args: testArgs{
				input: []string{},
			},
			expected: testExpected{
				result: []*models.Chest{
					{
						ID:       uuid.NewString(),
						UserID:   nil,
						Salt:     sha256.New().Sum([]byte("some-salt")),
						Name:     "yandex.disk",
						Data:     []byte("some-password"),
						DataType: models.ChestPasswordData,
					},
					{
						ID:       uuid.NewString(),
						UserID:   nil,
						Salt:     sha256.New().Sum([]byte("some-salt")),
						Name:     "yandex.card",
						Data:     []byte("some-card"),
						DataType: models.ChestCreditCardData,
					},
					{
						ID:       uuid.NewString(),
						UserID:   nil,
						Salt:     sha256.New().Sum([]byte("some-salt")),
						Name:     "yandex.card",
						Data:     []byte("some-file"),
						DataType: models.ChestFileData,
					},
				},
			},
		},
		{
			name: "success list with filters",
			args: testArgs{
				input: []string{"-p", "-c", "-f"},
			},
			expected: testExpected{
				result: []*models.Chest{
					{
						ID:       uuid.NewString(),
						UserID:   nil,
						Salt:     sha256.New().Sum([]byte("some-salt")),
						Name:     "yandex.disk",
						Data:     []byte("some-password"),
						DataType: models.ChestPasswordData,
					},
					{
						ID:       uuid.NewString(),
						UserID:   nil,
						Salt:     sha256.New().Sum([]byte("some-salt")),
						Name:     "yandex.card",
						Data:     []byte("some-card"),
						DataType: models.ChestCreditCardData,
					},
					{
						ID:       uuid.NewString(),
						UserID:   nil,
						Salt:     sha256.New().Sum([]byte("some-salt")),
						Name:     "yandex.card",
						Data:     []byte("some-file"),
						DataType: models.ChestFileData,
					},
				},
			},
		},
		{
			name: "usecase error",
			args: testArgs{
				input: []string{},
			},
			expected: testExpected{
				usecaseError: errors.New("some-error"),
				result: []*models.Chest{
					{
						ID:       uuid.NewString(),
						UserID:   nil,
						Salt:     sha256.New().Sum([]byte("some-salt")),
						Name:     "yandex.disk",
						Data:     []byte("some-password"),
						DataType: models.ChestPasswordData,
					},
					{
						ID:       uuid.NewString(),
						UserID:   nil,
						Salt:     sha256.New().Sum([]byte("some-salt")),
						Name:     "yandex.card",
						Data:     []byte("some-card"),
						DataType: models.ChestCreditCardData,
					},
					{
						ID:       uuid.NewString(),
						UserID:   nil,
						Salt:     sha256.New().Sum([]byte("some-salt")),
						Name:     "yandex.card",
						Data:     []byte("some-file"),
						DataType: models.ChestFileData,
					},
				},
			},
		},
	}

	for _, tt := range data {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			listMock := NewMockListUsecases(t)
			result := new(bytes.Buffer)
			errors := new(bytes.Buffer)

			defer func() {
				cmd := NewListCmd(listMock, cfg, lg)
				cmd.GetCommand().SetOut(result)
				cmd.GetCommand().SetErr(errors)
				cmd.GetCommand().SetArgs(tt.args.input)
				cmd.baseCommand.GetCommand().SetOut(result)
				cmd.baseCommand.GetCommand().SetErr(errors)

				cmd.ExecuteContext(context.Background())
				fmt.Println(tt.expected.usecaseError)
				if tt.expected.usecaseError != nil ||
					tt.expected.passwordFlagError != nil ||
					tt.expected.cardFlagError != nil ||
					tt.expected.fileFlagError != nil {
					fmt.Println("asdfasdfasdlasdfasdfasdfasdfasdffasdfa")
					assert.True(t, errors.Len() > 0, "failed while expecting error")
					return
				}

				assert.True(t, errors.Len() == 0, "failed while expecting result but got error")
				assert.True(t, result.Len() > 0, "failed while expecting result")
			}()

			listMock.EXPECT().GetAllChests(mock.Anything).Return(tt.expected.result, tt.expected.usecaseError)
			if tt.expected.usecaseError != nil {
				listMock.EXPECT().ExtractUserError(tt.expected.usecaseError).Return(tt.expected.usecaseError)
				return
			}

		})
	}
}
