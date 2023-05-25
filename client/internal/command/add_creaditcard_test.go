package command

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/Puena/password-keeper/client/config"
	"github.com/Puena/password-keeper/client/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestAddCreditCardCmd(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	type testArgs struct {
		input        []string
		name         string
		newCard      *models.Card
		lockPassword string
	}

	type testExpected struct {
		card         *models.Card
		usecaseError error
	}

	type testData struct {
		name     string
		args     testArgs
		expected testExpected
	}

	data := []testData{
		{
			name: "success",
			args: testArgs{
				input: []string{"sberbank", "-n 1234 5678 9012 3456", "-o some owner", "-e 12/34", "-c 123"},
				name:  "sberbank",
				newCard: &models.Card{
					Number:  "1234 5678 9012 3456",
					Owner:   "some owner",
					Expired: "12/34",
					Cvv:     "123",
				},
				lockPassword: "some-password",
			},
			expected: testExpected{
				card: &models.Card{
					Number:  "1234 5678 9012 3456",
					Owner:   "some owner",
					Expired: "12/34",
					Cvv:     "123",
				},
			},
		},
		{
			name: "usecase_error",
			args: testArgs{
				input: []string{"sberbank", "-n 1234 5678 9012 3456", "-o some owner", "-e 12/34", "-c 123"},
				name:  "sberbank",
				newCard: &models.Card{
					Number:  "1234 5678 9012 3456",
					Owner:   "some owner",
					Expired: "12/34",
					Cvv:     "123",
				},
				lockPassword: "some-password",
			},
			expected: testExpected{
				usecaseError: errors.New("some error"),
				card: &models.Card{
					Number:  "1234 5678 9012 3456",
					Owner:   "some owner",
					Expired: "12/34",
					Cvv:     "123",
				},
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {

			mockUsecase := NewMockAddCreditCardUsecase(t)

			defer func() {
				result := new(bytes.Buffer)
				errors := new(bytes.Buffer)
				in := new(bytes.Buffer)
				in.WriteString(tt.args.lockPassword + "\n")

				cmd := NewAddCreditCardCmd(mockUsecase, cfg, lg)
				cmd.GetCommand().SetOut(result)
				cmd.GetCommand().SetErr(errors)
				cmd.GetCommand().SetIn(in)
				cmd.GetCommand().SetArgs(tt.args.input)
				cmd.ExecuteContext(context.Background())

				if tt.expected.usecaseError != nil {
					assert.True(t, errors.Len() > 0, "failed while expected errors")
					return
				}

				assert.True(t, errors.Len() == 0, "failed while expected no errors")
				assert.True(t, result.Len() > 0, "failed while expected result")
			}()

			mockUsecase.EXPECT().AddCard(mock.Anything, tt.args.name, tt.args.newCard, tt.args.lockPassword).Return(tt.expected.usecaseError)
			if tt.expected.usecaseError != nil {
				mockUsecase.EXPECT().ExtractUserError(tt.expected.usecaseError).Return(tt.expected.usecaseError)
				return
			}
		})
	}
}
