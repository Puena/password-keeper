package command

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/Puena/password-keeper/client/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestGetFileCmd(t *testing.T) {
	cfg, err := config.New()
	require.NoError(t, err, "failed while init config")
	lg, err := zap.NewDevelopment()
	require.NoError(t, err, "failed while init logger")

	type testArgs struct {
		input        []string
		name         string
		lockPassword string
	}

	type testExpected struct {
		file           []byte
		filePath       string
		usecaseError   error
		writeFileError error
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
				input:        []string{"secret-file"},
				name:         "secret-file",
				lockPassword: "some-password",
			},
			expected: testExpected{
				file: []byte("some-file"),
			},
		},
		{
			name: "usecase_error",
			args: testArgs{
				input:        []string{"secret-file"},
				name:         "secret-file",
				lockPassword: "",
			},
			expected: testExpected{
				usecaseError: errors.New("some error"),
				file:         []byte("some-file"),
			},
		},
		{
			name: "write_file_error",
			args: testArgs{
				input:        []string{"secret-file", "-o some-path"},
				name:         "secret-file",
				lockPassword: "",
			},
			expected: testExpected{
				filePath:       "some-path",
				writeFileError: errors.New("some error"),
				file:           []byte("some-file"),
			},
		},
	}

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {

			mockUsecase := NewMockGetFileUsecase(t)

			defer func() {
				result := new(bytes.Buffer)
				errors := new(bytes.Buffer)
				in := new(bytes.Buffer)
				in.WriteString(tt.args.lockPassword + "\n")

				cmd := NewGetFileCmd(mockUsecase, cfg, lg)
				cmd.GetCommand().SetOut(result)
				cmd.GetCommand().SetErr(errors)
				cmd.GetCommand().SetIn(in)
				cmd.GetCommand().SetArgs(tt.args.input)
				cmd.ExecuteContext(context.Background())

				if tt.expected.usecaseError != nil ||
					tt.expected.writeFileError != nil {
					assert.True(t, errors.Len() > 0, "failed while expected errors")
					return
				}

				assert.True(t, errors.Len() == 0, "failed while expected no errors")
				assert.True(t, result.Len() > 0, "failed while expected result")
			}()

			mockUsecase.EXPECT().GetFileByName(mock.Anything, tt.args.name, tt.args.lockPassword).Return(tt.expected.file, tt.expected.usecaseError)
			if tt.expected.usecaseError != nil {
				mockUsecase.EXPECT().ExtractUserError(tt.expected.usecaseError).Return(tt.expected.usecaseError)
				return
			}

			if tt.expected.filePath != "" {
				mockUsecase.EXPECT().WriteFile(mock.Anything, tt.expected.filePath, tt.expected.file).Return(tt.expected.writeFileError)
				if tt.expected.writeFileError != nil {
					mockUsecase.EXPECT().ExtractUserError(tt.expected.writeFileError).Return(tt.expected.writeFileError)
					return
				}
			}
		})
	}
}
