package usecases

import (
	"errors"
	"fmt"
)

type errKeeperUseCasesType int

const (
	errKeeperUseCasesConflict errKeeperUseCasesType = iota
	errKeeperUseCasesNotFound
	errKeeperUseCasesInternal
	errKeeperUseCasesAuthentification
	errKeeperUseCasesValidation
)

// errKeeperUseCases represents keeper use cases errors.
type errKeeperUseCases struct {
	message string
	errType errKeeperUseCasesType
	err     error
}

// Error implements Error interface.
func (e *errKeeperUseCases) Error() string {
	return fmt.Sprintf("keeper usecases error: %s %s", e.message, e.err)
}

// Unwrap implements Unwrap intraface.
func (e *errKeeperUseCases) Unwrap() error {
	return e.err
}

// newErrKeeperUseCases create new [ErrKeeperUseCases] error.
func newErrKeeperUseCases(message string, errType errKeeperUseCasesType, err error) error {
	return &errKeeperUseCases{
		message: message,
		errType: errType,
		err:     err,
	}
}

func (u *keeperUseCases) ValidationError(err error) bool {
	var kucerr *errKeeperUseCases
	if errors.As(err, &kucerr) {
		return errKeeperUseCasesValidation == kucerr.errType
	}
	return false
}

func (u *keeperUseCases) NotFoundError(err error) bool {
	var kucerr *errKeeperUseCases
	if errors.As(err, &kucerr) {
		return errKeeperUseCasesNotFound == kucerr.errType
	}
	return false
}

func (u *keeperUseCases) InternalError(err error) bool {
	var kucerr *errKeeperUseCases
	if errors.As(err, &kucerr) {
		return errKeeperUseCasesInternal == kucerr.errType
	}
	return false
}

func (u *keeperUseCases) AuthentificationError(err error) bool {
	var kucerr *errKeeperUseCases
	if errors.As(err, &kucerr) {
		return errKeeperUseCasesAuthentification == kucerr.errType
	}
	return false
}

func (u *keeperUseCases) ConflictError(err error) bool {
	var kucerr *errKeeperUseCases
	if errors.As(err, &kucerr) {
		return errKeeperUseCasesConflict == kucerr.errType
	}
	return false
}

func (u *keeperUseCases) ExtractUserErrorMessage(err error) string {
	var kucerr *errKeeperUseCases
	if errors.As(err, &kucerr) {
		return kucerr.message
	}
	return err.Error()

}
