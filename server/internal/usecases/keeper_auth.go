package usecases

import (
	"context"
	"errors"

	"github.com/Puena/password-keeper/server/internal/dto"
	"github.com/Puena/password-keeper/server/internal/models"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type UserIDContextType string

const UserIDContextKey UserIDContextType = "ctx-user-id"

var ErrUsecasesAuthIDExtraction = errors.New("couldn't extract user id from context")

// SignUp creates a new user with the given authentification data.
// Login should be a valid email and password should be at least 8 characters long.
// It returns a token that can be used to authenticate the user in the future.
func (uc *keeperUseCases) SignUp(ctx context.Context, data dto.AuthDataDto) (*dto.AuthTokenDto, error) {

	err := validation.Struct(&data)
	if err != nil {
		verr, ok := err.(validator.ValidationErrors)
		if ok {
			for _, e := range verr {
				e := e
				if e.Field() == "Login" && e.Tag() == "email" {
					return nil, newErrKeeperUseCases("login should be valied email", errKeeperUseCasesValidation, err)
				}
				if e.Field() == "Password" && e.Tag() == "gte" {
					return nil, newErrKeeperUseCases("password should be at least 8 characters long", errKeeperUseCasesValidation, err)
				}
				if e.Field() == "Password" && e.Tag() == "lte" {
					return nil, newErrKeeperUseCases("password should be at most 24 characters long", errKeeperUseCasesValidation, err)
				}

			}
		}
		return nil, newErrKeeperUseCases("bad auth data", errKeeperUseCasesValidation, err)
	}

	newUser, err := models.NewUserModel(data.Login, data.Password)
	if err != nil {
		return nil, newErrKeeperUseCases("internal error when encrypting password", errKeeperUseCasesInternal, err)
	}

	// check that login is unique
	_, err = uc.usersRepository.SelectUserByLogin(ctx, data.Login)
	if err == nil {
		return nil, newErrKeeperUseCases("user with this authentification data already exists", errKeeperUseCasesConflict, errors.New("user already exists"))
	}
	if err != nil && uc.usersRepository.NotFoundError(err) == nil {
		return nil, newErrKeeperUseCases("inernal error while selecting user by login", errKeeperUseCasesInternal, err)
	}

	res, err := uc.usersRepository.InsertUser(ctx, newUser)
	if err != nil {
		if uc.usersRepository.ConflictError(err) == nil {
			return nil, newErrKeeperUseCases("user with this authentification data already exists", errKeeperUseCasesConflict, err)
		}
		return nil, newErrKeeperUseCases("inernal error while inserting user", errKeeperUseCasesInternal, err)
	}

	jwtToken, err := uc.tokenRepository.GenerateToken(ctx, *res)
	if err != nil {
		return nil, newErrKeeperUseCases("inernal error while generating auth token", errKeeperUseCasesInternal, err)
	}

	return &dto.AuthTokenDto{
		Token: jwtToken,
	}, nil
}

// SignIn checks if the given authentification data is valid and returns a token if it is.
func (uc *keeperUseCases) SignIn(ctx context.Context, data dto.AuthDataDto) (*dto.AuthTokenDto, error) {

	err := validation.Struct(&data)
	if err != nil {
		return nil, newErrKeeperUseCases("bad authentification data", errKeeperUseCasesValidation, err)
	}

	user, err := uc.usersRepository.SelectUserByLogin(ctx, data.Login)
	if err != nil {
		if uc.usersRepository.NotFoundError(err) != nil {
			return nil, newErrKeeperUseCases("user with this authentification data doesn't exist", errKeeperUseCasesNotFound, err)
		}
		return nil, newErrKeeperUseCases("inernal error while selecting user by login", errKeeperUseCasesInternal, err)
	}

	err = user.ValidatePassword(data.Password)
	if err != nil {
		return nil, newErrKeeperUseCases("bad user authentification data", errKeeperUseCasesValidation, err)
	}

	jwtToken, err := uc.tokenRepository.GenerateToken(ctx, user.Id)
	if err != nil {
		return nil, newErrKeeperUseCases("internal error while generate auth token", errKeeperUseCasesInternal, err)
	}

	return &dto.AuthTokenDto{
		Token: jwtToken,
	}, nil
}

// Auth checks if the given token is valid and returns the user id if it is.
func (uc *keeperUseCases) Auth(ctx context.Context, token string) (*uuid.UUID, error) {
	uid, err := uc.tokenRepository.ValidateToken(ctx, token)
	if err != nil {
		return nil, newErrKeeperUseCases("bad authentification data", errKeeperUseCasesValidation, err)
	}

	return uid, nil
}
