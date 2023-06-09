// Code generated by mockery v2.26.1. DO NOT EDIT.

package mocks

import (
	context "context"

	dto "github.com/Puena/password-keeper/server/internal/dto"
	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// KeeperUseCases is an autogenerated mock type for the KeeperUseCases type
type KeeperUseCases struct {
	mock.Mock
}

// AddChest provides a mock function with given fields: ctx, chest, history
func (_m *KeeperUseCases) AddChest(ctx context.Context, chest *dto.Chest, history *dto.History) (*dto.History, error) {
	ret := _m.Called(ctx, chest, history)

	var r0 *dto.History
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *dto.Chest, *dto.History) (*dto.History, error)); ok {
		return rf(ctx, chest, history)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *dto.Chest, *dto.History) *dto.History); ok {
		r0 = rf(ctx, chest, history)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*dto.History)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *dto.Chest, *dto.History) error); ok {
		r1 = rf(ctx, chest, history)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Auth provides a mock function with given fields: ctx, token
func (_m *KeeperUseCases) Auth(ctx context.Context, token string) (*uuid.UUID, error) {
	ret := _m.Called(ctx, token)

	var r0 *uuid.UUID
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*uuid.UUID, error)); ok {
		return rf(ctx, token)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *uuid.UUID); ok {
		r0 = rf(ctx, token)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*uuid.UUID)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AuthentificationError provides a mock function with given fields: err
func (_m *KeeperUseCases) AuthentificationError(err error) bool {
	ret := _m.Called(err)

	var r0 bool
	if rf, ok := ret.Get(0).(func(error) bool); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// ConflictError provides a mock function with given fields: err
func (_m *KeeperUseCases) ConflictError(err error) bool {
	ret := _m.Called(err)

	var r0 bool
	if rf, ok := ret.Get(0).(func(error) bool); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// DeleteChest provides a mock function with given fields: ctx, history
func (_m *KeeperUseCases) DeleteChest(ctx context.Context, history *dto.History) (*dto.History, error) {
	ret := _m.Called(ctx, history)

	var r0 *dto.History
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *dto.History) (*dto.History, error)); ok {
		return rf(ctx, history)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *dto.History) *dto.History); ok {
		r0 = rf(ctx, history)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*dto.History)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *dto.History) error); ok {
		r1 = rf(ctx, history)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ExtractUserErrorMessage provides a mock function with given fields: err
func (_m *KeeperUseCases) ExtractUserErrorMessage(err error) string {
	ret := _m.Called(err)

	var r0 string
	if rf, ok := ret.Get(0).(func(error) string); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// GetChestByID provides a mock function with given fields: ctx, chestID, userID
func (_m *KeeperUseCases) GetChestByID(ctx context.Context, chestID string, userID uuid.UUID) (*dto.Chest, *dto.History, error) {
	ret := _m.Called(ctx, chestID, userID)

	var r0 *dto.Chest
	var r1 *dto.History
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, uuid.UUID) (*dto.Chest, *dto.History, error)); ok {
		return rf(ctx, chestID, userID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, uuid.UUID) *dto.Chest); ok {
		r0 = rf(ctx, chestID, userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*dto.Chest)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, uuid.UUID) *dto.History); ok {
		r1 = rf(ctx, chestID, userID)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*dto.History)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, uuid.UUID) error); ok {
		r2 = rf(ctx, chestID, userID)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// InternalError provides a mock function with given fields: err
func (_m *KeeperUseCases) InternalError(err error) bool {
	ret := _m.Called(err)

	var r0 bool
	if rf, ok := ret.Get(0).(func(error) bool); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// NotFoundError provides a mock function with given fields: err
func (_m *KeeperUseCases) NotFoundError(err error) bool {
	ret := _m.Called(err)

	var r0 bool
	if rf, ok := ret.Get(0).(func(error) bool); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// SignIn provides a mock function with given fields: ctx, data
func (_m *KeeperUseCases) SignIn(ctx context.Context, data dto.AuthDataDto) (*dto.AuthTokenDto, error) {
	ret := _m.Called(ctx, data)

	var r0 *dto.AuthTokenDto
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, dto.AuthDataDto) (*dto.AuthTokenDto, error)); ok {
		return rf(ctx, data)
	}
	if rf, ok := ret.Get(0).(func(context.Context, dto.AuthDataDto) *dto.AuthTokenDto); ok {
		r0 = rf(ctx, data)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*dto.AuthTokenDto)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, dto.AuthDataDto) error); ok {
		r1 = rf(ctx, data)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SignUp provides a mock function with given fields: ctx, data
func (_m *KeeperUseCases) SignUp(ctx context.Context, data dto.AuthDataDto) (*dto.AuthTokenDto, error) {
	ret := _m.Called(ctx, data)

	var r0 *dto.AuthTokenDto
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, dto.AuthDataDto) (*dto.AuthTokenDto, error)); ok {
		return rf(ctx, data)
	}
	if rf, ok := ret.Get(0).(func(context.Context, dto.AuthDataDto) *dto.AuthTokenDto); ok {
		r0 = rf(ctx, data)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*dto.AuthTokenDto)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, dto.AuthDataDto) error); ok {
		r1 = rf(ctx, data)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Sync provides a mock function with given fields: ctx, history, userID
func (_m *KeeperUseCases) Sync(ctx context.Context, history []*dto.History, userID uuid.UUID) ([]*dto.History, error) {
	ret := _m.Called(ctx, history, userID)

	var r0 []*dto.History
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, []*dto.History, uuid.UUID) ([]*dto.History, error)); ok {
		return rf(ctx, history, userID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []*dto.History, uuid.UUID) []*dto.History); ok {
		r0 = rf(ctx, history, userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*dto.History)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []*dto.History, uuid.UUID) error); ok {
		r1 = rf(ctx, history, userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpsertChest provides a mock function with given fields: ctx, chest, history
func (_m *KeeperUseCases) UpsertChest(ctx context.Context, chest *dto.Chest, history *dto.History) (*dto.History, error) {
	ret := _m.Called(ctx, chest, history)

	var r0 *dto.History
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *dto.Chest, *dto.History) (*dto.History, error)); ok {
		return rf(ctx, chest, history)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *dto.Chest, *dto.History) *dto.History); ok {
		r0 = rf(ctx, chest, history)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*dto.History)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *dto.Chest, *dto.History) error); ok {
		r1 = rf(ctx, chest, history)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ValidationError provides a mock function with given fields: err
func (_m *KeeperUseCases) ValidationError(err error) bool {
	ret := _m.Called(err)

	var r0 bool
	if rf, ok := ret.Get(0).(func(error) bool); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

type mockConstructorTestingTNewKeeperUseCases interface {
	mock.TestingT
	Cleanup(func())
}

// NewKeeperUseCases creates a new instance of KeeperUseCases. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewKeeperUseCases(t mockConstructorTestingTNewKeeperUseCases) *KeeperUseCases {
	mock := &KeeperUseCases{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
