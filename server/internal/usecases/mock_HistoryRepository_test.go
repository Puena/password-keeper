// Code generated by mockery v2.26.1. DO NOT EDIT.

package usecases

import (
	context "context"

	models "github.com/Puena/password-keeper/server/internal/models"
	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// MockHistoryRepository is an autogenerated mock type for the HistoryRepository type
type MockHistoryRepository struct {
	mock.Mock
}

type MockHistoryRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *MockHistoryRepository) EXPECT() *MockHistoryRepository_Expecter {
	return &MockHistoryRepository_Expecter{mock: &_m.Mock}
}

// NotFoundError provides a mock function with given fields: err
func (_m *MockHistoryRepository) NotFoundError(err error) error {
	ret := _m.Called(err)

	var r0 error
	if rf, ok := ret.Get(0).(func(error) error); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockHistoryRepository_NotFoundError_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'NotFoundError'
type MockHistoryRepository_NotFoundError_Call struct {
	*mock.Call
}

// NotFoundError is a helper method to define mock.On call
//   - err error
func (_e *MockHistoryRepository_Expecter) NotFoundError(err interface{}) *MockHistoryRepository_NotFoundError_Call {
	return &MockHistoryRepository_NotFoundError_Call{Call: _e.mock.On("NotFoundError", err)}
}

func (_c *MockHistoryRepository_NotFoundError_Call) Run(run func(err error)) *MockHistoryRepository_NotFoundError_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(error))
	})
	return _c
}

func (_c *MockHistoryRepository_NotFoundError_Call) Return(_a0 error) *MockHistoryRepository_NotFoundError_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockHistoryRepository_NotFoundError_Call) RunAndReturn(run func(error) error) *MockHistoryRepository_NotFoundError_Call {
	_c.Call.Return(run)
	return _c
}

// RepositoryError provides a mock function with given fields: err
func (_m *MockHistoryRepository) RepositoryError(err error) error {
	ret := _m.Called(err)

	var r0 error
	if rf, ok := ret.Get(0).(func(error) error); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockHistoryRepository_RepositoryError_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RepositoryError'
type MockHistoryRepository_RepositoryError_Call struct {
	*mock.Call
}

// RepositoryError is a helper method to define mock.On call
//   - err error
func (_e *MockHistoryRepository_Expecter) RepositoryError(err interface{}) *MockHistoryRepository_RepositoryError_Call {
	return &MockHistoryRepository_RepositoryError_Call{Call: _e.mock.On("RepositoryError", err)}
}

func (_c *MockHistoryRepository_RepositoryError_Call) Run(run func(err error)) *MockHistoryRepository_RepositoryError_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(error))
	})
	return _c
}

func (_c *MockHistoryRepository_RepositoryError_Call) Return(_a0 error) *MockHistoryRepository_RepositoryError_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockHistoryRepository_RepositoryError_Call) RunAndReturn(run func(error) error) *MockHistoryRepository_RepositoryError_Call {
	_c.Call.Return(run)
	return _c
}

// SelectUserChestsLastHistory provides a mock function with given fields: ctx, userID
func (_m *MockHistoryRepository) SelectUserChestsLastHistory(ctx context.Context, userID uuid.UUID) ([]*models.History, error) {
	ret := _m.Called(ctx, userID)

	var r0 []*models.History
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) ([]*models.History, error)); ok {
		return rf(ctx, userID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) []*models.History); ok {
		r0 = rf(ctx, userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*models.History)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID) error); ok {
		r1 = rf(ctx, userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockHistoryRepository_SelectUserChestsLastHistory_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SelectUserChestsLastHistory'
type MockHistoryRepository_SelectUserChestsLastHistory_Call struct {
	*mock.Call
}

// SelectUserChestsLastHistory is a helper method to define mock.On call
//   - ctx context.Context
//   - userID uuid.UUID
func (_e *MockHistoryRepository_Expecter) SelectUserChestsLastHistory(ctx interface{}, userID interface{}) *MockHistoryRepository_SelectUserChestsLastHistory_Call {
	return &MockHistoryRepository_SelectUserChestsLastHistory_Call{Call: _e.mock.On("SelectUserChestsLastHistory", ctx, userID)}
}

func (_c *MockHistoryRepository_SelectUserChestsLastHistory_Call) Run(run func(ctx context.Context, userID uuid.UUID)) *MockHistoryRepository_SelectUserChestsLastHistory_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *MockHistoryRepository_SelectUserChestsLastHistory_Call) Return(_a0 []*models.History, _a1 error) *MockHistoryRepository_SelectUserChestsLastHistory_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockHistoryRepository_SelectUserChestsLastHistory_Call) RunAndReturn(run func(context.Context, uuid.UUID) ([]*models.History, error)) *MockHistoryRepository_SelectUserChestsLastHistory_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewMockHistoryRepository interface {
	mock.TestingT
	Cleanup(func())
}

// NewMockHistoryRepository creates a new instance of MockHistoryRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewMockHistoryRepository(t mockConstructorTestingTNewMockHistoryRepository) *MockHistoryRepository {
	mock := &MockHistoryRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
