// Code generated by mockery v2.26.1. DO NOT EDIT.

package command

import (
	context "context"

	models "github.com/Puena/password-keeper/client/internal/models"
	mock "github.com/stretchr/testify/mock"
)

// MockListUsecases is an autogenerated mock type for the ListUsecases type
type MockListUsecases struct {
	mock.Mock
}

type MockListUsecases_Expecter struct {
	mock *mock.Mock
}

func (_m *MockListUsecases) EXPECT() *MockListUsecases_Expecter {
	return &MockListUsecases_Expecter{mock: &_m.Mock}
}

// ExtractUserError provides a mock function with given fields: err
func (_m *MockListUsecases) ExtractUserError(err error) error {
	ret := _m.Called(err)

	var r0 error
	if rf, ok := ret.Get(0).(func(error) error); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockListUsecases_ExtractUserError_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ExtractUserError'
type MockListUsecases_ExtractUserError_Call struct {
	*mock.Call
}

// ExtractUserError is a helper method to define mock.On call
//   - err error
func (_e *MockListUsecases_Expecter) ExtractUserError(err interface{}) *MockListUsecases_ExtractUserError_Call {
	return &MockListUsecases_ExtractUserError_Call{Call: _e.mock.On("ExtractUserError", err)}
}

func (_c *MockListUsecases_ExtractUserError_Call) Run(run func(err error)) *MockListUsecases_ExtractUserError_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(error))
	})
	return _c
}

func (_c *MockListUsecases_ExtractUserError_Call) Return(_a0 error) *MockListUsecases_ExtractUserError_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockListUsecases_ExtractUserError_Call) RunAndReturn(run func(error) error) *MockListUsecases_ExtractUserError_Call {
	_c.Call.Return(run)
	return _c
}

// GetAllChests provides a mock function with given fields: ctx
func (_m *MockListUsecases) GetAllChests(ctx context.Context) ([]*models.Chest, error) {
	ret := _m.Called(ctx)

	var r0 []*models.Chest
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) ([]*models.Chest, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) []*models.Chest); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*models.Chest)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockListUsecases_GetAllChests_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAllChests'
type MockListUsecases_GetAllChests_Call struct {
	*mock.Call
}

// GetAllChests is a helper method to define mock.On call
//   - ctx context.Context
func (_e *MockListUsecases_Expecter) GetAllChests(ctx interface{}) *MockListUsecases_GetAllChests_Call {
	return &MockListUsecases_GetAllChests_Call{Call: _e.mock.On("GetAllChests", ctx)}
}

func (_c *MockListUsecases_GetAllChests_Call) Run(run func(ctx context.Context)) *MockListUsecases_GetAllChests_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *MockListUsecases_GetAllChests_Call) Return(chest []*models.Chest, err error) *MockListUsecases_GetAllChests_Call {
	_c.Call.Return(chest, err)
	return _c
}

func (_c *MockListUsecases_GetAllChests_Call) RunAndReturn(run func(context.Context) ([]*models.Chest, error)) *MockListUsecases_GetAllChests_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewMockListUsecases interface {
	mock.TestingT
	Cleanup(func())
}

// NewMockListUsecases creates a new instance of MockListUsecases. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewMockListUsecases(t mockConstructorTestingTNewMockListUsecases) *MockListUsecases {
	mock := &MockListUsecases{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
