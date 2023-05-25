// Code generated by mockery v2.26.1. DO NOT EDIT.

package command

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// MockDeleteUsecases is an autogenerated mock type for the DeleteUsecases type
type MockDeleteUsecases struct {
	mock.Mock
}

type MockDeleteUsecases_Expecter struct {
	mock *mock.Mock
}

func (_m *MockDeleteUsecases) EXPECT() *MockDeleteUsecases_Expecter {
	return &MockDeleteUsecases_Expecter{mock: &_m.Mock}
}

// DeleteChest provides a mock function with given fields: ctx, name, lockPassword
func (_m *MockDeleteUsecases) DeleteChest(ctx context.Context, name string, lockPassword string) error {
	ret := _m.Called(ctx, name, lockPassword)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, name, lockPassword)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockDeleteUsecases_DeleteChest_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteChest'
type MockDeleteUsecases_DeleteChest_Call struct {
	*mock.Call
}

// DeleteChest is a helper method to define mock.On call
//   - ctx context.Context
//   - name string
//   - lockPassword string
func (_e *MockDeleteUsecases_Expecter) DeleteChest(ctx interface{}, name interface{}, lockPassword interface{}) *MockDeleteUsecases_DeleteChest_Call {
	return &MockDeleteUsecases_DeleteChest_Call{Call: _e.mock.On("DeleteChest", ctx, name, lockPassword)}
}

func (_c *MockDeleteUsecases_DeleteChest_Call) Run(run func(ctx context.Context, name string, lockPassword string)) *MockDeleteUsecases_DeleteChest_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *MockDeleteUsecases_DeleteChest_Call) Return(_a0 error) *MockDeleteUsecases_DeleteChest_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockDeleteUsecases_DeleteChest_Call) RunAndReturn(run func(context.Context, string, string) error) *MockDeleteUsecases_DeleteChest_Call {
	_c.Call.Return(run)
	return _c
}

// ExtractUserError provides a mock function with given fields: err
func (_m *MockDeleteUsecases) ExtractUserError(err error) error {
	ret := _m.Called(err)

	var r0 error
	if rf, ok := ret.Get(0).(func(error) error); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockDeleteUsecases_ExtractUserError_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ExtractUserError'
type MockDeleteUsecases_ExtractUserError_Call struct {
	*mock.Call
}

// ExtractUserError is a helper method to define mock.On call
//   - err error
func (_e *MockDeleteUsecases_Expecter) ExtractUserError(err interface{}) *MockDeleteUsecases_ExtractUserError_Call {
	return &MockDeleteUsecases_ExtractUserError_Call{Call: _e.mock.On("ExtractUserError", err)}
}

func (_c *MockDeleteUsecases_ExtractUserError_Call) Run(run func(err error)) *MockDeleteUsecases_ExtractUserError_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(error))
	})
	return _c
}

func (_c *MockDeleteUsecases_ExtractUserError_Call) Return(_a0 error) *MockDeleteUsecases_ExtractUserError_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockDeleteUsecases_ExtractUserError_Call) RunAndReturn(run func(error) error) *MockDeleteUsecases_ExtractUserError_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewMockDeleteUsecases interface {
	mock.TestingT
	Cleanup(func())
}

// NewMockDeleteUsecases creates a new instance of MockDeleteUsecases. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewMockDeleteUsecases(t mockConstructorTestingTNewMockDeleteUsecases) *MockDeleteUsecases {
	mock := &MockDeleteUsecases{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}