// Code generated by mockery v2.26.1. DO NOT EDIT.

package command

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// MockAddPasswordUsecase is an autogenerated mock type for the AddPasswordUsecase type
type MockAddPasswordUsecase struct {
	mock.Mock
}

type MockAddPasswordUsecase_Expecter struct {
	mock *mock.Mock
}

func (_m *MockAddPasswordUsecase) EXPECT() *MockAddPasswordUsecase_Expecter {
	return &MockAddPasswordUsecase_Expecter{mock: &_m.Mock}
}

// AddPassword provides a mock function with given fields: ctx, name, passowrd, lockPassword
func (_m *MockAddPasswordUsecase) AddPassword(ctx context.Context, name string, passowrd string, lockPassword string) error {
	ret := _m.Called(ctx, name, passowrd, lockPassword)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) error); ok {
		r0 = rf(ctx, name, passowrd, lockPassword)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockAddPasswordUsecase_AddPassword_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddPassword'
type MockAddPasswordUsecase_AddPassword_Call struct {
	*mock.Call
}

// AddPassword is a helper method to define mock.On call
//   - ctx context.Context
//   - name string
//   - passowrd string
//   - lockPassword string
func (_e *MockAddPasswordUsecase_Expecter) AddPassword(ctx interface{}, name interface{}, passowrd interface{}, lockPassword interface{}) *MockAddPasswordUsecase_AddPassword_Call {
	return &MockAddPasswordUsecase_AddPassword_Call{Call: _e.mock.On("AddPassword", ctx, name, passowrd, lockPassword)}
}

func (_c *MockAddPasswordUsecase_AddPassword_Call) Run(run func(ctx context.Context, name string, passowrd string, lockPassword string)) *MockAddPasswordUsecase_AddPassword_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(string))
	})
	return _c
}

func (_c *MockAddPasswordUsecase_AddPassword_Call) Return(_a0 error) *MockAddPasswordUsecase_AddPassword_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockAddPasswordUsecase_AddPassword_Call) RunAndReturn(run func(context.Context, string, string, string) error) *MockAddPasswordUsecase_AddPassword_Call {
	_c.Call.Return(run)
	return _c
}

// ExtractUserError provides a mock function with given fields: err
func (_m *MockAddPasswordUsecase) ExtractUserError(err error) error {
	ret := _m.Called(err)

	var r0 error
	if rf, ok := ret.Get(0).(func(error) error); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockAddPasswordUsecase_ExtractUserError_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ExtractUserError'
type MockAddPasswordUsecase_ExtractUserError_Call struct {
	*mock.Call
}

// ExtractUserError is a helper method to define mock.On call
//   - err error
func (_e *MockAddPasswordUsecase_Expecter) ExtractUserError(err interface{}) *MockAddPasswordUsecase_ExtractUserError_Call {
	return &MockAddPasswordUsecase_ExtractUserError_Call{Call: _e.mock.On("ExtractUserError", err)}
}

func (_c *MockAddPasswordUsecase_ExtractUserError_Call) Run(run func(err error)) *MockAddPasswordUsecase_ExtractUserError_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(error))
	})
	return _c
}

func (_c *MockAddPasswordUsecase_ExtractUserError_Call) Return(_a0 error) *MockAddPasswordUsecase_ExtractUserError_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockAddPasswordUsecase_ExtractUserError_Call) RunAndReturn(run func(error) error) *MockAddPasswordUsecase_ExtractUserError_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewMockAddPasswordUsecase interface {
	mock.TestingT
	Cleanup(func())
}

// NewMockAddPasswordUsecase creates a new instance of MockAddPasswordUsecase. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewMockAddPasswordUsecase(t mockConstructorTestingTNewMockAddPasswordUsecase) *MockAddPasswordUsecase {
	mock := &MockAddPasswordUsecase{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}