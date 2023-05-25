// Code generated by mockery v2.26.1. DO NOT EDIT.

package command

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// MockAuthentificateUsecase is an autogenerated mock type for the AuthentificateUsecase type
type MockAuthentificateUsecase struct {
	mock.Mock
}

type MockAuthentificateUsecase_Expecter struct {
	mock *mock.Mock
}

func (_m *MockAuthentificateUsecase) EXPECT() *MockAuthentificateUsecase_Expecter {
	return &MockAuthentificateUsecase_Expecter{mock: &_m.Mock}
}

// Authentification provides a mock function with given fields: ctx, login, password
func (_m *MockAuthentificateUsecase) Authentification(ctx context.Context, login string, password string) error {
	ret := _m.Called(ctx, login, password)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, login, password)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockAuthentificateUsecase_Authentification_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Authentification'
type MockAuthentificateUsecase_Authentification_Call struct {
	*mock.Call
}

// Authentification is a helper method to define mock.On call
//   - ctx context.Context
//   - login string
//   - password string
func (_e *MockAuthentificateUsecase_Expecter) Authentification(ctx interface{}, login interface{}, password interface{}) *MockAuthentificateUsecase_Authentification_Call {
	return &MockAuthentificateUsecase_Authentification_Call{Call: _e.mock.On("Authentification", ctx, login, password)}
}

func (_c *MockAuthentificateUsecase_Authentification_Call) Run(run func(ctx context.Context, login string, password string)) *MockAuthentificateUsecase_Authentification_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *MockAuthentificateUsecase_Authentification_Call) Return(_a0 error) *MockAuthentificateUsecase_Authentification_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockAuthentificateUsecase_Authentification_Call) RunAndReturn(run func(context.Context, string, string) error) *MockAuthentificateUsecase_Authentification_Call {
	_c.Call.Return(run)
	return _c
}

// ExtractUserError provides a mock function with given fields: err
func (_m *MockAuthentificateUsecase) ExtractUserError(err error) error {
	ret := _m.Called(err)

	var r0 error
	if rf, ok := ret.Get(0).(func(error) error); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockAuthentificateUsecase_ExtractUserError_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ExtractUserError'
type MockAuthentificateUsecase_ExtractUserError_Call struct {
	*mock.Call
}

// ExtractUserError is a helper method to define mock.On call
//   - err error
func (_e *MockAuthentificateUsecase_Expecter) ExtractUserError(err interface{}) *MockAuthentificateUsecase_ExtractUserError_Call {
	return &MockAuthentificateUsecase_ExtractUserError_Call{Call: _e.mock.On("ExtractUserError", err)}
}

func (_c *MockAuthentificateUsecase_ExtractUserError_Call) Run(run func(err error)) *MockAuthentificateUsecase_ExtractUserError_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(error))
	})
	return _c
}

func (_c *MockAuthentificateUsecase_ExtractUserError_Call) Return(_a0 error) *MockAuthentificateUsecase_ExtractUserError_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockAuthentificateUsecase_ExtractUserError_Call) RunAndReturn(run func(error) error) *MockAuthentificateUsecase_ExtractUserError_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewMockAuthentificateUsecase interface {
	mock.TestingT
	Cleanup(func())
}

// NewMockAuthentificateUsecase creates a new instance of MockAuthentificateUsecase. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewMockAuthentificateUsecase(t mockConstructorTestingTNewMockAuthentificateUsecase) *MockAuthentificateUsecase {
	mock := &MockAuthentificateUsecase{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
