// Code generated by mockery v2.26.1. DO NOT EDIT.

package command

import (
	context "context"

	models "github.com/Puena/password-keeper/client/internal/models"
	mock "github.com/stretchr/testify/mock"
)

// MockGetCreditCardUsecase is an autogenerated mock type for the GetCreditCardUsecase type
type MockGetCreditCardUsecase struct {
	mock.Mock
}

type MockGetCreditCardUsecase_Expecter struct {
	mock *mock.Mock
}

func (_m *MockGetCreditCardUsecase) EXPECT() *MockGetCreditCardUsecase_Expecter {
	return &MockGetCreditCardUsecase_Expecter{mock: &_m.Mock}
}

// ExtractUserError provides a mock function with given fields: err
func (_m *MockGetCreditCardUsecase) ExtractUserError(err error) error {
	ret := _m.Called(err)

	var r0 error
	if rf, ok := ret.Get(0).(func(error) error); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockGetCreditCardUsecase_ExtractUserError_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ExtractUserError'
type MockGetCreditCardUsecase_ExtractUserError_Call struct {
	*mock.Call
}

// ExtractUserError is a helper method to define mock.On call
//   - err error
func (_e *MockGetCreditCardUsecase_Expecter) ExtractUserError(err interface{}) *MockGetCreditCardUsecase_ExtractUserError_Call {
	return &MockGetCreditCardUsecase_ExtractUserError_Call{Call: _e.mock.On("ExtractUserError", err)}
}

func (_c *MockGetCreditCardUsecase_ExtractUserError_Call) Run(run func(err error)) *MockGetCreditCardUsecase_ExtractUserError_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(error))
	})
	return _c
}

func (_c *MockGetCreditCardUsecase_ExtractUserError_Call) Return(_a0 error) *MockGetCreditCardUsecase_ExtractUserError_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockGetCreditCardUsecase_ExtractUserError_Call) RunAndReturn(run func(error) error) *MockGetCreditCardUsecase_ExtractUserError_Call {
	_c.Call.Return(run)
	return _c
}

// GetCardByName provides a mock function with given fields: ctx, name, lockPassword
func (_m *MockGetCreditCardUsecase) GetCardByName(ctx context.Context, name string, lockPassword string) (*models.Card, error) {
	ret := _m.Called(ctx, name, lockPassword)

	var r0 *models.Card
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (*models.Card, error)); ok {
		return rf(ctx, name, lockPassword)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *models.Card); ok {
		r0 = rf(ctx, name, lockPassword)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*models.Card)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, name, lockPassword)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockGetCreditCardUsecase_GetCardByName_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetCardByName'
type MockGetCreditCardUsecase_GetCardByName_Call struct {
	*mock.Call
}

// GetCardByName is a helper method to define mock.On call
//   - ctx context.Context
//   - name string
//   - lockPassword string
func (_e *MockGetCreditCardUsecase_Expecter) GetCardByName(ctx interface{}, name interface{}, lockPassword interface{}) *MockGetCreditCardUsecase_GetCardByName_Call {
	return &MockGetCreditCardUsecase_GetCardByName_Call{Call: _e.mock.On("GetCardByName", ctx, name, lockPassword)}
}

func (_c *MockGetCreditCardUsecase_GetCardByName_Call) Run(run func(ctx context.Context, name string, lockPassword string)) *MockGetCreditCardUsecase_GetCardByName_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *MockGetCreditCardUsecase_GetCardByName_Call) Return(_a0 *models.Card, _a1 error) *MockGetCreditCardUsecase_GetCardByName_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockGetCreditCardUsecase_GetCardByName_Call) RunAndReturn(run func(context.Context, string, string) (*models.Card, error)) *MockGetCreditCardUsecase_GetCardByName_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewMockGetCreditCardUsecase interface {
	mock.TestingT
	Cleanup(func())
}

// NewMockGetCreditCardUsecase creates a new instance of MockGetCreditCardUsecase. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewMockGetCreditCardUsecase(t mockConstructorTestingTNewMockGetCreditCardUsecase) *MockGetCreditCardUsecase {
	mock := &MockGetCreditCardUsecase{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
