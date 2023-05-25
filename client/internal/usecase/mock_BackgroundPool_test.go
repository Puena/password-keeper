// Code generated by mockery v2.26.1. DO NOT EDIT.

package usecase

import (
	context "context"
	io "io"

	mock "github.com/stretchr/testify/mock"

	models "github.com/Puena/password-keeper/client/internal/models"
)

// MockBackgroundPool is an autogenerated mock type for the BackgroundPool type
type MockBackgroundPool struct {
	mock.Mock
}

type MockBackgroundPool_Expecter struct {
	mock *mock.Mock
}

func (_m *MockBackgroundPool) EXPECT() *MockBackgroundPool_Expecter {
	return &MockBackgroundPool_Expecter{mock: &_m.Mock}
}

// GetErrors provides a mock function with given fields:
func (_m *MockBackgroundPool) GetErrors() []error {
	ret := _m.Called()

	var r0 []error
	if rf, ok := ret.Get(0).(func() []error); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]error)
		}
	}

	return r0
}

// MockBackgroundPool_GetErrors_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetErrors'
type MockBackgroundPool_GetErrors_Call struct {
	*mock.Call
}

// GetErrors is a helper method to define mock.On call
func (_e *MockBackgroundPool_Expecter) GetErrors() *MockBackgroundPool_GetErrors_Call {
	return &MockBackgroundPool_GetErrors_Call{Call: _e.mock.On("GetErrors")}
}

func (_c *MockBackgroundPool_GetErrors_Call) Run(run func()) *MockBackgroundPool_GetErrors_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockBackgroundPool_GetErrors_Call) Return(_a0 []error) *MockBackgroundPool_GetErrors_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockBackgroundPool_GetErrors_Call) RunAndReturn(run func() []error) *MockBackgroundPool_GetErrors_Call {
	_c.Call.Return(run)
	return _c
}

// SetStatusOutput provides a mock function with given fields: _a0
func (_m *MockBackgroundPool) SetStatusOutput(_a0 io.Writer) {
	_m.Called(_a0)
}

// MockBackgroundPool_SetStatusOutput_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetStatusOutput'
type MockBackgroundPool_SetStatusOutput_Call struct {
	*mock.Call
}

// SetStatusOutput is a helper method to define mock.On call
//   - _a0 io.Writer
func (_e *MockBackgroundPool_Expecter) SetStatusOutput(_a0 interface{}) *MockBackgroundPool_SetStatusOutput_Call {
	return &MockBackgroundPool_SetStatusOutput_Call{Call: _e.mock.On("SetStatusOutput", _a0)}
}

func (_c *MockBackgroundPool_SetStatusOutput_Call) Run(run func(_a0 io.Writer)) *MockBackgroundPool_SetStatusOutput_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(io.Writer))
	})
	return _c
}

func (_c *MockBackgroundPool_SetStatusOutput_Call) Return() *MockBackgroundPool_SetStatusOutput_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockBackgroundPool_SetStatusOutput_Call) RunAndReturn(run func(io.Writer)) *MockBackgroundPool_SetStatusOutput_Call {
	_c.Call.Return(run)
	return _c
}

// Start provides a mock function with given fields: _a0, _a1, _a2
func (_m *MockBackgroundPool) Start(_a0 context.Context, _a1 []*models.History, _a2 func(context.Context, *models.History) error) error {
	ret := _m.Called(_a0, _a1, _a2)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []*models.History, func(context.Context, *models.History) error) error); ok {
		r0 = rf(_a0, _a1, _a2)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockBackgroundPool_Start_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Start'
type MockBackgroundPool_Start_Call struct {
	*mock.Call
}

// Start is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 []*models.History
//   - _a2 func(context.Context , *models.History) error
func (_e *MockBackgroundPool_Expecter) Start(_a0 interface{}, _a1 interface{}, _a2 interface{}) *MockBackgroundPool_Start_Call {
	return &MockBackgroundPool_Start_Call{Call: _e.mock.On("Start", _a0, _a1, _a2)}
}

func (_c *MockBackgroundPool_Start_Call) Run(run func(_a0 context.Context, _a1 []*models.History, _a2 func(context.Context, *models.History) error)) *MockBackgroundPool_Start_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]*models.History), args[2].(func(context.Context, *models.History) error))
	})
	return _c
}

func (_c *MockBackgroundPool_Start_Call) Return(_a0 error) *MockBackgroundPool_Start_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockBackgroundPool_Start_Call) RunAndReturn(run func(context.Context, []*models.History, func(context.Context, *models.History) error) error) *MockBackgroundPool_Start_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewMockBackgroundPool interface {
	mock.TestingT
	Cleanup(func())
}

// NewMockBackgroundPool creates a new instance of MockBackgroundPool. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewMockBackgroundPool(t mockConstructorTestingTNewMockBackgroundPool) *MockBackgroundPool {
	mock := &MockBackgroundPool{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
