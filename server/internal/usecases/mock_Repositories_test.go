// Code generated by mockery v2.26.1. DO NOT EDIT.

package usecases

import mock "github.com/stretchr/testify/mock"

// MockRepositories is an autogenerated mock type for the Repositories type
type MockRepositories struct {
	mock.Mock
}

type MockRepositories_Expecter struct {
	mock *mock.Mock
}

func (_m *MockRepositories) EXPECT() *MockRepositories_Expecter {
	return &MockRepositories_Expecter{mock: &_m.Mock}
}

// Chests provides a mock function with given fields:
func (_m *MockRepositories) Chests() ChestRepository {
	ret := _m.Called()

	var r0 ChestRepository
	if rf, ok := ret.Get(0).(func() ChestRepository); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(ChestRepository)
		}
	}

	return r0
}

// MockRepositories_Chests_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Chests'
type MockRepositories_Chests_Call struct {
	*mock.Call
}

// Chests is a helper method to define mock.On call
func (_e *MockRepositories_Expecter) Chests() *MockRepositories_Chests_Call {
	return &MockRepositories_Chests_Call{Call: _e.mock.On("Chests")}
}

func (_c *MockRepositories_Chests_Call) Run(run func()) *MockRepositories_Chests_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockRepositories_Chests_Call) Return(_a0 ChestRepository) *MockRepositories_Chests_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockRepositories_Chests_Call) RunAndReturn(run func() ChestRepository) *MockRepositories_Chests_Call {
	_c.Call.Return(run)
	return _c
}

// History provides a mock function with given fields:
func (_m *MockRepositories) History() HistoryRepository {
	ret := _m.Called()

	var r0 HistoryRepository
	if rf, ok := ret.Get(0).(func() HistoryRepository); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(HistoryRepository)
		}
	}

	return r0
}

// MockRepositories_History_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'History'
type MockRepositories_History_Call struct {
	*mock.Call
}

// History is a helper method to define mock.On call
func (_e *MockRepositories_Expecter) History() *MockRepositories_History_Call {
	return &MockRepositories_History_Call{Call: _e.mock.On("History")}
}

func (_c *MockRepositories_History_Call) Run(run func()) *MockRepositories_History_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockRepositories_History_Call) Return(_a0 HistoryRepository) *MockRepositories_History_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockRepositories_History_Call) RunAndReturn(run func() HistoryRepository) *MockRepositories_History_Call {
	_c.Call.Return(run)
	return _c
}

// Token provides a mock function with given fields:
func (_m *MockRepositories) Token() TokenRepository {
	ret := _m.Called()

	var r0 TokenRepository
	if rf, ok := ret.Get(0).(func() TokenRepository); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(TokenRepository)
		}
	}

	return r0
}

// MockRepositories_Token_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Token'
type MockRepositories_Token_Call struct {
	*mock.Call
}

// Token is a helper method to define mock.On call
func (_e *MockRepositories_Expecter) Token() *MockRepositories_Token_Call {
	return &MockRepositories_Token_Call{Call: _e.mock.On("Token")}
}

func (_c *MockRepositories_Token_Call) Run(run func()) *MockRepositories_Token_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockRepositories_Token_Call) Return(_a0 TokenRepository) *MockRepositories_Token_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockRepositories_Token_Call) RunAndReturn(run func() TokenRepository) *MockRepositories_Token_Call {
	_c.Call.Return(run)
	return _c
}

// Users provides a mock function with given fields:
func (_m *MockRepositories) Users() UsersRepository {
	ret := _m.Called()

	var r0 UsersRepository
	if rf, ok := ret.Get(0).(func() UsersRepository); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(UsersRepository)
		}
	}

	return r0
}

// MockRepositories_Users_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Users'
type MockRepositories_Users_Call struct {
	*mock.Call
}

// Users is a helper method to define mock.On call
func (_e *MockRepositories_Expecter) Users() *MockRepositories_Users_Call {
	return &MockRepositories_Users_Call{Call: _e.mock.On("Users")}
}

func (_c *MockRepositories_Users_Call) Run(run func()) *MockRepositories_Users_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockRepositories_Users_Call) Return(_a0 UsersRepository) *MockRepositories_Users_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockRepositories_Users_Call) RunAndReturn(run func() UsersRepository) *MockRepositories_Users_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewMockRepositories interface {
	mock.TestingT
	Cleanup(func())
}

// NewMockRepositories creates a new instance of MockRepositories. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewMockRepositories(t mockConstructorTestingTNewMockRepositories) *MockRepositories {
	mock := &MockRepositories{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
