// Code generated by mockery v2.26.1. DO NOT EDIT.

package usecases

import (
	context "context"

	models "github.com/Puena/password-keeper/server/internal/models"
	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// MockChestRepository is an autogenerated mock type for the ChestRepository type
type MockChestRepository struct {
	mock.Mock
}

type MockChestRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *MockChestRepository) EXPECT() *MockChestRepository_Expecter {
	return &MockChestRepository_Expecter{mock: &_m.Mock}
}

// ConflictError provides a mock function with given fields: err
func (_m *MockChestRepository) ConflictError(err error) error {
	ret := _m.Called(err)

	var r0 error
	if rf, ok := ret.Get(0).(func(error) error); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockChestRepository_ConflictError_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ConflictError'
type MockChestRepository_ConflictError_Call struct {
	*mock.Call
}

// ConflictError is a helper method to define mock.On call
//   - err error
func (_e *MockChestRepository_Expecter) ConflictError(err interface{}) *MockChestRepository_ConflictError_Call {
	return &MockChestRepository_ConflictError_Call{Call: _e.mock.On("ConflictError", err)}
}

func (_c *MockChestRepository_ConflictError_Call) Run(run func(err error)) *MockChestRepository_ConflictError_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(error))
	})
	return _c
}

func (_c *MockChestRepository_ConflictError_Call) Return(_a0 error) *MockChestRepository_ConflictError_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockChestRepository_ConflictError_Call) RunAndReturn(run func(error) error) *MockChestRepository_ConflictError_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteChest provides a mock function with given fields: ctx, history
func (_m *MockChestRepository) DeleteChest(ctx context.Context, history *models.History) error {
	ret := _m.Called(ctx, history)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *models.History) error); ok {
		r0 = rf(ctx, history)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockChestRepository_DeleteChest_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteChest'
type MockChestRepository_DeleteChest_Call struct {
	*mock.Call
}

// DeleteChest is a helper method to define mock.On call
//   - ctx context.Context
//   - history *models.History
func (_e *MockChestRepository_Expecter) DeleteChest(ctx interface{}, history interface{}) *MockChestRepository_DeleteChest_Call {
	return &MockChestRepository_DeleteChest_Call{Call: _e.mock.On("DeleteChest", ctx, history)}
}

func (_c *MockChestRepository_DeleteChest_Call) Run(run func(ctx context.Context, history *models.History)) *MockChestRepository_DeleteChest_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*models.History))
	})
	return _c
}

func (_c *MockChestRepository_DeleteChest_Call) Return(_a0 error) *MockChestRepository_DeleteChest_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockChestRepository_DeleteChest_Call) RunAndReturn(run func(context.Context, *models.History) error) *MockChestRepository_DeleteChest_Call {
	_c.Call.Return(run)
	return _c
}

// NotAffectedError provides a mock function with given fields: err
func (_m *MockChestRepository) NotAffectedError(err error) error {
	ret := _m.Called(err)

	var r0 error
	if rf, ok := ret.Get(0).(func(error) error); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockChestRepository_NotAffectedError_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'NotAffectedError'
type MockChestRepository_NotAffectedError_Call struct {
	*mock.Call
}

// NotAffectedError is a helper method to define mock.On call
//   - err error
func (_e *MockChestRepository_Expecter) NotAffectedError(err interface{}) *MockChestRepository_NotAffectedError_Call {
	return &MockChestRepository_NotAffectedError_Call{Call: _e.mock.On("NotAffectedError", err)}
}

func (_c *MockChestRepository_NotAffectedError_Call) Run(run func(err error)) *MockChestRepository_NotAffectedError_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(error))
	})
	return _c
}

func (_c *MockChestRepository_NotAffectedError_Call) Return(_a0 error) *MockChestRepository_NotAffectedError_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockChestRepository_NotAffectedError_Call) RunAndReturn(run func(error) error) *MockChestRepository_NotAffectedError_Call {
	_c.Call.Return(run)
	return _c
}

// NotFoundError provides a mock function with given fields: err
func (_m *MockChestRepository) NotFoundError(err error) error {
	ret := _m.Called(err)

	var r0 error
	if rf, ok := ret.Get(0).(func(error) error); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockChestRepository_NotFoundError_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'NotFoundError'
type MockChestRepository_NotFoundError_Call struct {
	*mock.Call
}

// NotFoundError is a helper method to define mock.On call
//   - err error
func (_e *MockChestRepository_Expecter) NotFoundError(err interface{}) *MockChestRepository_NotFoundError_Call {
	return &MockChestRepository_NotFoundError_Call{Call: _e.mock.On("NotFoundError", err)}
}

func (_c *MockChestRepository_NotFoundError_Call) Run(run func(err error)) *MockChestRepository_NotFoundError_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(error))
	})
	return _c
}

func (_c *MockChestRepository_NotFoundError_Call) Return(_a0 error) *MockChestRepository_NotFoundError_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockChestRepository_NotFoundError_Call) RunAndReturn(run func(error) error) *MockChestRepository_NotFoundError_Call {
	_c.Call.Return(run)
	return _c
}

// RepositoryError provides a mock function with given fields: err
func (_m *MockChestRepository) RepositoryError(err error) error {
	ret := _m.Called(err)

	var r0 error
	if rf, ok := ret.Get(0).(func(error) error); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockChestRepository_RepositoryError_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RepositoryError'
type MockChestRepository_RepositoryError_Call struct {
	*mock.Call
}

// RepositoryError is a helper method to define mock.On call
//   - err error
func (_e *MockChestRepository_Expecter) RepositoryError(err interface{}) *MockChestRepository_RepositoryError_Call {
	return &MockChestRepository_RepositoryError_Call{Call: _e.mock.On("RepositoryError", err)}
}

func (_c *MockChestRepository_RepositoryError_Call) Run(run func(err error)) *MockChestRepository_RepositoryError_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(error))
	})
	return _c
}

func (_c *MockChestRepository_RepositoryError_Call) Return(_a0 error) *MockChestRepository_RepositoryError_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockChestRepository_RepositoryError_Call) RunAndReturn(run func(error) error) *MockChestRepository_RepositoryError_Call {
	_c.Call.Return(run)
	return _c
}

// SelectChestByID provides a mock function with given fields: ctx, chestID, userID
func (_m *MockChestRepository) SelectChestByID(ctx context.Context, chestID string, userID uuid.UUID) (*models.Chest, *models.History, error) {
	ret := _m.Called(ctx, chestID, userID)

	var r0 *models.Chest
	var r1 *models.History
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, uuid.UUID) (*models.Chest, *models.History, error)); ok {
		return rf(ctx, chestID, userID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, uuid.UUID) *models.Chest); ok {
		r0 = rf(ctx, chestID, userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*models.Chest)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, uuid.UUID) *models.History); ok {
		r1 = rf(ctx, chestID, userID)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*models.History)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, uuid.UUID) error); ok {
		r2 = rf(ctx, chestID, userID)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockChestRepository_SelectChestByID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SelectChestByID'
type MockChestRepository_SelectChestByID_Call struct {
	*mock.Call
}

// SelectChestByID is a helper method to define mock.On call
//   - ctx context.Context
//   - chestID string
//   - userID uuid.UUID
func (_e *MockChestRepository_Expecter) SelectChestByID(ctx interface{}, chestID interface{}, userID interface{}) *MockChestRepository_SelectChestByID_Call {
	return &MockChestRepository_SelectChestByID_Call{Call: _e.mock.On("SelectChestByID", ctx, chestID, userID)}
}

func (_c *MockChestRepository_SelectChestByID_Call) Run(run func(ctx context.Context, chestID string, userID uuid.UUID)) *MockChestRepository_SelectChestByID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(uuid.UUID))
	})
	return _c
}

func (_c *MockChestRepository_SelectChestByID_Call) Return(_a0 *models.Chest, _a1 *models.History, _a2 error) *MockChestRepository_SelectChestByID_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockChestRepository_SelectChestByID_Call) RunAndReturn(run func(context.Context, string, uuid.UUID) (*models.Chest, *models.History, error)) *MockChestRepository_SelectChestByID_Call {
	_c.Call.Return(run)
	return _c
}

// UpsertChest provides a mock function with given fields: ctx, chest, history
func (_m *MockChestRepository) UpsertChest(ctx context.Context, chest *models.Chest, history *models.History) error {
	ret := _m.Called(ctx, chest, history)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *models.Chest, *models.History) error); ok {
		r0 = rf(ctx, chest, history)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockChestRepository_UpsertChest_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpsertChest'
type MockChestRepository_UpsertChest_Call struct {
	*mock.Call
}

// UpsertChest is a helper method to define mock.On call
//   - ctx context.Context
//   - chest *models.Chest
//   - history *models.History
func (_e *MockChestRepository_Expecter) UpsertChest(ctx interface{}, chest interface{}, history interface{}) *MockChestRepository_UpsertChest_Call {
	return &MockChestRepository_UpsertChest_Call{Call: _e.mock.On("UpsertChest", ctx, chest, history)}
}

func (_c *MockChestRepository_UpsertChest_Call) Run(run func(ctx context.Context, chest *models.Chest, history *models.History)) *MockChestRepository_UpsertChest_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*models.Chest), args[2].(*models.History))
	})
	return _c
}

func (_c *MockChestRepository_UpsertChest_Call) Return(_a0 error) *MockChestRepository_UpsertChest_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockChestRepository_UpsertChest_Call) RunAndReturn(run func(context.Context, *models.Chest, *models.History) error) *MockChestRepository_UpsertChest_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewMockChestRepository interface {
	mock.TestingT
	Cleanup(func())
}

// NewMockChestRepository creates a new instance of MockChestRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewMockChestRepository(t mockConstructorTestingTNewMockChestRepository) *MockChestRepository {
	mock := &MockChestRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
