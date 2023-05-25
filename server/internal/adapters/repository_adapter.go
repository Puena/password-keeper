package adapters

import (
	repositories "github.com/Puena/password-keeper/server/internal/repostiories"
	"github.com/Puena/password-keeper/server/internal/usecases"
)

type usecaseRepoAdapter struct {
	repos *repositories.Repositories
}

func (u *usecaseRepoAdapter) Users() usecases.UsersRepository {
	return u.repos.Users
}

func (u *usecaseRepoAdapter) Token() usecases.TokenRepository {
	return u.repos.Token
}

func (u *usecaseRepoAdapter) Chests() usecases.ChestRepository {
	return u.repos.Chests
}

func (u *usecaseRepoAdapter) History() usecases.HistoryRepository {
	return u.repos.History
}

func UsecaseRepoAdapter(repos *repositories.Repositories) *usecaseRepoAdapter {
	return &usecaseRepoAdapter{
		repos: repos,
	}
}
