package dto

// AuthDataDto represent data transfer object for auth data.
type AuthDataDto struct {
	Login    string `validate:"required,email"`        // accept only email as login.
	Password string `validate:"required,gte=8,lte=24"` // accept password only greater or equal 8 symbols, but lower than 25.
}
