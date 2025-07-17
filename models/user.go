package models

import (
	"errors"
	"strings"
	"time"
)

// User represents a user in the system
type User struct {
	ID         int       `db:"id" json:"id"`
	Provider   string    `db:"provider" json:"provider"`
	ProviderID string    `db:"provider_id" json:"provider_id"`
	Username   string    `db:"username" json:"username"`
	Email      string    `db:"email" json:"email"`
	AvatarURL  string    `db:"avatar_url" json:"avatar_url"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
	UpdatedAt  time.Time `db:"updated_at" json:"updated_at"`
}

// Validate validates the User struct fields
func (u *User) Validate() error {
	if strings.TrimSpace(u.Provider) == "" {
		return errors.New("provider is required")
	}
	
	if strings.TrimSpace(u.ProviderID) == "" {
		return errors.New("provider_id is required")
	}
	
	if strings.TrimSpace(u.Username) == "" {
		return errors.New("username is required")
	}
	
	// Validate provider is one of the supported providers
	validProviders := map[string]bool{
		"microsoft": true,
		"github":    true,
	}
	
	if !validProviders[strings.ToLower(u.Provider)] {
		return errors.New("provider must be 'microsoft' or 'github'")
	}
	
	return nil
}

// IsValid returns true if the user is valid
func (u *User) IsValid() bool {
	return u.Validate() == nil
}