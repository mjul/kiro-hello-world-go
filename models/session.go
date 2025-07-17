package models

import (
	"errors"
	"strings"
	"time"
)

// Session represents a user session in the system
type Session struct {
	ID        string    `db:"id" json:"id"`
	UserID    int       `db:"user_id" json:"user_id"`
	ExpiresAt time.Time `db:"expires_at" json:"expires_at"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// Validate validates the Session struct fields
func (s *Session) Validate() error {
	if strings.TrimSpace(s.ID) == "" {
		return errors.New("session id is required")
	}
	
	if s.UserID <= 0 {
		return errors.New("user_id must be a positive integer")
	}
	
	if s.ExpiresAt.IsZero() {
		return errors.New("expires_at is required")
	}
	
	if s.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	
	return nil
}

// IsValid returns true if the session is valid
func (s *Session) IsValid() bool {
	return s.Validate() == nil
}

// IsExpired returns true if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsActive returns true if the session is valid and not expired
func (s *Session) IsActive() bool {
	return s.IsValid() && !s.IsExpired()
}

// TimeUntilExpiry returns the duration until the session expires
func (s *Session) TimeUntilExpiry() time.Duration {
	if s.IsExpired() {
		return 0
	}
	return time.Until(s.ExpiresAt)
}