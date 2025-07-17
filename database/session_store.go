package database

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sso-web-app/models"
	"time"
)

// SessionStore defines the interface for session data operations
type SessionStore interface {
	Create(userID int, duration time.Duration) (*models.Session, error)
	Get(sessionID string) (*models.Session, error)
	Delete(sessionID string) error
	Cleanup() error
}

// SQLiteSessionStore implements SessionStore for SQLite database
type SQLiteSessionStore struct {
	db *DB
}

// NewSessionStore creates a new SessionStore instance
func NewSessionStore(db *DB) SessionStore {
	return &SQLiteSessionStore{db: db}
}

// generateSessionID generates a cryptographically secure random session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// Create creates a new session for the given user
func (s *SQLiteSessionStore) Create(userID int, duration time.Duration) (*models.Session, error) {
	if s.db == nil || s.db.DB == nil {
		return nil, fmt.Errorf("database connection is nil")
	}

	if userID <= 0 {
		return nil, fmt.Errorf("user ID must be positive")
	}

	if duration <= 0 {
		return nil, fmt.Errorf("session duration must be positive")
	}

	// Generate a secure session ID
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(duration)

	session := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	// Validate the session before inserting
	if err := session.Validate(); err != nil {
		return nil, fmt.Errorf("session validation failed: %w", err)
	}

	query := `
		INSERT INTO sessions (id, user_id, expires_at, created_at)
		VALUES (?, ?, ?, ?)
	`

	_, err = s.db.Exec(query, session.ID, session.UserID, session.ExpiresAt, session.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return session, nil
}

// Get retrieves a session by ID
func (s *SQLiteSessionStore) Get(sessionID string) (*models.Session, error) {
	if s.db == nil || s.db.DB == nil {
		return nil, fmt.Errorf("database connection is nil")
	}

	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}

	query := `
		SELECT id, user_id, expires_at, created_at
		FROM sessions 
		WHERE id = ?
	`

	session := &models.Session{}
	err := s.db.QueryRow(query, sessionID).Scan(
		&session.ID,
		&session.UserID,
		&session.ExpiresAt,
		&session.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Session not found, return nil without error
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return session, nil
}

// Delete removes a session by ID
func (s *SQLiteSessionStore) Delete(sessionID string) error {
	if s.db == nil || s.db.DB == nil {
		return fmt.Errorf("database connection is nil")
	}

	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}

	query := `DELETE FROM sessions WHERE id = ?`

	result, err := s.db.Exec(query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	// Check if any rows were affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("session with ID %s not found", sessionID)
	}

	return nil
}

// Cleanup removes all expired sessions from the database
func (s *SQLiteSessionStore) Cleanup() error {
	if s.db == nil || s.db.DB == nil {
		return fmt.Errorf("database connection is nil")
	}

	query := `DELETE FROM sessions WHERE expires_at < ?`

	result, err := s.db.Exec(query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	// Get the number of cleaned up sessions for logging purposes
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	// Note: In a real application, you might want to log this information
	_ = rowsAffected

	return nil
}

// CleanupExpiredSessions is a convenience method that can be called periodically
func (s *SQLiteSessionStore) CleanupExpiredSessions() error {
	return s.Cleanup()
}

// GetActiveSessionsCount returns the number of active (non-expired) sessions
func (s *SQLiteSessionStore) GetActiveSessionsCount() (int, error) {
	if s.db == nil || s.db.DB == nil {
		return 0, fmt.Errorf("database connection is nil")
	}

	query := `SELECT COUNT(*) FROM sessions WHERE expires_at > ?`

	var count int
	err := s.db.QueryRow(query, time.Now()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active sessions: %w", err)
	}

	return count, nil
}