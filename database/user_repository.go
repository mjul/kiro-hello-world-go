package database

import (
	"database/sql"
	"fmt"
	"sso-web-app/models"
	"time"
)

// UserRepository defines the interface for user data operations
type UserRepository interface {
	FindByProviderID(provider, providerID string) (*models.User, error)
	FindByID(id int) (*models.User, error)
	Create(user *models.User) error
	Update(user *models.User) error
}

// SQLiteUserRepository implements UserRepository for SQLite database
type SQLiteUserRepository struct {
	db *DB
}

// NewUserRepository creates a new UserRepository instance
func NewUserRepository(db *DB) UserRepository {
	return &SQLiteUserRepository{db: db}
}

// FindByProviderID finds a user by provider and provider ID
func (r *SQLiteUserRepository) FindByProviderID(provider, providerID string) (*models.User, error) {
	if r.db == nil || r.db.DB == nil {
		return nil, fmt.Errorf("database connection is nil")
	}

	query := `
		SELECT id, provider, provider_id, username, email, avatar_url, created_at, updated_at
		FROM users 
		WHERE provider = ? AND provider_id = ?
	`

	user := &models.User{}
	err := r.db.QueryRow(query, provider, providerID).Scan(
		&user.ID,
		&user.Provider,
		&user.ProviderID,
		&user.Username,
		&user.Email,
		&user.AvatarURL,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found, return nil without error
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	return user, nil
}

// FindByID finds a user by their ID
func (r *SQLiteUserRepository) FindByID(id int) (*models.User, error) {
	if r.db == nil || r.db.DB == nil {
		return nil, fmt.Errorf("database connection is nil")
	}

	if id <= 0 {
		return nil, fmt.Errorf("user ID must be positive")
	}

	query := `
		SELECT id, provider, provider_id, username, email, avatar_url, created_at, updated_at
		FROM users 
		WHERE id = ?
	`

	user := &models.User{}
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Provider,
		&user.ProviderID,
		&user.Username,
		&user.Email,
		&user.AvatarURL,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found, return nil without error
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	return user, nil
}

// Create creates a new user in the database
func (r *SQLiteUserRepository) Create(user *models.User) error {
	if r.db == nil || r.db.DB == nil {
		return fmt.Errorf("database connection is nil")
	}

	if user == nil {
		return fmt.Errorf("user cannot be nil")
	}

	// Validate user before creating
	if err := user.Validate(); err != nil {
		return fmt.Errorf("user validation failed: %w", err)
	}

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	query := `
		INSERT INTO users (provider, provider_id, username, email, avatar_url, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	result, err := r.db.Exec(query,
		user.Provider,
		user.ProviderID,
		user.Username,
		user.Email,
		user.AvatarURL,
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Get the inserted ID
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get inserted user ID: %w", err)
	}

	user.ID = int(id)
	return nil
}

// Update updates an existing user in the database
func (r *SQLiteUserRepository) Update(user *models.User) error {
	if r.db == nil || r.db.DB == nil {
		return fmt.Errorf("database connection is nil")
	}

	if user == nil {
		return fmt.Errorf("user cannot be nil")
	}

	if user.ID <= 0 {
		return fmt.Errorf("user ID must be positive")
	}

	// Validate user before updating
	if err := user.Validate(); err != nil {
		return fmt.Errorf("user validation failed: %w", err)
	}

	user.UpdatedAt = time.Now()

	query := `
		UPDATE users 
		SET provider = ?, provider_id = ?, username = ?, email = ?, avatar_url = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := r.db.Exec(query,
		user.Provider,
		user.ProviderID,
		user.Username,
		user.Email,
		user.AvatarURL,
		user.UpdatedAt,
		user.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Check if any rows were affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user with ID %d not found", user.ID)
	}

	return nil
}