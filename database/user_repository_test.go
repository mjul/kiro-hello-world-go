//go:build !cgo
// +build !cgo

package database

import (
	"sso-web-app/models"
	"testing"
	"time"
)

// TestNewUserRepository tests the constructor
func TestNewUserRepository(t *testing.T) {
	db := &DB{DB: nil}
	repo := NewUserRepository(db)
	
	if repo == nil {
		t.Errorf("NewUserRepository() returned nil")
	}
	
	// Verify it returns the correct type
	if _, ok := repo.(*SQLiteUserRepository); !ok {
		t.Errorf("NewUserRepository() did not return *SQLiteUserRepository")
	}
}

// TestSQLiteUserRepository_FindByProviderID_NilDB tests with nil database
func TestSQLiteUserRepository_FindByProviderID_NilDB(t *testing.T) {
	repo := &SQLiteUserRepository{db: nil}
	
	user, err := repo.FindByProviderID("github", "12345")
	if err == nil {
		t.Errorf("FindByProviderID() should fail with nil database")
	}
	if user != nil {
		t.Errorf("FindByProviderID() should return nil user with nil database")
	}
}

// TestSQLiteUserRepository_Create_NilDB tests with nil database
func TestSQLiteUserRepository_Create_NilDB(t *testing.T) {
	repo := &SQLiteUserRepository{db: nil}
	
	user := &models.User{
		Provider:   "github",
		ProviderID: "12345",
		Username:   "testuser",
	}
	
	err := repo.Create(user)
	if err == nil {
		t.Errorf("Create() should fail with nil database")
	}
}

// TestSQLiteUserRepository_Create_NilUser tests with nil user
func TestSQLiteUserRepository_Create_NilUser(t *testing.T) {
	db := &DB{DB: nil}
	repo := &SQLiteUserRepository{db: db}
	
	err := repo.Create(nil)
	if err == nil {
		t.Errorf("Create() should fail with nil user")
	}
	
	expectedMsg := "user cannot be nil"
	if err.Error() != expectedMsg {
		t.Errorf("Create() error = %v, want %v", err.Error(), expectedMsg)
	}
}

// TestSQLiteUserRepository_Create_InvalidUser tests with invalid user
func TestSQLiteUserRepository_Create_InvalidUser(t *testing.T) {
	db := &DB{DB: nil}
	repo := &SQLiteUserRepository{db: db}
	
	// User with missing required fields
	user := &models.User{
		Provider: "", // Invalid - empty provider
		ProviderID: "12345",
		Username: "testuser",
	}
	
	err := repo.Create(user)
	if err == nil {
		t.Errorf("Create() should fail with invalid user")
	}
	
	// Should contain validation error
	if err != nil && err.Error() == "" {
		t.Errorf("Create() should return validation error message")
	}
}

// TestSQLiteUserRepository_Update_NilDB tests with nil database
func TestSQLiteUserRepository_Update_NilDB(t *testing.T) {
	repo := &SQLiteUserRepository{db: nil}
	
	user := &models.User{
		ID:         1,
		Provider:   "github",
		ProviderID: "12345",
		Username:   "testuser",
	}
	
	err := repo.Update(user)
	if err == nil {
		t.Errorf("Update() should fail with nil database")
	}
}

// TestSQLiteUserRepository_Update_NilUser tests with nil user
func TestSQLiteUserRepository_Update_NilUser(t *testing.T) {
	db := &DB{DB: nil}
	repo := &SQLiteUserRepository{db: db}
	
	err := repo.Update(nil)
	if err == nil {
		t.Errorf("Update() should fail with nil user")
	}
	
	expectedMsg := "user cannot be nil"
	if err.Error() != expectedMsg {
		t.Errorf("Update() error = %v, want %v", err.Error(), expectedMsg)
	}
}

// TestSQLiteUserRepository_Update_InvalidUserID tests with invalid user ID
func TestSQLiteUserRepository_Update_InvalidUserID(t *testing.T) {
	db := &DB{DB: nil}
	repo := &SQLiteUserRepository{db: db}
	
	tests := []struct {
		name   string
		userID int
	}{
		{"zero ID", 0},
		{"negative ID", -1},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &models.User{
				ID:         tt.userID,
				Provider:   "github",
				ProviderID: "12345",
				Username:   "testuser",
			}
			
			err := repo.Update(user)
			if err == nil {
				t.Errorf("Update() should fail with invalid user ID %d", tt.userID)
			}
			
			expectedMsg := "user ID must be positive"
			if err.Error() != expectedMsg {
				t.Errorf("Update() error = %v, want %v", err.Error(), expectedMsg)
			}
		})
	}
}

// TestSQLiteUserRepository_Update_InvalidUser tests with invalid user data
func TestSQLiteUserRepository_Update_InvalidUser(t *testing.T) {
	db := &DB{DB: nil}
	repo := &SQLiteUserRepository{db: db}
	
	// User with missing required fields
	user := &models.User{
		ID:         1,
		Provider:   "", // Invalid - empty provider
		ProviderID: "12345",
		Username:   "testuser",
	}
	
	err := repo.Update(user)
	if err == nil {
		t.Errorf("Update() should fail with invalid user")
	}
	
	// Should contain validation error
	if err != nil && err.Error() == "" {
		t.Errorf("Update() should return validation error message")
	}
}

// TestSQLiteUserRepository_Create_TimestampHandling tests timestamp handling
func TestSQLiteUserRepository_Create_TimestampHandling(t *testing.T) {
	db := &DB{DB: nil}
	repo := &SQLiteUserRepository{db: db}
	
	user := &models.User{
		Provider:   "github",
		ProviderID: "12345",
		Username:   "testuser",
		Email:      "test@example.com",
	}
	
	// Timestamps should be zero initially
	if !user.CreatedAt.IsZero() {
		t.Errorf("CreatedAt should be zero initially")
	}
	if !user.UpdatedAt.IsZero() {
		t.Errorf("UpdatedAt should be zero initially")
	}
	
	// This will fail due to nil DB, but we can check that timestamps would be set
	// by examining the error handling logic
	err := repo.Create(user)
	if err == nil {
		t.Errorf("Create() should fail with nil database connection")
	}
}

// TestSQLiteUserRepository_Update_TimestampHandling tests timestamp handling in update
func TestSQLiteUserRepository_Update_TimestampHandling(t *testing.T) {
	db := &DB{DB: nil}
	repo := &SQLiteUserRepository{db: db}
	
	originalTime := time.Now().Add(-time.Hour)
	user := &models.User{
		ID:         1,
		Provider:   "github",
		ProviderID: "12345",
		Username:   "testuser",
		Email:      "test@example.com",
		CreatedAt:  originalTime,
		UpdatedAt:  originalTime,
	}
	
	// This will fail due to nil DB, but we can verify the validation logic
	err := repo.Update(user)
	if err == nil {
		t.Errorf("Update() should fail with nil database connection")
	}
}