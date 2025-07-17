package database

import (
	"sso-web-app/models"
	"testing"
	"time"
)



// TestNewUserRepository tests the constructor
func TestNewUserRepository(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	repo := NewUserRepository(db)
	
	if repo == nil {
		t.Errorf("NewUserRepository() returned nil")
	}
	
	// Verify it returns the correct type
	if _, ok := repo.(*SQLiteUserRepository); !ok {
		t.Errorf("NewUserRepository() did not return *SQLiteUserRepository")
	}
}

// TestSQLiteUserRepository_FindByProviderID_NotFound tests finding non-existent user
func TestSQLiteUserRepository_FindByProviderID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	repo := NewUserRepository(db)
	
	user, err := repo.FindByProviderID("github", "nonexistent")
	if err != nil {
		t.Errorf("FindByProviderID() should not return error for non-existent user, got: %v", err)
	}
	if user != nil {
		t.Errorf("FindByProviderID() should return nil user for non-existent user")
	}
}

// TestSQLiteUserRepository_CreateAndFind tests creating and finding a user
func TestSQLiteUserRepository_CreateAndFind(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	repo := NewUserRepository(db)
	
	user := &models.User{
		Provider:   "github",
		ProviderID: "12345",
		Username:   "testuser",
		Email:      "test@example.com",
	}
	
	// Create user
	err := repo.Create(user)
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}
	
	// User should now have an ID
	if user.ID == 0 {
		t.Errorf("Create() should set user ID")
	}
	
	// Find the user
	foundUser, err := repo.FindByProviderID("github", "12345")
	if err != nil {
		t.Fatalf("FindByProviderID() failed: %v", err)
	}
	
	if foundUser == nil {
		t.Fatalf("FindByProviderID() returned nil user")
	}
	
	// Verify user data
	if foundUser.Provider != user.Provider {
		t.Errorf("Provider = %v, want %v", foundUser.Provider, user.Provider)
	}
	if foundUser.ProviderID != user.ProviderID {
		t.Errorf("ProviderID = %v, want %v", foundUser.ProviderID, user.ProviderID)
	}
	if foundUser.Username != user.Username {
		t.Errorf("Username = %v, want %v", foundUser.Username, user.Username)
	}
	if foundUser.Email != user.Email {
		t.Errorf("Email = %v, want %v", foundUser.Email, user.Email)
	}
}

// TestSQLiteUserRepository_Create_NilUser tests with nil user
func TestSQLiteUserRepository_Create_NilUser(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	repo := NewUserRepository(db)
	
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
	db := setupTestDB(t)
	defer db.Close()
	
	repo := NewUserRepository(db)
	
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
}

// TestSQLiteUserRepository_Update_NilUser tests with nil user
func TestSQLiteUserRepository_Update_NilUser(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	repo := NewUserRepository(db)
	
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
	db := setupTestDB(t)
	defer db.Close()
	
	repo := NewUserRepository(db)
	
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

// TestSQLiteUserRepository_CreateUpdateAndFind tests full CRUD operations
func TestSQLiteUserRepository_CreateUpdateAndFind(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	repo := NewUserRepository(db)
	
	// Create user
	user := &models.User{
		Provider:   "github",
		ProviderID: "12345",
		Username:   "testuser",
		Email:      "test@example.com",
	}
	
	err := repo.Create(user)
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}
	
	// Verify timestamps were set
	if user.CreatedAt.IsZero() {
		t.Errorf("CreatedAt should be set after Create()")
	}
	if user.UpdatedAt.IsZero() {
		t.Errorf("UpdatedAt should be set after Create()")
	}
	
	// Update user
	user.Username = "updateduser"
	user.Email = "updated@example.com"
	originalUpdatedAt := user.UpdatedAt
	
	// Wait a bit to ensure timestamp difference
	time.Sleep(10 * time.Millisecond)
	
	err = repo.Update(user)
	if err != nil {
		t.Fatalf("Update() failed: %v", err)
	}
	
	// Verify UpdatedAt was changed
	if !user.UpdatedAt.After(originalUpdatedAt) {
		t.Errorf("UpdatedAt should be updated after Update()")
	}
	
	// Find and verify updated user
	foundUser, err := repo.FindByProviderID("github", "12345")
	if err != nil {
		t.Fatalf("FindByProviderID() failed: %v", err)
	}
	
	if foundUser.Username != "updateduser" {
		t.Errorf("Username = %v, want %v", foundUser.Username, "updateduser")
	}
	if foundUser.Email != "updated@example.com" {
		t.Errorf("Email = %v, want %v", foundUser.Email, "updated@example.com")
	}
}