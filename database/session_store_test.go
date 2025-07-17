package database

import (
	"path/filepath"
	"sso-web-app/models"
	"strings"
	"testing"
	"time"
)

// setupTestDB creates a temporary SQLite database for testing
func setupTestDB(t *testing.T) *DB {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	
	db, err := Initialize(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	
	return db
}



// TestNewSessionStore tests the constructor
func TestNewSessionStore(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	store := NewSessionStore(db)
	
	if store == nil {
		t.Errorf("NewSessionStore() returned nil")
	}
	
	// Verify it returns the correct type
	if _, ok := store.(*SQLiteSessionStore); !ok {
		t.Errorf("NewSessionStore() did not return *SQLiteSessionStore")
	}
}

// TestGenerateSessionID tests session ID generation
func TestGenerateSessionID(t *testing.T) {
	// Generate multiple session IDs to test uniqueness and format
	ids := make(map[string]bool)
	
	for i := 0; i < 100; i++ {
		id, err := generateSessionID()
		if err != nil {
			t.Fatalf("generateSessionID() failed: %v", err)
		}
		
		// Check length (32 bytes = 64 hex characters)
		if len(id) != 64 {
			t.Errorf("generateSessionID() returned ID with length %d, want 64", len(id))
		}
		
		// Check that it's valid hex
		if !isValidHex(id) {
			t.Errorf("generateSessionID() returned non-hex ID: %s", id)
		}
		
		// Check uniqueness
		if ids[id] {
			t.Errorf("generateSessionID() generated duplicate ID: %s", id)
		}
		ids[id] = true
	}
}

// isValidHex checks if a string contains only valid hexadecimal characters
func isValidHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// TestSQLiteSessionStore_Create_InvalidUserID tests with invalid user ID
func TestSQLiteSessionStore_Create_InvalidUserID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	store := NewSessionStore(db)
	
	tests := []struct {
		name   string
		userID int
	}{
		{"zero user ID", 0},
		{"negative user ID", -1},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, err := store.Create(tt.userID, time.Hour)
			if err == nil {
				t.Errorf("Create() should fail with invalid user ID %d", tt.userID)
			}
			if session != nil {
				t.Errorf("Create() should return nil session with invalid user ID")
			}
			
			expectedMsg := "user ID must be positive"
			if err.Error() != expectedMsg {
				t.Errorf("Create() error = %v, want %v", err.Error(), expectedMsg)
			}
		})
	}
}

// TestSQLiteSessionStore_Create_InvalidDuration tests with invalid duration
func TestSQLiteSessionStore_Create_InvalidDuration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	store := NewSessionStore(db)
	
	tests := []struct {
		name     string
		duration time.Duration
	}{
		{"zero duration", 0},
		{"negative duration", -time.Hour},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, err := store.Create(1, tt.duration)
			if err == nil {
				t.Errorf("Create() should fail with invalid duration %v", tt.duration)
			}
			if session != nil {
				t.Errorf("Create() should return nil session with invalid duration")
			}
			
			expectedMsg := "session duration must be positive"
			if err.Error() != expectedMsg {
				t.Errorf("Create() error = %v, want %v", err.Error(), expectedMsg)
			}
		})
	}
}

// TestSQLiteSessionStore_Get_EmptySessionID tests with empty session ID
func TestSQLiteSessionStore_Get_EmptySessionID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	store := NewSessionStore(db)
	
	session, err := store.Get("")
	if err == nil {
		t.Errorf("Get() should fail with empty session ID")
	}
	if session != nil {
		t.Errorf("Get() should return nil session with empty session ID")
	}
	
	expectedMsg := "session ID cannot be empty"
	if err.Error() != expectedMsg {
		t.Errorf("Get() error = %v, want %v", err.Error(), expectedMsg)
	}
}

// TestSQLiteSessionStore_Delete_EmptySessionID tests with empty session ID
func TestSQLiteSessionStore_Delete_EmptySessionID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	store := NewSessionStore(db)
	
	err := store.Delete("")
	if err == nil {
		t.Errorf("Delete() should fail with empty session ID")
	}
	
	expectedMsg := "session ID cannot be empty"
	if err.Error() != expectedMsg {
		t.Errorf("Delete() error = %v, want %v", err.Error(), expectedMsg)
	}
}

// TestSQLiteSessionStore_SessionIDFormat tests session ID format
func TestSQLiteSessionStore_SessionIDFormat(t *testing.T) {
	// Test that generated session IDs have the expected format
	for i := 0; i < 10; i++ {
		id, err := generateSessionID()
		if err != nil {
			t.Fatalf("generateSessionID() failed: %v", err)
		}
		
		// Should be 64 characters long (32 bytes in hex)
		if len(id) != 64 {
			t.Errorf("Session ID length = %d, want 64", len(id))
		}
		
		// Should only contain lowercase hex characters
		if strings.ToLower(id) != id {
			t.Errorf("Session ID should be lowercase: %s", id)
		}
		
		// Should be valid hex
		if !isValidHex(id) {
			t.Errorf("Session ID is not valid hex: %s", id)
		}
	}
}

// TestSQLiteSessionStore_FullCRUD tests complete session lifecycle with real database
func TestSQLiteSessionStore_FullCRUD(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// First create a user to satisfy foreign key constraint
	userRepo := NewUserRepository(db)
	user := &models.User{
		Provider:   "github",
		ProviderID: "12345",
		Username:   "testuser",
		Email:      "test@example.com",
	}
	err := userRepo.Create(user)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	
	store := NewSessionStore(db)
	
	// Create a session
	session, err := store.Create(user.ID, time.Hour)
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}
	
	if session == nil {
		t.Fatalf("Create() returned nil session")
	}
	
	// Verify session properties
	if session.UserID != 1 {
		t.Errorf("UserID = %d, want 1", session.UserID)
	}
	
	if len(session.ID) != 64 {
		t.Errorf("Session ID length = %d, want 64", len(session.ID))
	}
	
	if session.ExpiresAt.Before(time.Now()) {
		t.Errorf("Session should not be expired immediately after creation")
	}
	
	// Get the session
	foundSession, err := store.Get(session.ID)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	
	if foundSession == nil {
		t.Fatalf("Get() returned nil session")
	}
	
	if foundSession.ID != session.ID {
		t.Errorf("Session ID = %v, want %v", foundSession.ID, session.ID)
	}
	
	if foundSession.UserID != session.UserID {
		t.Errorf("UserID = %v, want %v", foundSession.UserID, session.UserID)
	}
	
	// Delete the session
	err = store.Delete(session.ID)
	if err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}
	
	// Verify session is deleted
	deletedSession, err := store.Get(session.ID)
	if err != nil {
		t.Errorf("Get() should not return error for deleted session, got: %v", err)
	}
	if deletedSession != nil {
		t.Errorf("Get() should return nil for deleted session")
	}
}

// TestSQLiteSessionStore_Cleanup tests session cleanup functionality
func TestSQLiteSessionStore_Cleanup(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// First create a user to satisfy foreign key constraint
	userRepo := NewUserRepository(db)
	user := &models.User{
		Provider:   "github",
		ProviderID: "12345",
		Username:   "testuser",
		Email:      "test@example.com",
	}
	err := userRepo.Create(user)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	
	store := NewSessionStore(db)
	
	// Create an expired session (should fail)
	_, err = store.Create(user.ID, -time.Hour) // Already expired
	if err == nil {
		t.Errorf("Create() should fail with negative duration")
	}
	
	// Create a valid session with very short duration
	session, err := store.Create(user.ID, time.Millisecond)
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}
	
	// Wait for session to expire
	time.Sleep(10 * time.Millisecond)
	
	// Run cleanup
	err = store.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup() failed: %v", err)
	}
	
	// Verify expired session is cleaned up
	cleanedSession, err := store.Get(session.ID)
	if err != nil {
		t.Errorf("Get() should not return error for expired/cleaned session, got: %v", err)
	}
	if cleanedSession != nil {
		t.Errorf("Get() should return nil for expired/cleaned session")
	}
}