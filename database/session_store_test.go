//go:build !cgo
// +build !cgo

package database

import (
	"strings"
	"testing"
	"time"
)

// TestNewSessionStore tests the constructor
func TestNewSessionStore(t *testing.T) {
	db := &DB{DB: nil}
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

// TestSQLiteSessionStore_Create_NilDB tests with nil database
func TestSQLiteSessionStore_Create_NilDB(t *testing.T) {
	store := &SQLiteSessionStore{db: nil}
	
	session, err := store.Create(1, time.Hour)
	if err == nil {
		t.Errorf("Create() should fail with nil database")
	}
	if session != nil {
		t.Errorf("Create() should return nil session with nil database")
	}
}

// TestSQLiteSessionStore_Create_InvalidUserID tests with invalid user ID
func TestSQLiteSessionStore_Create_InvalidUserID(t *testing.T) {
	db := &DB{DB: nil}
	store := &SQLiteSessionStore{db: db}
	
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
	db := &DB{DB: nil}
	store := &SQLiteSessionStore{db: db}
	
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

// TestSQLiteSessionStore_Get_NilDB tests with nil database
func TestSQLiteSessionStore_Get_NilDB(t *testing.T) {
	store := &SQLiteSessionStore{db: nil}
	
	session, err := store.Get("session123")
	if err == nil {
		t.Errorf("Get() should fail with nil database")
	}
	if session != nil {
		t.Errorf("Get() should return nil session with nil database")
	}
}

// TestSQLiteSessionStore_Get_EmptySessionID tests with empty session ID
func TestSQLiteSessionStore_Get_EmptySessionID(t *testing.T) {
	db := &DB{DB: nil}
	store := &SQLiteSessionStore{db: db}
	
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

// TestSQLiteSessionStore_Delete_NilDB tests with nil database
func TestSQLiteSessionStore_Delete_NilDB(t *testing.T) {
	store := &SQLiteSessionStore{db: nil}
	
	err := store.Delete("session123")
	if err == nil {
		t.Errorf("Delete() should fail with nil database")
	}
}

// TestSQLiteSessionStore_Delete_EmptySessionID tests with empty session ID
func TestSQLiteSessionStore_Delete_EmptySessionID(t *testing.T) {
	db := &DB{DB: nil}
	store := &SQLiteSessionStore{db: db}
	
	err := store.Delete("")
	if err == nil {
		t.Errorf("Delete() should fail with empty session ID")
	}
	
	expectedMsg := "session ID cannot be empty"
	if err.Error() != expectedMsg {
		t.Errorf("Delete() error = %v, want %v", err.Error(), expectedMsg)
	}
}

// TestSQLiteSessionStore_Cleanup_NilDB tests with nil database
func TestSQLiteSessionStore_Cleanup_NilDB(t *testing.T) {
	store := &SQLiteSessionStore{db: nil}
	
	err := store.Cleanup()
	if err == nil {
		t.Errorf("Cleanup() should fail with nil database")
	}
}

// TestSQLiteSessionStore_CleanupExpiredSessions tests the convenience method
func TestSQLiteSessionStore_CleanupExpiredSessions(t *testing.T) {
	db := &DB{DB: nil}
	store := &SQLiteSessionStore{db: db}
	
	err := store.CleanupExpiredSessions()
	if err == nil {
		t.Errorf("CleanupExpiredSessions() should fail with nil database")
	}
}

// TestSQLiteSessionStore_GetActiveSessionsCount_NilDB tests with nil database
func TestSQLiteSessionStore_GetActiveSessionsCount_NilDB(t *testing.T) {
	store := &SQLiteSessionStore{db: nil}
	
	count, err := store.GetActiveSessionsCount()
	if err == nil {
		t.Errorf("GetActiveSessionsCount() should fail with nil database")
	}
	if count != 0 {
		t.Errorf("GetActiveSessionsCount() should return 0 with nil database")
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

// TestSQLiteSessionStore_ValidationLogic tests validation logic without database
func TestSQLiteSessionStore_ValidationLogic(t *testing.T) {
	db := &DB{DB: nil}
	store := &SQLiteSessionStore{db: db}
	
	// Test that validation happens before database operations
	tests := []struct {
		name     string
		userID   int
		duration time.Duration
		wantErr  string
	}{
		{
			name:     "valid parameters",
			userID:   1,
			duration: time.Hour,
			wantErr:  "database connection is nil", // Should fail at DB level, not validation
		},
		{
			name:     "invalid user ID",
			userID:   0,
			duration: time.Hour,
			wantErr:  "user ID must be positive",
		},
		{
			name:     "invalid duration",
			userID:   1,
			duration: 0,
			wantErr:  "session duration must be positive",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.Create(tt.userID, tt.duration)
			if err == nil {
				t.Errorf("Create() should fail")
				return
			}
			
			if err.Error() != tt.wantErr {
				t.Errorf("Create() error = %v, want %v", err.Error(), tt.wantErr)
			}
		})
	}
}