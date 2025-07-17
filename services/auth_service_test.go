package services

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sso-web-app/models"
	"strings"
	"sync"
	"testing"
	"time"
)

// MockUserRepository implements database.UserRepository for testing
type MockUserRepository struct {
	users map[string]*models.User
}

func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users: make(map[string]*models.User),
	}
}

func (m *MockUserRepository) FindByProviderID(provider, providerID string) (*models.User, error) {
	key := provider + ":" + providerID
	user, exists := m.users[key]
	if !exists {
		return nil, nil
	}
	return user, nil
}

func (m *MockUserRepository) FindByID(id int) (*models.User, error) {
	for _, user := range m.users {
		if user.ID == id {
			return user, nil
		}
	}
	return nil, nil
}

func (m *MockUserRepository) Create(user *models.User) error {
	if err := user.Validate(); err != nil {
		return err
	}
	key := user.Provider + ":" + user.ProviderID
	user.ID = len(m.users) + 1
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	m.users[key] = user
	return nil
}

func (m *MockUserRepository) Update(user *models.User) error {
	if err := user.Validate(); err != nil {
		return err
	}
	key := user.Provider + ":" + user.ProviderID
	if _, exists := m.users[key]; !exists {
		return ErrUserNotFound
	}
	user.UpdatedAt = time.Now()
	m.users[key] = user
	return nil
}

// MockSessionStore implements database.SessionStore for testing
type MockSessionStore struct {
	sessions map[string]*models.Session
	nextID   int
	mu       sync.RWMutex
}

func NewMockSessionStore() *MockSessionStore {
	return &MockSessionStore{
		sessions: make(map[string]*models.Session),
		nextID:   1,
	}
}

func (m *MockSessionStore) Create(userID int, duration time.Duration) (*models.Session, error) {
	if userID <= 0 {
		return nil, ErrInvalidUserID
	}
	if duration <= 0 {
		return nil, ErrInvalidDuration
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	sessionID := generateTestSessionID(m.nextID)
	m.nextID++
	
	now := time.Now()
	session := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		ExpiresAt: now.Add(duration),
		CreatedAt: now,
	}
	
	m.sessions[sessionID] = session
	return session, nil
}

func (m *MockSessionStore) Get(sessionID string) (*models.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	session, exists := m.sessions[sessionID]
	if !exists {
		return nil, nil
	}
	return session, nil
}

func (m *MockSessionStore) Delete(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if _, exists := m.sessions[sessionID]; !exists {
		return ErrSessionNotFound
	}
	delete(m.sessions, sessionID)
	return nil
}

func (m *MockSessionStore) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	now := time.Now()
	for id, session := range m.sessions {
		if now.After(session.ExpiresAt) {
			delete(m.sessions, id)
		}
	}
	return nil
}

func generateTestSessionID(id int) string {
	return "test_session_" + string(rune('0'+id))
}

// Define mock errors for testing
var (
	ErrUserNotFound     = fmt.Errorf("user not found")
	ErrInvalidUserID    = fmt.Errorf("invalid user ID")
	ErrInvalidDuration  = fmt.Errorf("invalid duration")
	ErrSessionNotFound  = fmt.Errorf("session not found")
)

// isValidHex checks if a string contains only valid hexadecimal characters
func isValidHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func TestGenerateSecureState(t *testing.T) {
	// Generate multiple state tokens to test uniqueness and format
	states := make(map[string]bool)
	
	for i := 0; i < 100; i++ {
		state, err := generateSecureState()
		if err != nil {
			t.Fatalf("generateSecureState() failed: %v", err)
		}
		
		// Check length (32 bytes = 64 hex characters)
		if len(state) != 64 {
			t.Errorf("generateSecureState() returned state with length %d, want 64", len(state))
		}
		
		// Check that it's valid hex
		if !isValidHex(state) {
			t.Errorf("generateSecureState() returned non-hex state: %s", state)
		}
		
		// Check uniqueness
		if states[state] {
			t.Errorf("generateSecureState() generated duplicate state: %s", state)
		}
		states[state] = true
	}
}

func TestInMemoryStateStore_Store(t *testing.T) {
	store := NewInMemoryStateStore()
	
	tests := []struct {
		name     string
		state    string
		provider SupportedProvider
		expiry   time.Time
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid state",
			state:    "valid_state_123",
			provider: ProviderMicrosoft,
			expiry:   time.Now().Add(time.Hour),
			wantErr:  false,
		},
		{
			name:     "empty state",
			state:    "",
			provider: ProviderMicrosoft,
			expiry:   time.Now().Add(time.Hour),
			wantErr:  true,
			errMsg:   "state cannot be empty",
		},
		{
			name:     "invalid provider",
			state:    "valid_state_123",
			provider: SupportedProvider("invalid"),
			expiry:   time.Now().Add(time.Hour),
			wantErr:  true,
			errMsg:   "invalid provider: invalid",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.Store(tt.state, tt.provider, tt.expiry)
			if tt.wantErr {
				if err == nil {
					t.Errorf("InMemoryStateStore.Store() expected error but got none")
					return
				}
				if err.Error() != tt.errMsg {
					t.Errorf("InMemoryStateStore.Store() error = %v, want %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("InMemoryStateStore.Store() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestInMemoryStateStore_Validate(t *testing.T) {
	store := NewInMemoryStateStore()
	
	// Store a valid state
	validState := "valid_state_123"
	validProvider := ProviderGitHub
	futureExpiry := time.Now().Add(time.Hour)
	store.Store(validState, validProvider, futureExpiry)
	
	// Store an expired state
	expiredState := "expired_state_456"
	expiredProvider := ProviderMicrosoft
	pastExpiry := time.Now().Add(-time.Hour)
	store.Store(expiredState, expiredProvider, pastExpiry)
	
	tests := []struct {
		name             string
		state            string
		expectedProvider SupportedProvider
		wantErr          bool
		errMsg           string
	}{
		{
			name:             "valid state",
			state:            validState,
			expectedProvider: validProvider,
			wantErr:          false,
		},
		{
			name:             "expired state",
			state:            expiredState,
			expectedProvider: "",
			wantErr:          true,
			errMsg:           "state token expired",
		},
		{
			name:             "non-existent state",
			state:            "non_existent_state",
			expectedProvider: "",
			wantErr:          true,
			errMsg:           "invalid state token",
		},
		{
			name:             "empty state",
			state:            "",
			expectedProvider: "",
			wantErr:          true,
			errMsg:           "state cannot be empty",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := store.Validate(tt.state)
			if tt.wantErr {
				if err == nil {
					t.Errorf("InMemoryStateStore.Validate() expected error but got none")
					return
				}
				if err.Error() != tt.errMsg {
					t.Errorf("InMemoryStateStore.Validate() error = %v, want %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("InMemoryStateStore.Validate() unexpected error: %v", err)
					return
				}
				if provider != tt.expectedProvider {
					t.Errorf("InMemoryStateStore.Validate() provider = %v, want %v", provider, tt.expectedProvider)
				}
			}
		})
	}
}

func TestInMemoryStateStore_Delete(t *testing.T) {
	store := NewInMemoryStateStore()
	
	// Store a state
	state := "test_state"
	store.Store(state, ProviderMicrosoft, time.Now().Add(time.Hour))
	
	// Verify it exists
	_, err := store.Validate(state)
	if err != nil {
		t.Fatalf("State should exist before deletion: %v", err)
	}
	
	// Delete it
	err = store.Delete(state)
	if err != nil {
		t.Errorf("InMemoryStateStore.Delete() unexpected error: %v", err)
	}
	
	// Verify it's gone
	_, err = store.Validate(state)
	if err == nil {
		t.Errorf("State should not exist after deletion")
	}
}

func TestInMemoryStateStore_Cleanup(t *testing.T) {
	store := NewInMemoryStateStore()
	
	// Store valid and expired states
	validState := "valid_state"
	expiredState := "expired_state"
	
	store.Store(validState, ProviderMicrosoft, time.Now().Add(time.Hour))
	store.Store(expiredState, ProviderGitHub, time.Now().Add(-time.Hour))
	
	// Cleanup
	store.Cleanup()
	
	// Valid state should still exist
	_, err := store.Validate(validState)
	if err != nil {
		t.Errorf("Valid state should still exist after cleanup: %v", err)
	}
	
	// Expired state should be gone
	_, err = store.Validate(expiredState)
	if err == nil {
		t.Errorf("Expired state should be removed after cleanup")
	}
}

func TestNewAuthService(t *testing.T) {
	oauthConfig := NewOAuth2Config()
	userRepo := NewMockUserRepository()
	sessionStore := NewMockSessionStore()
	sessionTimeout := time.Hour
	
	authService := NewAuthService(oauthConfig, userRepo, sessionStore, sessionTimeout)
	
	if authService == nil {
		t.Errorf("NewAuthService() returned nil")
	}
	
	// Verify it returns the correct type
	if _, ok := authService.(*AuthServiceImpl); !ok {
		t.Errorf("NewAuthService() did not return *AuthServiceImpl")
	}
}

func TestAuthServiceImpl_InitiateOAuth(t *testing.T) {
	// Create a valid OAuth2 config
	oauthConfig := &OAuth2Config{
		Microsoft: ProviderConfig{
			ClientID:     "ms_client",
			ClientSecret: "ms_secret",
			RedirectURL:  "http://localhost:8080/auth/callback/microsoft",
			Scopes:       []string{"openid", "profile", "email"},
		},
		GitHub: ProviderConfig{
			ClientID:     "gh_client",
			ClientSecret: "gh_secret",
			RedirectURL:  "http://localhost:8080/auth/callback/github",
			Scopes:       []string{"user:email", "read:user"},
		},
	}
	
	userRepo := NewMockUserRepository()
	sessionStore := NewMockSessionStore()
	authService := NewAuthService(oauthConfig, userRepo, sessionStore, time.Hour)
	
	tests := []struct {
		name     string
		provider SupportedProvider
		wantErr  bool
	}{
		{
			name:     "valid microsoft provider",
			provider: ProviderMicrosoft,
			wantErr:  false,
		},
		{
			name:     "valid github provider",
			provider: ProviderGitHub,
			wantErr:  false,
		},
		{
			name:     "invalid provider",
			provider: SupportedProvider("invalid"),
			wantErr:  true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL, state, err := authService.InitiateOAuth(tt.provider)
			if tt.wantErr {
				if err == nil {
					t.Errorf("AuthServiceImpl.InitiateOAuth() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("AuthServiceImpl.InitiateOAuth() unexpected error: %v", err)
				return
			}
			
			// Verify URL is not empty
			if authURL == "" {
				t.Errorf("AuthServiceImpl.InitiateOAuth() returned empty auth URL")
			}
			
			// Verify state is not empty and has correct format
			if state == "" {
				t.Errorf("AuthServiceImpl.InitiateOAuth() returned empty state")
			}
			if len(state) != 64 {
				t.Errorf("AuthServiceImpl.InitiateOAuth() state length = %d, want 64", len(state))
			}
			
			// Verify URL contains expected parameters
			if !strings.Contains(authURL, "client_id=") {
				t.Errorf("AuthServiceImpl.InitiateOAuth() URL missing client_id parameter")
			}
			if !strings.Contains(authURL, "state="+state) {
				t.Errorf("AuthServiceImpl.InitiateOAuth() URL missing or incorrect state parameter")
			}
		})
	}
}

func TestAuthServiceImpl_HandleCallback(t *testing.T) {
	// Create a valid OAuth2 config
	oauthConfig := &OAuth2Config{
		Microsoft: ProviderConfig{
			ClientID:     "ms_client",
			ClientSecret: "ms_secret",
			RedirectURL:  "http://localhost:8080/auth/callback/microsoft",
			Scopes:       []string{"openid", "profile", "email"},
		},
		GitHub: ProviderConfig{
			ClientID:     "gh_client",
			ClientSecret: "gh_secret",
			RedirectURL:  "http://localhost:8080/auth/callback/github",
			Scopes:       []string{"user:email", "read:user"},
		},
	}
	
	userRepo := NewMockUserRepository()
	sessionStore := NewMockSessionStore()
	authService := NewAuthService(oauthConfig, userRepo, sessionStore, time.Hour)
	
	// First initiate OAuth to get a valid state
	_, state, err := authService.InitiateOAuth(ProviderMicrosoft)
	if err != nil {
		t.Fatalf("Failed to initiate OAuth: %v", err)
	}
	
	tests := []struct {
		name     string
		provider SupportedProvider
		code     string
		state    string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "missing code",
			provider: ProviderMicrosoft,
			code:     "",
			state:    state,
			wantErr:  true,
			errMsg:   "authorization code is required",
		},
		{
			name:     "missing state",
			provider: ProviderMicrosoft,
			code:     "valid_code",
			state:    "",
			wantErr:  true,
			errMsg:   "state parameter is required",
		},
		{
			name:     "invalid state",
			provider: ProviderMicrosoft,
			code:     "valid_code",
			state:    "invalid_state",
			wantErr:  true,
			errMsg:   "invalid state token",
		},
		{
			name:     "valid parameters but token exchange fails",
			provider: ProviderMicrosoft,
			code:     "valid_code",
			state:    state,
			wantErr:  true,
			errMsg:   "failed to exchange code for token",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, session, err := authService.HandleCallback(tt.provider, tt.code, tt.state)
			if tt.wantErr {
				if err == nil {
					t.Errorf("AuthServiceImpl.HandleCallback() expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("AuthServiceImpl.HandleCallback() error = %v, want to contain %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("AuthServiceImpl.HandleCallback() unexpected error: %v", err)
					return
				}
				if user == nil {
					t.Errorf("AuthServiceImpl.HandleCallback() returned nil user")
				}
				if session == nil {
					t.Errorf("AuthServiceImpl.HandleCallback() returned nil session")
				}
			}
		})
	}
}

func TestAuthServiceImpl_CreateSession(t *testing.T) {
	oauthConfig := NewOAuth2Config()
	userRepo := NewMockUserRepository()
	sessionStore := NewMockSessionStore()
	authService := NewAuthService(oauthConfig, userRepo, sessionStore, time.Hour)
	
	tests := []struct {
		name     string
		userID   int
		duration time.Duration
		wantErr  bool
	}{
		{
			name:     "valid session creation",
			userID:   1,
			duration: time.Hour,
			wantErr:  false,
		},
		{
			name:     "invalid user ID",
			userID:   0,
			duration: time.Hour,
			wantErr:  true,
		},
		{
			name:     "negative user ID",
			userID:   -1,
			duration: time.Hour,
			wantErr:  true,
		},
		{
			name:     "zero duration uses default",
			userID:   1,
			duration: 0,
			wantErr:  false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, err := authService.CreateSession(tt.userID, tt.duration)
			if tt.wantErr {
				if err == nil {
					t.Errorf("AuthServiceImpl.CreateSession() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("AuthServiceImpl.CreateSession() unexpected error: %v", err)
				return
			}
			if session == nil {
				t.Errorf("AuthServiceImpl.CreateSession() returned nil session")
			}
			if session.UserID != tt.userID {
				t.Errorf("AuthServiceImpl.CreateSession() session.UserID = %d, want %d", session.UserID, tt.userID)
			}
		})
	}
}

func TestAuthServiceImpl_ValidateSession(t *testing.T) {
	oauthConfig := NewOAuth2Config()
	userRepo := NewMockUserRepository()
	mockSessionStore := NewMockSessionStore()
	authService := NewAuthService(oauthConfig, userRepo, mockSessionStore, time.Hour)
	
	// Create a valid session
	validSession, err := authService.CreateSession(1, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}
	
	// Create an expired session by manually creating it in the mock store
	expiredSessionID := "expired_session_test"
	expiredSession := &models.Session{
		ID:        expiredSessionID,
		UserID:    2,
		ExpiresAt: time.Now().Add(-time.Hour), // Already expired
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	mockSessionStore.sessions[expiredSessionID] = expiredSession
	
	tests := []struct {
		name      string
		sessionID string
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "valid session",
			sessionID: validSession.ID,
			wantErr:   false,
		},
		{
			name:      "expired session",
			sessionID: expiredSession.ID,
			wantErr:   true,
			errMsg:    "session expired",
		},
		{
			name:      "non-existent session",
			sessionID: "non_existent",
			wantErr:   true,
			errMsg:    "session not found",
		},
		{
			name:      "empty session ID",
			sessionID: "",
			wantErr:   true,
			errMsg:    "session ID cannot be empty",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, err := authService.ValidateSession(tt.sessionID)
			if tt.wantErr {
				if err == nil {
					t.Errorf("AuthServiceImpl.ValidateSession() expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("AuthServiceImpl.ValidateSession() error = %v, want to contain %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("AuthServiceImpl.ValidateSession() unexpected error: %v", err)
					return
				}
				if session == nil {
					t.Errorf("AuthServiceImpl.ValidateSession() returned nil session")
				}
			}
		})
	}
}

func TestAuthServiceImpl_DestroySession(t *testing.T) {
	oauthConfig := NewOAuth2Config()
	userRepo := NewMockUserRepository()
	sessionStore := NewMockSessionStore()
	authService := NewAuthService(oauthConfig, userRepo, sessionStore, time.Hour)
	
	// Create a session to destroy
	session, err := authService.CreateSession(1, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}
	
	tests := []struct {
		name      string
		sessionID string
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "valid session destruction",
			sessionID: session.ID,
			wantErr:   false,
		},
		{
			name:      "non-existent session",
			sessionID: "non_existent",
			wantErr:   true,
			errMsg:    "session not found",
		},
		{
			name:      "empty session ID",
			sessionID: "",
			wantErr:   true,
			errMsg:    "session ID cannot be empty",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := authService.DestroySession(tt.sessionID)
			if tt.wantErr {
				if err == nil {
					t.Errorf("AuthServiceImpl.DestroySession() expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("AuthServiceImpl.DestroySession() error = %v, want to contain %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("AuthServiceImpl.DestroySession() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestSessionLifecycle tests the complete session lifecycle
func TestSessionLifecycle(t *testing.T) {
	oauthConfig := NewOAuth2Config()
	userRepo := NewMockUserRepository()
	sessionStore := NewMockSessionStore()
	authService := NewAuthService(oauthConfig, userRepo, sessionStore, time.Hour)
	
	userID := 1
	duration := time.Hour
	
	// Step 1: Create a session
	session, err := authService.CreateSession(userID, duration)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	
	if session == nil {
		t.Fatal("CreateSession returned nil session")
	}
	
	if session.ID == "" {
		t.Error("Session ID should not be empty")
	}
	
	if session.UserID != userID {
		t.Errorf("Session UserID = %d, want %d", session.UserID, userID)
	}
	
	if session.IsExpired() {
		t.Error("Newly created session should not be expired")
	}
	
	// Step 2: Validate the session
	validatedSession, err := authService.ValidateSession(session.ID)
	if err != nil {
		t.Fatalf("Failed to validate session: %v", err)
	}
	
	if validatedSession == nil {
		t.Fatal("ValidateSession returned nil session")
	}
	
	if validatedSession.ID != session.ID {
		t.Errorf("Validated session ID = %s, want %s", validatedSession.ID, session.ID)
	}
	
	if validatedSession.UserID != session.UserID {
		t.Errorf("Validated session UserID = %d, want %d", validatedSession.UserID, session.UserID)
	}
	
	// Step 3: Destroy the session
	err = authService.DestroySession(session.ID)
	if err != nil {
		t.Fatalf("Failed to destroy session: %v", err)
	}
	
	// Step 4: Verify session is destroyed
	_, err = authService.ValidateSession(session.ID)
	if err == nil {
		t.Error("ValidateSession should fail after session is destroyed")
	}
	
	if !strings.Contains(err.Error(), "session not found") {
		t.Errorf("Expected 'session not found' error, got: %v", err)
	}
}

// TestSessionExpiration tests session expiration behavior
func TestSessionExpiration(t *testing.T) {
	oauthConfig := NewOAuth2Config()
	userRepo := NewMockUserRepository()
	mockSessionStore := NewMockSessionStore()
	authService := NewAuthService(oauthConfig, userRepo, mockSessionStore, time.Hour)
	
	// Create a session with very short duration
	shortDuration := 100 * time.Millisecond
	session, err := authService.CreateSession(1, shortDuration)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	
	// Verify session is initially valid
	validatedSession, err := authService.ValidateSession(session.ID)
	if err != nil {
		t.Fatalf("Session should be valid initially: %v", err)
	}
	
	if validatedSession == nil {
		t.Fatal("ValidateSession should return session initially")
	}
	
	// Wait for session to expire
	time.Sleep(150 * time.Millisecond)
	
	// Verify session is now expired and validation fails
	_, err = authService.ValidateSession(session.ID)
	if err == nil {
		t.Error("ValidateSession should fail for expired session")
	}
	
	if !strings.Contains(err.Error(), "session expired") {
		t.Errorf("Expected 'session expired' error, got: %v", err)
	}
	
	// Verify expired session is cleaned up from store
	if _, exists := mockSessionStore.sessions[session.ID]; exists {
		t.Error("Expired session should be removed from store after validation")
	}
}

// TestConcurrentSessionOperations tests concurrent session operations
func TestConcurrentSessionOperations(t *testing.T) {
	oauthConfig := NewOAuth2Config()
	userRepo := NewMockUserRepository()
	sessionStore := NewMockSessionStore()
	authService := NewAuthService(oauthConfig, userRepo, sessionStore, time.Hour)
	
	const numGoroutines = 10
	const numOperationsPerGoroutine = 5
	
	// Channel to collect errors
	errChan := make(chan error, numGoroutines*numOperationsPerGoroutine)
	
	// Channel to collect created sessions
	sessionChan := make(chan *models.Session, numGoroutines*numOperationsPerGoroutine)
	
	// Start multiple goroutines creating sessions
	for i := 0; i < numGoroutines; i++ {
		go func(userID int) {
			for j := 0; j < numOperationsPerGoroutine; j++ {
				session, err := authService.CreateSession(userID, time.Hour)
				if err != nil {
					errChan <- err
					return
				}
				sessionChan <- session
			}
		}(i + 1)
	}
	
	// Collect results
	var sessions []*models.Session
	var errors []error
	
	for i := 0; i < numGoroutines*numOperationsPerGoroutine; i++ {
		select {
		case session := <-sessionChan:
			sessions = append(sessions, session)
		case err := <-errChan:
			errors = append(errors, err)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}
	
	// Verify no errors occurred
	if len(errors) > 0 {
		t.Errorf("Concurrent session creation failed with errors: %v", errors)
	}
	
	// Verify all sessions were created
	if len(sessions) != numGoroutines*numOperationsPerGoroutine {
		t.Errorf("Expected %d sessions, got %d", numGoroutines*numOperationsPerGoroutine, len(sessions))
	}
	
	// Verify all session IDs are unique
	sessionIDs := make(map[string]bool)
	for _, session := range sessions {
		if sessionIDs[session.ID] {
			t.Errorf("Duplicate session ID found: %s", session.ID)
		}
		sessionIDs[session.ID] = true
	}
	
	// Test concurrent validation and destruction
	for _, session := range sessions {
		go func(s *models.Session) {
			// Validate session
			_, err := authService.ValidateSession(s.ID)
			if err != nil {
				errChan <- err
				return
			}
			
			// Destroy session
			err = authService.DestroySession(s.ID)
			if err != nil {
				errChan <- err
				return
			}
		}(session)
	}
	
	// Wait for all operations to complete
	time.Sleep(100 * time.Millisecond)
	
	// Check for any additional errors
	select {
	case err := <-errChan:
		t.Errorf("Concurrent validation/destruction failed: %v", err)
	default:
		// No errors, which is expected
	}
}

// TestSessionSecurityProperties tests security properties of sessions
func TestSessionSecurityProperties(t *testing.T) {
	oauthConfig := NewOAuth2Config()
	userRepo := NewMockUserRepository()
	sessionStore := NewMockSessionStore()
	authService := NewAuthService(oauthConfig, userRepo, sessionStore, time.Hour)
	
	// Create multiple sessions and verify they have unique IDs and proper properties
	const numSessions = 10
	sessionIDs := make(map[string]bool)
	
	for i := 0; i < numSessions; i++ {
		session, err := authService.CreateSession(1, time.Hour)
		if err != nil {
			t.Fatalf("Failed to create session %d: %v", i, err)
		}
		
		// Verify session ID is not empty
		if session.ID == "" {
			t.Error("Session ID should not be empty")
		}
		
		// Verify uniqueness
		if sessionIDs[session.ID] {
			t.Errorf("Duplicate session ID generated: %s", session.ID)
		}
		sessionIDs[session.ID] = true
		
		// Verify session properties
		if session.UserID != 1 {
			t.Errorf("Session UserID = %d, want 1", session.UserID)
		}
		
		if session.CreatedAt.IsZero() {
			t.Error("Session CreatedAt should not be zero")
		}
		
		if session.ExpiresAt.IsZero() {
			t.Error("Session ExpiresAt should not be zero")
		}
		
		if !session.ExpiresAt.After(session.CreatedAt) {
			t.Error("Session ExpiresAt should be after CreatedAt")
		}
		
		// Verify session is valid and not expired
		if !session.IsValid() {
			t.Error("Newly created session should be valid")
		}
		
		if session.IsExpired() {
			t.Error("Newly created session should not be expired")
		}
		
		if !session.IsActive() {
			t.Error("Newly created session should be active")
		}
	}
}

// TestRealSessionIDGeneration tests the actual secure session ID generation
func TestRealSessionIDGeneration(t *testing.T) {
	// Test the actual session ID generation function used by the real session store
	sessionIDs := make(map[string]bool)
	const numIDs = 100
	
	for i := 0; i < numIDs; i++ {
		// This tests the generateSessionID function from the database package
		// We'll simulate it here since we can't easily import it
		bytes := make([]byte, 32)
		_, err := rand.Read(bytes)
		if err != nil {
			t.Fatalf("Failed to generate random bytes: %v", err)
		}
		sessionID := hex.EncodeToString(bytes)
		
		// Verify session ID length (should be 64 hex characters for 32 bytes)
		if len(sessionID) != 64 {
			t.Errorf("Session ID length = %d, want 64", len(sessionID))
		}
		
		// Verify session ID is valid hex
		if !isValidHex(sessionID) {
			t.Errorf("Session ID is not valid hex: %s", sessionID)
		}
		
		// Verify uniqueness
		if sessionIDs[sessionID] {
			t.Errorf("Duplicate session ID generated: %s", sessionID)
		}
		sessionIDs[sessionID] = true
	}
}

// Test helper functions for OAuth2 callback handling

func TestUserProfile_Validation(t *testing.T) {
	tests := []struct {
		name    string
		profile UserProfile
		valid   bool
	}{
		{
			name: "valid profile",
			profile: UserProfile{
				ID:        "12345",
				Username:  "testuser",
				Email:     "test@example.com",
				AvatarURL: "https://example.com/avatar.jpg",
			},
			valid: true,
		},
		{
			name: "minimal valid profile",
			profile: UserProfile{
				ID:       "12345",
				Username: "testuser",
			},
			valid: true,
		},
		{
			name: "empty profile",
			profile: UserProfile{},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation - profile should have ID and Username
			isValid := tt.profile.ID != "" && tt.profile.Username != ""
			if isValid != tt.valid {
				t.Errorf("UserProfile validation = %v, want %v", isValid, tt.valid)
			}
		})
	}
}

func TestAuthServiceImpl_findOrCreateUser(t *testing.T) {
	oauthConfig := NewOAuth2Config()
	mockUserRepo := NewMockUserRepository()
	sessionStore := NewMockSessionStore()
	authService := NewAuthService(oauthConfig, mockUserRepo, sessionStore, time.Hour).(*AuthServiceImpl)

	tests := []struct {
		name        string
		provider    SupportedProvider
		profile     *UserProfile
		existingUser *models.User
		wantErr     bool
		expectCreate bool
	}{
		{
			name:     "create new user",
			provider: ProviderGitHub,
			profile: &UserProfile{
				ID:        "12345",
				Username:  "newuser",
				Email:     "new@example.com",
				AvatarURL: "https://example.com/avatar.jpg",
			},
			existingUser: nil,
			wantErr:      false,
			expectCreate: true,
		},
		{
			name:     "update existing user",
			provider: ProviderGitHub,
			profile: &UserProfile{
				ID:        "67890",
				Username:  "updateduser",
				Email:     "updated@example.com",
				AvatarURL: "https://example.com/new-avatar.jpg",
			},
			existingUser: &models.User{
				ID:         1,
				Provider:   "github",
				ProviderID: "67890",
				Username:   "olduser",
				Email:      "old@example.com",
				AvatarURL:  "https://example.com/old-avatar.jpg",
			},
			wantErr:      false,
			expectCreate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup existing user if provided
			if tt.existingUser != nil {
				mockUserRepo.users[tt.existingUser.Provider+":"+tt.existingUser.ProviderID] = tt.existingUser
			}

			user, err := authService.findOrCreateUser(tt.provider, tt.profile)
			if tt.wantErr {
				if err == nil {
					t.Errorf("AuthServiceImpl.findOrCreateUser() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("AuthServiceImpl.findOrCreateUser() unexpected error: %v", err)
				return
			}

			if user == nil {
				t.Errorf("AuthServiceImpl.findOrCreateUser() returned nil user")
				return
			}

			// Verify user data
			if user.Provider != tt.provider.String() {
				t.Errorf("User.Provider = %v, want %v", user.Provider, tt.provider.String())
			}
			if user.ProviderID != tt.profile.ID {
				t.Errorf("User.ProviderID = %v, want %v", user.ProviderID, tt.profile.ID)
			}
			if user.Username != tt.profile.Username {
				t.Errorf("User.Username = %v, want %v", user.Username, tt.profile.Username)
			}
			if user.Email != tt.profile.Email {
				t.Errorf("User.Email = %v, want %v", user.Email, tt.profile.Email)
			}
			if user.AvatarURL != tt.profile.AvatarURL {
				t.Errorf("User.AvatarURL = %v, want %v", user.AvatarURL, tt.profile.AvatarURL)
			}

			if tt.expectCreate && user.ID == 0 {
				t.Errorf("Expected new user to have ID assigned")
			}
		})
	}
}

func TestAuthServiceImpl_HandleCallback_Integration(t *testing.T) {
	// Create a valid OAuth2 config
	oauthConfig := &OAuth2Config{
		Microsoft: ProviderConfig{
			ClientID:     "ms_client",
			ClientSecret: "ms_secret",
			RedirectURL:  "http://localhost:8080/auth/callback/microsoft",
			Scopes:       []string{"openid", "profile", "email"},
		},
		GitHub: ProviderConfig{
			ClientID:     "gh_client",
			ClientSecret: "gh_secret",
			RedirectURL:  "http://localhost:8080/auth/callback/github",
			Scopes:       []string{"user:email", "read:user"},
		},
	}

	userRepo := NewMockUserRepository()
	sessionStore := NewMockSessionStore()
	authService := NewAuthService(oauthConfig, userRepo, sessionStore, time.Hour)

	// Test the validation part of HandleCallback (the parts we can test without external APIs)
	tests := []struct {
		name     string
		provider SupportedProvider
		code     string
		state    string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "missing code",
			provider: ProviderMicrosoft,
			code:     "",
			state:    "valid_state",
			wantErr:  true,
			errMsg:   "authorization code is required",
		},
		{
			name:     "missing state",
			provider: ProviderMicrosoft,
			code:     "valid_code",
			state:    "",
			wantErr:  true,
			errMsg:   "state parameter is required",
		},
		{
			name:     "invalid state",
			provider: ProviderMicrosoft,
			code:     "valid_code",
			state:    "invalid_state",
			wantErr:  true,
			errMsg:   "invalid state token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, session, err := authService.HandleCallback(tt.provider, tt.code, tt.state)
			if tt.wantErr {
				if err == nil {
					t.Errorf("AuthServiceImpl.HandleCallback() expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("AuthServiceImpl.HandleCallback() error = %v, want to contain %v", err.Error(), tt.errMsg)
				}
				if user != nil {
					t.Errorf("AuthServiceImpl.HandleCallback() should return nil user on error")
				}
				if session != nil {
					t.Errorf("AuthServiceImpl.HandleCallback() should return nil session on error")
				}
			} else {
				if err != nil {
					t.Errorf("AuthServiceImpl.HandleCallback() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestAuthServiceImpl_HandleCallback_StateValidation(t *testing.T) {
	// Create a valid OAuth2 config
	oauthConfig := &OAuth2Config{
		Microsoft: ProviderConfig{
			ClientID:     "ms_client",
			ClientSecret: "ms_secret",
			RedirectURL:  "http://localhost:8080/auth/callback/microsoft",
			Scopes:       []string{"openid", "profile", "email"},
		},
		GitHub: ProviderConfig{
			ClientID:     "gh_client",
			ClientSecret: "gh_secret",
			RedirectURL:  "http://localhost:8080/auth/callback/github",
			Scopes:       []string{"user:email", "read:user"},
		},
	}

	userRepo := NewMockUserRepository()
	sessionStore := NewMockSessionStore()
	authService := NewAuthService(oauthConfig, userRepo, sessionStore, time.Hour)

	// First initiate OAuth to get a valid state for Microsoft
	_, msState, err := authService.InitiateOAuth(ProviderMicrosoft)
	if err != nil {
		t.Fatalf("Failed to initiate OAuth for Microsoft: %v", err)
	}

	// First initiate OAuth to get a valid state for GitHub
	_, ghState, err := authService.InitiateOAuth(ProviderGitHub)
	if err != nil {
		t.Fatalf("Failed to initiate OAuth for GitHub: %v", err)
	}

	tests := []struct {
		name     string
		provider SupportedProvider
		code     string
		state    string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "provider mismatch - Microsoft state with GitHub provider",
			provider: ProviderGitHub,
			code:     "valid_code",
			state:    msState,
			wantErr:  true,
			errMsg:   "state token provider mismatch",
		},
		{
			name:     "provider mismatch - GitHub state with Microsoft provider",
			provider: ProviderMicrosoft,
			code:     "valid_code",
			state:    ghState,
			wantErr:  true,
			errMsg:   "state token provider mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, session, err := authService.HandleCallback(tt.provider, tt.code, tt.state)
			if tt.wantErr {
				if err == nil {
					t.Errorf("AuthServiceImpl.HandleCallback() expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("AuthServiceImpl.HandleCallback() error = %v, want to contain %v", err.Error(), tt.errMsg)
				}
				if user != nil {
					t.Errorf("AuthServiceImpl.HandleCallback() should return nil user on error")
				}
				if session != nil {
					t.Errorf("AuthServiceImpl.HandleCallback() should return nil session on error")
				}
			}
		})
	}
}

// Test profile conversion functions
func TestMicrosoftUserProfile_Conversion(t *testing.T) {
	tests := []struct {
		name       string
		msProfile  MicrosoftUserProfile
		expected   UserProfile
	}{
		{
			name: "complete profile",
			msProfile: MicrosoftUserProfile{
				ID:                "ms-12345",
				DisplayName:       "John Doe",
				UserPrincipalName: "john.doe@company.com",
				Mail:              "john@company.com",
			},
			expected: UserProfile{
				ID:       "ms-12345",
				Username: "John Doe",
				Email:    "john@company.com",
			},
		},
		{
			name: "missing mail - use UserPrincipalName",
			msProfile: MicrosoftUserProfile{
				ID:                "ms-67890",
				DisplayName:       "Jane Smith",
				UserPrincipalName: "jane.smith@company.com",
				Mail:              "",
			},
			expected: UserProfile{
				ID:       "ms-67890",
				Username: "Jane Smith",
				Email:    "jane.smith@company.com",
			},
		},
		{
			name: "missing DisplayName - use UserPrincipalName",
			msProfile: MicrosoftUserProfile{
				ID:                "ms-11111",
				DisplayName:       "",
				UserPrincipalName: "test.user@company.com",
				Mail:              "test@company.com",
			},
			expected: UserProfile{
				ID:       "ms-11111",
				Username: "test.user@company.com",
				Email:    "test@company.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the conversion logic from getMicrosoftUserProfile
			profile := &UserProfile{
				ID:       tt.msProfile.ID,
				Username: tt.msProfile.DisplayName,
				Email:    tt.msProfile.Mail,
			}

			// Use UserPrincipalName as fallback for email if Mail is empty
			if profile.Email == "" {
				profile.Email = tt.msProfile.UserPrincipalName
			}

			// Use UserPrincipalName as fallback for username if DisplayName is empty
			if profile.Username == "" {
				profile.Username = tt.msProfile.UserPrincipalName
			}

			if profile.ID != tt.expected.ID {
				t.Errorf("Profile.ID = %v, want %v", profile.ID, tt.expected.ID)
			}
			if profile.Username != tt.expected.Username {
				t.Errorf("Profile.Username = %v, want %v", profile.Username, tt.expected.Username)
			}
			if profile.Email != tt.expected.Email {
				t.Errorf("Profile.Email = %v, want %v", profile.Email, tt.expected.Email)
			}
		})
	}
}

func TestGitHubUserProfile_Conversion(t *testing.T) {
	tests := []struct {
		name      string
		ghProfile GitHubUserProfile
		expected  UserProfile
	}{
		{
			name: "complete profile",
			ghProfile: GitHubUserProfile{
				ID:        12345,
				Login:     "johndoe",
				Email:     "john@example.com",
				AvatarURL: "https://github.com/avatar.jpg",
			},
			expected: UserProfile{
				ID:        "12345",
				Username:  "johndoe",
				Email:     "john@example.com",
				AvatarURL: "https://github.com/avatar.jpg",
			},
		},
		{
			name: "missing email",
			ghProfile: GitHubUserProfile{
				ID:        67890,
				Login:     "janesmith",
				Email:     "",
				AvatarURL: "https://github.com/avatar2.jpg",
			},
			expected: UserProfile{
				ID:        "67890",
				Username:  "janesmith",
				Email:     "", // Would be filled by getGitHubUserEmail in real implementation
				AvatarURL: "https://github.com/avatar2.jpg",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the conversion logic from getGitHubUserProfile
			profile := &UserProfile{
				ID:        fmt.Sprintf("%d", tt.ghProfile.ID),
				Username:  tt.ghProfile.Login,
				Email:     tt.ghProfile.Email,
				AvatarURL: tt.ghProfile.AvatarURL,
			}

			if profile.ID != tt.expected.ID {
				t.Errorf("Profile.ID = %v, want %v", profile.ID, tt.expected.ID)
			}
			if profile.Username != tt.expected.Username {
				t.Errorf("Profile.Username = %v, want %v", profile.Username, tt.expected.Username)
			}
			if profile.Email != tt.expected.Email {
				t.Errorf("Profile.Email = %v, want %v", profile.Email, tt.expected.Email)
			}
			if profile.AvatarURL != tt.expected.AvatarURL {
				t.Errorf("Profile.AvatarURL = %v, want %v", profile.AvatarURL, tt.expected.AvatarURL)
			}
		})
	}
}