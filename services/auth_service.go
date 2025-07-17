package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sso-web-app/models"
	"time"

	"golang.org/x/oauth2"
)

// UserRepository defines the interface for user data operations
type UserRepository interface {
	FindByProviderID(provider, providerID string) (*models.User, error)
	FindByID(id int) (*models.User, error)
	Create(user *models.User) error
	Update(user *models.User) error
}

// SessionStore defines the interface for session data operations
type SessionStore interface {
	Create(userID int, duration time.Duration) (*models.Session, error)
	Get(sessionID string) (*models.Session, error)
	Delete(sessionID string) error
	Cleanup() error
}

// AuthService defines the interface for authentication operations
type AuthService interface {
	InitiateOAuth(provider SupportedProvider) (string, string, error)
	HandleCallback(provider SupportedProvider, code, state string) (*models.User, *models.Session, error)
	CreateSession(userID int, duration time.Duration) (*models.Session, error)
	ValidateSession(sessionID string) (*models.Session, error)
	DestroySession(sessionID string) error
}

// AuthServiceImpl implements the AuthService interface
type AuthServiceImpl struct {
	oauthConfig    *OAuth2Config
	userRepo       UserRepository
	sessionStore   SessionStore
	stateStore     StateStore // For storing OAuth state tokens
	sessionTimeout time.Duration
}

// StateStore defines the interface for storing OAuth state tokens
type StateStore interface {
	Store(state string, provider SupportedProvider, expiry time.Time) error
	Validate(state string) (SupportedProvider, error)
	Delete(state string) error
}

// InMemoryStateStore is a simple in-memory implementation of StateStore
type InMemoryStateStore struct {
	states map[string]stateEntry
}

type stateEntry struct {
	provider SupportedProvider
	expiry   time.Time
}

// NewInMemoryStateStore creates a new in-memory state store
func NewInMemoryStateStore() *InMemoryStateStore {
	return &InMemoryStateStore{
		states: make(map[string]stateEntry),
	}
}

// Store stores a state token with its associated provider and expiry
func (s *InMemoryStateStore) Store(state string, provider SupportedProvider, expiry time.Time) error {
	if state == "" {
		return fmt.Errorf("state cannot be empty")
	}
	if !provider.IsValid() {
		return fmt.Errorf("invalid provider: %s", provider)
	}
	
	s.states[state] = stateEntry{
		provider: provider,
		expiry:   expiry,
	}
	return nil
}

// Validate validates a state token and returns the associated provider
func (s *InMemoryStateStore) Validate(state string) (SupportedProvider, error) {
	if state == "" {
		return "", fmt.Errorf("state cannot be empty")
	}
	
	entry, exists := s.states[state]
	if !exists {
		return "", fmt.Errorf("invalid state token")
	}
	
	if time.Now().After(entry.expiry) {
		delete(s.states, state)
		return "", fmt.Errorf("state token expired")
	}
	
	return entry.provider, nil
}

// Delete removes a state token from the store
func (s *InMemoryStateStore) Delete(state string) error {
	delete(s.states, state)
	return nil
}

// Cleanup removes expired state tokens
func (s *InMemoryStateStore) Cleanup() {
	now := time.Now()
	for state, entry := range s.states {
		if now.After(entry.expiry) {
			delete(s.states, state)
		}
	}
}

// NewAuthService creates a new AuthService instance
func NewAuthService(
	oauthConfig *OAuth2Config,
	userRepo UserRepository,
	sessionStore SessionStore,
	sessionTimeout time.Duration,
) AuthService {
	return &AuthServiceImpl{
		oauthConfig:    oauthConfig,
		userRepo:       userRepo,
		sessionStore:   sessionStore,
		stateStore:     NewInMemoryStateStore(),
		sessionTimeout: sessionTimeout,
	}
}

// generateSecureState generates a cryptographically secure random state token
func generateSecureState() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// InitiateOAuth initiates the OAuth2 flow and returns the authorization URL and state
func (a *AuthServiceImpl) InitiateOAuth(provider SupportedProvider) (string, string, error) {
	if !provider.IsValid() {
		return "", "", fmt.Errorf("unsupported provider: %s", provider)
	}
	
	// Get OAuth2 configuration for the provider
	oauth2Config, err := a.oauthConfig.GetOAuth2Config(provider)
	if err != nil {
		return "", "", fmt.Errorf("failed to get OAuth2 config: %w", err)
	}
	
	// Generate secure state token for CSRF protection
	state, err := generateSecureState()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate state token: %w", err)
	}
	
	// Store the state token with expiry (10 minutes)
	expiry := time.Now().Add(10 * time.Minute)
	if err := a.stateStore.Store(state, provider, expiry); err != nil {
		return "", "", fmt.Errorf("failed to store state token: %w", err)
	}
	
	// Generate authorization URL
	authURL := oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	
	return authURL, state, nil
}

// HandleCallback handles the OAuth2 callback and returns the user and session
func (a *AuthServiceImpl) HandleCallback(provider SupportedProvider, code, state string) (*models.User, *models.Session, error) {
	if code == "" {
		return nil, nil, fmt.Errorf("authorization code is required")
	}
	
	if state == "" {
		return nil, nil, fmt.Errorf("state parameter is required")
	}
	
	// Validate state token
	storedProvider, err := a.stateStore.Validate(state)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid state token: %w", err)
	}
	
	if storedProvider != provider {
		return nil, nil, fmt.Errorf("state token provider mismatch")
	}
	
	// Clean up the state token
	a.stateStore.Delete(state)
	
	// Get OAuth2 configuration for the provider
	oauth2Config, err := a.oauthConfig.GetOAuth2Config(provider)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get OAuth2 config: %w", err)
	}
	
	// Exchange authorization code for access token
	token, err := oauth2Config.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	
	// Retrieve user profile from the OAuth provider
	userProfile, err := a.getUserProfile(provider, token)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user profile: %w", err)
	}
	
	// Find or create user in database
	user, err := a.findOrCreateUser(provider, userProfile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find or create user: %w", err)
	}
	
	// Create session for the authenticated user
	session, err := a.CreateSession(user.ID, a.sessionTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session: %w", err)
	}
	
	return user, session, nil
}

// CreateSession creates a new session for the given user
func (a *AuthServiceImpl) CreateSession(userID int, duration time.Duration) (*models.Session, error) {
	if userID <= 0 {
		return nil, fmt.Errorf("user ID must be positive")
	}
	
	if duration <= 0 {
		duration = a.sessionTimeout
	}
	
	return a.sessionStore.Create(userID, duration)
}

// ValidateSession validates a session and returns it if valid and not expired
func (a *AuthServiceImpl) ValidateSession(sessionID string) (*models.Session, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}
	
	session, err := a.sessionStore.Get(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	
	if session == nil {
		return nil, fmt.Errorf("session not found")
	}
	
	if session.IsExpired() {
		// Clean up expired session
		a.sessionStore.Delete(sessionID)
		return nil, fmt.Errorf("session expired")
	}
	
	return session, nil
}

// DestroySession destroys a session (logout)
func (a *AuthServiceImpl) DestroySession(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}
	
	return a.sessionStore.Delete(sessionID)
}

// CleanupExpiredStates removes expired state tokens (should be called periodically)
func (a *AuthServiceImpl) CleanupExpiredStates() {
	if inMemoryStore, ok := a.stateStore.(*InMemoryStateStore); ok {
		inMemoryStore.Cleanup()
	}
}

// UserProfile represents user profile data from OAuth providers
type UserProfile struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// MicrosoftUserProfile represents Microsoft Graph API user profile response
type MicrosoftUserProfile struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
}

// GitHubUserProfile represents GitHub API user profile response
type GitHubUserProfile struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// getUserProfile retrieves user profile from the OAuth provider
func (a *AuthServiceImpl) getUserProfile(provider SupportedProvider, token *oauth2.Token) (*UserProfile, error) {
	switch provider {
	case ProviderMicrosoft:
		return a.getMicrosoftUserProfile(token)
	case ProviderGitHub:
		return a.getGitHubUserProfile(token)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

// getMicrosoftUserProfile retrieves user profile from Microsoft Graph API
func (a *AuthServiceImpl) getMicrosoftUserProfile(token *oauth2.Token) (*UserProfile, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user profile: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Microsoft Graph API error: %d - %s", resp.StatusCode, string(body))
	}
	
	var msProfile MicrosoftUserProfile
	if err := json.NewDecoder(resp.Body).Decode(&msProfile); err != nil {
		return nil, fmt.Errorf("failed to decode Microsoft profile: %w", err)
	}
	
	// Convert to standard UserProfile
	profile := &UserProfile{
		ID:       msProfile.ID,
		Username: msProfile.DisplayName,
		Email:    msProfile.Mail,
	}
	
	// Use UserPrincipalName as fallback for email if Mail is empty
	if profile.Email == "" {
		profile.Email = msProfile.UserPrincipalName
	}
	
	// Use UserPrincipalName as fallback for username if DisplayName is empty
	if profile.Username == "" {
		profile.Username = msProfile.UserPrincipalName
	}
	
	return profile, nil
}

// getGitHubUserProfile retrieves user profile from GitHub API
func (a *AuthServiceImpl) getGitHubUserProfile(token *oauth2.Token) (*UserProfile, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "sso-web-app")
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user profile: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %d - %s", resp.StatusCode, string(body))
	}
	
	var ghProfile GitHubUserProfile
	if err := json.NewDecoder(resp.Body).Decode(&ghProfile); err != nil {
		return nil, fmt.Errorf("failed to decode GitHub profile: %w", err)
	}
	
	// If email is not public, try to get it from the emails endpoint
	email := ghProfile.Email
	if email == "" {
		email, _ = a.getGitHubUserEmail(token)
	}
	
	// Convert to standard UserProfile
	profile := &UserProfile{
		ID:        fmt.Sprintf("%d", ghProfile.ID),
		Username:  ghProfile.Login,
		Email:     email,
		AvatarURL: ghProfile.AvatarURL,
	}
	
	return profile, nil
}

// getGitHubUserEmail retrieves user's primary email from GitHub API
func (a *AuthServiceImpl) getGitHubUserEmail(token *oauth2.Token) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "sso-web-app")
	
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get user emails: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API error: %d", resp.StatusCode)
	}
	
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", fmt.Errorf("failed to decode emails: %w", err)
	}
	
	// Find primary verified email
	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}
	
	// Fallback to first verified email
	for _, email := range emails {
		if email.Verified {
			return email.Email, nil
		}
	}
	
	return "", fmt.Errorf("no verified email found")
}

// findOrCreateUser finds an existing user or creates a new one
func (a *AuthServiceImpl) findOrCreateUser(provider SupportedProvider, profile *UserProfile) (*models.User, error) {
	// Try to find existing user
	existingUser, err := a.userRepo.FindByProviderID(provider.String(), profile.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	
	if existingUser != nil {
		// Update existing user with latest profile information
		existingUser.Username = profile.Username
		existingUser.Email = profile.Email
		existingUser.AvatarURL = profile.AvatarURL
		
		if err := a.userRepo.Update(existingUser); err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}
		
		return existingUser, nil
	}
	
	// Create new user
	newUser := &models.User{
		Provider:   provider.String(),
		ProviderID: profile.ID,
		Username:   profile.Username,
		Email:      profile.Email,
		AvatarURL:  profile.AvatarURL,
	}
	
	if err := a.userRepo.Create(newUser); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	
	return newUser, nil
}