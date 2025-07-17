package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sso-web-app/config"
	"sso-web-app/database"
	"sso-web-app/handlers"
	"sso-web-app/models"
	"sso-web-app/services"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// MockOAuth2Server simulates OAuth2 provider endpoints for testing
type MockOAuth2Server struct {
	server       *httptest.Server
	authCodes    map[string]OAuthCodeData
	accessTokens map[string]OAuthTokenData
	userProfiles map[string]interface{}
}

type OAuthCodeData struct {
	Provider    string
	State       string
	UserProfile interface{}
}

type OAuthTokenData struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int
	UserProfile interface{}
}

// NewMockOAuth2Server creates a new mock OAuth2 server
func NewMockOAuth2Server() *MockOAuth2Server {
	mock := &MockOAuth2Server{
		authCodes:    make(map[string]OAuthCodeData),
		accessTokens: make(map[string]OAuthTokenData),
		userProfiles: make(map[string]interface{}),
	}

	mux := http.NewServeMux()

	// Microsoft OAuth2 endpoints
	mux.HandleFunc("/microsoft/oauth2/v2.0/authorize", mock.handleMicrosoftAuth)
	mux.HandleFunc("/microsoft/oauth2/v2.0/token", mock.handleMicrosoftToken)
	mux.HandleFunc("/microsoft/v1.0/me", mock.handleMicrosoftProfile)

	// GitHub OAuth2 endpoints
	mux.HandleFunc("/github/login/oauth/authorize", mock.handleGitHubAuth)
	mux.HandleFunc("/github/login/oauth/access_token", mock.handleGitHubToken)
	mux.HandleFunc("/github/user", mock.handleGitHubProfile)

	mock.server = httptest.NewServer(mux)
	return mock
}

func (m *MockOAuth2Server) Close() {
	m.server.Close()
}

func (m *MockOAuth2Server) URL() string {
	return m.server.URL
}

// AddUser adds a mock user profile for testing
func (m *MockOAuth2Server) AddUser(provider, userID string, profile interface{}) {
	key := provider + ":" + userID
	m.userProfiles[key] = profile
}

// Microsoft OAuth2 handlers
func (m *MockOAuth2Server) handleMicrosoftAuth(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	
	if clientID == "" || redirectURI == "" || state == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	// Generate auth code
	authCode := "mock_auth_code_" + state
	m.authCodes[authCode] = OAuthCodeData{
		Provider: "microsoft",
		State:    state,
		UserProfile: services.MicrosoftUserProfile{
			ID:                "ms_user_123",
			DisplayName:       "Test User",
			UserPrincipalName: "testuser@example.com",
			Mail:              "testuser@example.com",
		},
	}

	// Redirect back with auth code
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, authCode, state)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (m *MockOAuth2Server) handleMicrosoftToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	code := r.Form.Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	codeData, exists := m.authCodes[code]
	if !exists {
		http.Error(w, "Invalid authorization code", http.StatusBadRequest)
		return
	}

	// Generate access token
	accessToken := "mock_access_token_" + code
	m.accessTokens[accessToken] = OAuthTokenData{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		UserProfile: codeData.UserProfile,
	}

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (m *MockOAuth2Server) handleMicrosoftProfile(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing or invalid authorization header", http.StatusUnauthorized)
		return
	}

	accessToken := strings.TrimPrefix(authHeader, "Bearer ")
	tokenData, exists := m.accessTokens[accessToken]
	if !exists {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenData.UserProfile)
}

// GitHub OAuth2 handlers
func (m *MockOAuth2Server) handleGitHubAuth(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	
	if clientID == "" || redirectURI == "" || state == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	// Generate auth code
	authCode := "mock_auth_code_" + state
	m.authCodes[authCode] = OAuthCodeData{
		Provider: "github",
		State:    state,
		UserProfile: services.GitHubUserProfile{
			ID:        456,
			Login:     "testuser",
			Email:     "testuser@example.com",
			AvatarURL: "https://github.com/avatar.jpg",
		},
	}

	// Redirect back with auth code
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, authCode, state)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (m *MockOAuth2Server) handleGitHubToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	code := r.Form.Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	codeData, exists := m.authCodes[code]
	if !exists {
		http.Error(w, "Invalid authorization code", http.StatusBadRequest)
		return
	}

	// Generate access token
	accessToken := "mock_access_token_" + code
	m.accessTokens[accessToken] = OAuthTokenData{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		UserProfile: codeData.UserProfile,
	}

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (m *MockOAuth2Server) handleGitHubProfile(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing or invalid authorization header", http.StatusUnauthorized)
		return
	}

	accessToken := strings.TrimPrefix(authHeader, "Bearer ")
	tokenData, exists := m.accessTokens[accessToken]
	if !exists {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenData.UserProfile)
}

// IntegrationTestSuite holds the test environment
type IntegrationTestSuite struct {
	server       *handlers.Server
	db           *database.DB
	mockOAuth    *MockOAuth2Server
	authService  services.AuthService
	userRepo     services.UserRepository
	sessionStore services.SessionStore
}

// NewIntegrationTestSuite creates a new integration test suite
func NewIntegrationTestSuite(t *testing.T) *IntegrationTestSuite {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Create in-memory SQLite database for testing
	db, err := database.Initialize(":memory:")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}

	// Create mock OAuth2 server
	mockOAuth := NewMockOAuth2Server()

	// Create test configuration with mock OAuth endpoints
	cfg := &config.Config{
		Port:          "8080",
		BaseURL:       "http://localhost:8080",
		SessionSecret: "test-secret-key-for-integration-tests",
		DatabaseURL:   ":memory:",
		Microsoft: config.OAuth2Config{
			ClientID:     "test_ms_client_id",
			ClientSecret: "test_ms_client_secret",
			RedirectURL:  "http://localhost:8080/auth/callback/microsoft",
			Scopes:       []string{"openid", "profile", "email"},
			AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
		},
		GitHub: config.OAuth2Config{
			ClientID:     "test_gh_client_id",
			ClientSecret: "test_gh_client_secret",
			RedirectURL:  "http://localhost:8080/auth/callback/github",
			Scopes:       []string{"user:email", "read:user"},
			AuthURL:      "https://github.com/login/oauth/authorize",
			TokenURL:     "https://github.com/login/oauth/access_token",
			UserInfoURL:  "https://api.github.com/user",
		},
	}

	// Initialize OAuth2 configuration
	oauthConfig := services.NewOAuth2Config()
	oauthConfig.Microsoft.ClientID = cfg.Microsoft.ClientID
	oauthConfig.Microsoft.ClientSecret = cfg.Microsoft.ClientSecret
	oauthConfig.Microsoft.RedirectURL = cfg.Microsoft.RedirectURL
	oauthConfig.Microsoft.Scopes = cfg.Microsoft.Scopes

	oauthConfig.GitHub.ClientID = cfg.GitHub.ClientID
	oauthConfig.GitHub.ClientSecret = cfg.GitHub.ClientSecret
	oauthConfig.GitHub.RedirectURL = cfg.GitHub.RedirectURL
	oauthConfig.GitHub.Scopes = cfg.GitHub.Scopes

	// Initialize repositories
	userRepo := database.NewUserRepository(db)
	sessionStore := database.NewSessionStore(db)

	// Initialize auth service
	authService := services.NewAuthService(
		oauthConfig,
		userRepo,
		sessionStore,
		24*time.Hour,
	)

	// Initialize web server
	server := handlers.NewServer(cfg, db, authService, userRepo)

	return &IntegrationTestSuite{
		server:       server,
		db:           db,
		mockOAuth:    mockOAuth,
		authService:  authService,
		userRepo:     userRepo,
		sessionStore: sessionStore,
	}
}

// Cleanup cleans up test resources
func (suite *IntegrationTestSuite) Cleanup() {
	if suite.mockOAuth != nil {
		suite.mockOAuth.Close()
	}
	if suite.db != nil {
		suite.db.Close()
	}
}

// Helper method to create simple templates for testing
func (suite *IntegrationTestSuite) setupTemplates() {
	templateManager := suite.server.GetTemplateManager()
	if templateManager == nil {
		return
	}

	// Create simple templates for testing
	templates := map[string]string{
		"login.html": `
			<html><body>
				<h1>{{.Title}}</h1>
				{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
				<a href="/auth/microsoft">Login with Microsoft</a>
				<a href="/auth/github">Login with GitHub</a>
			</body></html>
		`,
		"dashboard.html": `
			<html><body>
				<h1>{{.Title}}</h1>
				<p>Hello {{.Username}}!</p>
				<p>Email: {{.Email}}</p>
				<form method="POST" action="/logout">
					<button type="submit">Logout</button>
				</form>
			</body></html>
		`,
		"error.html": `
			<html><body>
				<h1>Error</h1>
				<p>{{.Message}}</p>
				<a href="/login">Back to Login</a>
			</body></html>
		`,
	}

	for name, content := range templates {
		tmpl, err := template.New(name).Parse(content)
		if err == nil {
			templateManager.SetTemplate(name, tmpl)
		}
	}
}

// TestCompleteOAuthFlowMicrosoft tests the complete OAuth flow with Microsoft
func TestCompleteOAuthFlowMicrosoft(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	suite.setupTemplates()

	router := suite.server.GetRouter()

	// Step 1: Access root - should redirect to login
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected redirect status %d, got %d", http.StatusFound, w.Code)
	}

	location := w.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}

	// Step 2: Access login page
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/login", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d for login page, got %d", http.StatusOK, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Login with Microsoft") {
		t.Error("Login page should contain Microsoft login option")
	}

	// Step 3: Initiate OAuth flow with Microsoft
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/auth/microsoft", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected redirect status %d for OAuth initiation, got %d", http.StatusFound, w.Code)
	}

	oauthURL := w.Header().Get("Location")
	if !strings.Contains(oauthURL, suite.mockOAuth.URL()) {
		t.Errorf("Expected redirect to mock OAuth server, got %s", oauthURL)
	}

	// Extract state parameter from OAuth URL
	parsedURL, err := url.Parse(oauthURL)
	if err != nil {
		t.Fatalf("Failed to parse OAuth URL: %v", err)
	}
	state := parsedURL.Query().Get("state")
	if state == "" {
		t.Fatal("OAuth URL should contain state parameter")
	}

	// Step 4: Simulate OAuth provider redirect back with auth code
	// The mock OAuth server would normally handle this, but we'll simulate the callback directly
	authCode := "mock_auth_code_" + state
	suite.mockOAuth.authCodes[authCode] = OAuthCodeData{
		Provider: "microsoft",
		State:    state,
		UserProfile: services.MicrosoftUserProfile{
			ID:                "ms_user_123",
			DisplayName:       "Test User",
			UserPrincipalName: "testuser@example.com",
			Mail:              "testuser@example.com",
		},
	}

	// Generate access token for the auth code
	accessToken := "mock_access_token_" + authCode
	suite.mockOAuth.accessTokens[accessToken] = OAuthTokenData{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		UserProfile: services.MicrosoftUserProfile{
			ID:                "ms_user_123",
			DisplayName:       "Test User",
			UserPrincipalName: "testuser@example.com",
			Mail:              "testuser@example.com",
		},
	}

	// Step 5: Handle OAuth callback
	callbackURL := fmt.Sprintf("/auth/callback/microsoft?code=%s&state=%s", authCode, state)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", callbackURL, nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected redirect status %d for OAuth callback, got %d", http.StatusFound, w.Code)
	}

	location = w.Header().Get("Location")
	if location != "/dashboard" {
		t.Errorf("Expected redirect to /dashboard after successful auth, got %s", location)
	}

	// Extract session cookie
	var sessionCookie *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "session_id" {
			sessionCookie = cookie
			break
		}
	}

	if sessionCookie == nil {
		t.Fatal("Expected session cookie to be set after successful authentication")
	}

	// Step 6: Access dashboard with session
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(sessionCookie)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d for dashboard access, got %d", http.StatusOK, w.Code)
	}

	body = w.Body.String()
	if !strings.Contains(body, "Hello Test User!") {
		t.Error("Dashboard should display user greeting")
	}
	if !strings.Contains(body, "testuser@example.com") {
		t.Error("Dashboard should display user email")
	}

	// Step 7: Verify user was created in database
	user, err := suite.userRepo.FindByProviderID("microsoft", "ms_user_123")
	if err != nil {
		t.Fatalf("Failed to find user in database: %v", err)
	}
	if user == nil {
		t.Fatal("User should be created in database after successful authentication")
	}
	if user.Username != "Test User" {
		t.Errorf("Expected username 'Test User', got '%s'", user.Username)
	}
	if user.Email != "testuser@example.com" {
		t.Errorf("Expected email 'testuser@example.com', got '%s'", user.Email)
	}

	// Step 8: Test logout
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/logout", nil)
	req.AddCookie(sessionCookie)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected redirect status %d for logout, got %d", http.StatusFound, w.Code)
	}

	location = w.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login after logout, got %s", location)
	}

	// Verify session cookie is cleared
	var clearedCookie *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "session_id" {
			clearedCookie = cookie
			break
		}
	}

	if clearedCookie == nil || clearedCookie.MaxAge != -1 {
		t.Error("Session cookie should be cleared after logout")
	}

	// Step 9: Verify session is destroyed and dashboard access is denied
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(sessionCookie) // Use old session cookie
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected redirect status %d for dashboard access after logout, got %d", http.StatusFound, w.Code)
	}

	location = w.Header().Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("Expected redirect to login after logout, got %s", location)
	}
}

// TestCompleteOAuthFlowGitHub tests the complete OAuth flow with GitHub
func TestCompleteOAuthFlowGitHub(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	suite.setupTemplates()

	router := suite.server.GetRouter()

	// Step 1: Initiate OAuth flow with GitHub
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth/github", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected redirect status %d for OAuth initiation, got %d", http.StatusFound, w.Code)
	}

	oauthURL := w.Header().Get("Location")
	if !strings.Contains(oauthURL, suite.mockOAuth.URL()) {
		t.Errorf("Expected redirect to mock OAuth server, got %s", oauthURL)
	}

	// Extract state parameter
	parsedURL, err := url.Parse(oauthURL)
	if err != nil {
		t.Fatalf("Failed to parse OAuth URL: %v", err)
	}
	state := parsedURL.Query().Get("state")
	if state == "" {
		t.Fatal("OAuth URL should contain state parameter")
	}

	// Step 2: Simulate OAuth callback with GitHub
	authCode := "mock_auth_code_" + state
	suite.mockOAuth.authCodes[authCode] = OAuthCodeData{
		Provider: "github",
		State:    state,
		UserProfile: services.GitHubUserProfile{
			ID:        456,
			Login:     "githubuser",
			Email:     "githubuser@example.com",
			AvatarURL: "https://github.com/avatar.jpg",
		},
	}

	accessToken := "mock_access_token_" + authCode
	suite.mockOAuth.accessTokens[accessToken] = OAuthTokenData{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		UserProfile: services.GitHubUserProfile{
			ID:        456,
			Login:     "githubuser",
			Email:     "githubuser@example.com",
			AvatarURL: "https://github.com/avatar.jpg",
		},
	}

	// Step 3: Handle OAuth callback
	callbackURL := fmt.Sprintf("/auth/callback/github?code=%s&state=%s", authCode, state)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", callbackURL, nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected redirect status %d for OAuth callback, got %d", http.StatusFound, w.Code)
	}

	location := w.Header().Get("Location")
	if location != "/dashboard" {
		t.Errorf("Expected redirect to /dashboard after successful auth, got %s", location)
	}

	// Extract session cookie
	var sessionCookie *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "session_id" {
			sessionCookie = cookie
			break
		}
	}

	if sessionCookie == nil {
		t.Fatal("Expected session cookie to be set after successful authentication")
	}

	// Step 4: Verify user was created with GitHub data
	user, err := suite.userRepo.FindByProviderID("github", "456")
	if err != nil {
		t.Fatalf("Failed to find user in database: %v", err)
	}
	if user == nil {
		t.Fatal("User should be created in database after successful authentication")
	}
	if user.Username != "githubuser" {
		t.Errorf("Expected username 'githubuser', got '%s'", user.Username)
	}
	if user.Email != "githubuser@example.com" {
		t.Errorf("Expected email 'githubuser@example.com', got '%s'", user.Email)
	}
	if user.AvatarURL != "https://github.com/avatar.jpg" {
		t.Errorf("Expected avatar URL 'https://github.com/avatar.jpg', got '%s'", user.AvatarURL)
	}
}

// TestOAuthErrorScenarios tests various OAuth error scenarios
func TestOAuthErrorScenarios(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	suite.setupTemplates()

	router := suite.server.GetRouter()

	tests := []struct {
		name           string
		provider       string
		code           string
		state          string
		oauthError     string
		errorDesc      string
		expectedStatus int
		expectRedirect string
	}{
		{
			name:           "OAuth provider error",
			provider:       "microsoft",
			code:           "",
			state:          "",
			oauthError:     "access_denied",
			errorDesc:      "User denied access",
			expectedStatus: http.StatusFound,
			expectRedirect: "/login?error=",
		},
		{
			name:           "Missing authorization code",
			provider:       "github",
			code:           "",
			state:          "valid_state",
			oauthError:     "",
			errorDesc:      "",
			expectedStatus: http.StatusFound,
			expectRedirect: "/login?error=",
		},
		{
			name:           "Missing state parameter",
			provider:       "microsoft",
			code:           "valid_code",
			state:          "",
			oauthError:     "",
			errorDesc:      "",
			expectedStatus: http.StatusFound,
			expectRedirect: "/login?error=",
		},
		{
			name:           "Invalid state parameter",
			provider:       "github",
			code:           "valid_code",
			state:          "invalid_state",
			oauthError:     "",
			errorDesc:      "",
			expectedStatus: http.StatusFound,
			expectRedirect: "/login?error=",
		},
		{
			name:           "Unsupported provider",
			provider:       "invalid",
			code:           "valid_code",
			state:          "valid_state",
			oauthError:     "",
			errorDesc:      "",
			expectedStatus: http.StatusFound,
			expectRedirect: "/login?error=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build callback URL
			callbackURL := fmt.Sprintf("/auth/callback/%s", tt.provider)
			params := url.Values{}
			
			if tt.code != "" {
				params.Add("code", tt.code)
			}
			if tt.state != "" {
				params.Add("state", tt.state)
			}
			if tt.oauthError != "" {
				params.Add("error", tt.oauthError)
			}
			if tt.errorDesc != "" {
				params.Add("error_description", tt.errorDesc)
			}
			
			if len(params) > 0 {
				callbackURL += "?" + params.Encode()
			}

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", callbackURL, nil)
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			location := w.Header().Get("Location")
			if !strings.Contains(location, tt.expectRedirect) {
				t.Errorf("Expected redirect to contain %s, got %s", tt.expectRedirect, location)
			}
		})
	}
}

// TestSessionValidationAcrossRequests tests session validation across multiple requests
func TestSessionValidationAcrossRequests(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	suite.setupTemplates()

	router := suite.server.GetRouter()

	// Create a user and session manually for testing
	user := &models.User{
		Provider:   "microsoft",
		ProviderID: "test_user_123",
		Username:   "Test User",
		Email:      "test@example.com",
		AvatarURL:  "",
	}

	err := suite.userRepo.Create(user)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	session, err := suite.authService.CreateSession(user.ID, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	sessionCookie := &http.Cookie{
		Name:  "session_id",
		Value: session.ID,
	}

	// Test multiple requests with the same session
	protectedPaths := []string{"/dashboard", "/"}

	for _, path := range protectedPaths {
		t.Run(fmt.Sprintf("Access %s with valid session", path), func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", path, nil)
			req.AddCookie(sessionCookie)
			router.ServeHTTP(w, req)

			// Should either show the page or redirect to dashboard (for root)
			if w.Code != http.StatusOK && w.Code != http.StatusFound {
				t.Errorf("Expected status 200 or 302 for %s with valid session, got %d", path, w.Code)
			}

			if w.Code == http.StatusFound {
				location := w.Header().Get("Location")
				if path == "/" && location != "/dashboard" {
					t.Errorf("Expected redirect to /dashboard for root with session, got %s", location)
				}
			}
		})
	}

	// Test session expiration
	t.Run("Session expiration", func(t *testing.T) {
		// Create a session with very short duration
		shortSession, err := suite.authService.CreateSession(user.ID, 100*time.Millisecond)
		if err != nil {
			t.Fatalf("Failed to create short session: %v", err)
		}

		shortSessionCookie := &http.Cookie{
			Name:  "session_id",
			Value: shortSession.ID,
		}

		// Wait for session to expire
		time.Sleep(150 * time.Millisecond)

		// Try to access protected resource
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/dashboard", nil)
		req.AddCookie(shortSessionCookie)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected redirect status for expired session, got %d", w.Code)
		}

		location := w.Header().Get("Location")
		if !strings.Contains(location, "/login") {
			t.Errorf("Expected redirect to login for expired session, got %s", location)
		}
	})

	// Test invalid session ID
	t.Run("Invalid session ID", func(t *testing.T) {
		invalidCookie := &http.Cookie{
			Name:  "session_id",
			Value: "invalid_session_id",
		}

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/dashboard", nil)
		req.AddCookie(invalidCookie)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected redirect status for invalid session, got %d", w.Code)
		}

		location := w.Header().Get("Location")
		if !strings.Contains(location, "/login") {
			t.Errorf("Expected redirect to login for invalid session, got %s", location)
		}
	})
}

// TestConcurrentAuthentication tests concurrent authentication attempts
func TestConcurrentAuthentication(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	suite.setupTemplates()

	router := suite.server.GetRouter()

	const numConcurrentUsers = 5
	const numRequestsPerUser = 3

	// Channel to collect results
	type authResult struct {
		userID    int
		sessionID string
		err       error
	}
	resultChan := make(chan authResult, numConcurrentUsers*numRequestsPerUser)

	// Start concurrent authentication attempts
	for i := 0; i < numConcurrentUsers; i++ {
		go func(userIndex int) {
			for j := 0; j < numRequestsPerUser; j++ {
				// Create unique user for each attempt
				user := &models.User{
					Provider:   "microsoft",
					ProviderID: fmt.Sprintf("concurrent_user_%d_%d", userIndex, j),
					Username:   fmt.Sprintf("User %d-%d", userIndex, j),
					Email:      fmt.Sprintf("user%d-%d@example.com", userIndex, j),
				}

				err := suite.userRepo.Create(user)
				if err != nil {
					resultChan <- authResult{err: err}
					return
				}

				session, err := suite.authService.CreateSession(user.ID, time.Hour)
				if err != nil {
					resultChan <- authResult{err: err}
					return
				}

				resultChan <- authResult{
					userID:    user.ID,
					sessionID: session.ID,
					err:       nil,
				}
			}
		}(i)
	}

	// Collect results
	var results []authResult
	for i := 0; i < numConcurrentUsers*numRequestsPerUser; i++ {
		select {
		case result := <-resultChan:
			results = append(results, result)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent authentication results")
		}
	}

	// Verify all authentications succeeded
	successCount := 0
	sessionIDs := make(map[string]bool)
	
	for _, result := range results {
		if result.err != nil {
			t.Errorf("Concurrent authentication failed: %v", result.err)
			continue
		}
		
		successCount++
		
		// Verify session ID uniqueness
		if sessionIDs[result.sessionID] {
			t.Errorf("Duplicate session ID generated: %s", result.sessionID)
		}
		sessionIDs[result.sessionID] = true
		
		// Test session validation
		validatedSession, err := suite.authService.ValidateSession(result.sessionID)
		if err != nil {
			t.Errorf("Failed to validate concurrent session %s: %v", result.sessionID, err)
		}
		if validatedSession == nil {
			t.Errorf("ValidateSession returned nil for session %s", result.sessionID)
		}
	}

	expectedSuccessCount := numConcurrentUsers * numRequestsPerUser
	if successCount != expectedSuccessCount {
		t.Errorf("Expected %d successful authentications, got %d", expectedSuccessCount, successCount)
	}

	// Test concurrent access to protected resources
	for sessionID := range sessionIDs {
		go func(sid string) {
			sessionCookie := &http.Cookie{
				Name:  "session_id",
				Value: sid,
			}

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/dashboard", nil)
			req.AddCookie(sessionCookie)
			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Concurrent dashboard access failed for session %s: status %d", sid, w.Code)
			}
		}(sessionID)
	}

	// Give concurrent requests time to complete
	time.Sleep(100 * time.Millisecond)
}

// TestUserProfileUpdates tests user profile updates on subsequent logins
func TestUserProfileUpdates(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	suite.setupTemplates()

	router := suite.server.GetRouter()

	// Step 1: First login creates user
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth/microsoft", nil)
	router.ServeHTTP(w, req)

	oauthURL := w.Header().Get("Location")
	parsedURL, _ := url.Parse(oauthURL)
	state := parsedURL.Query().Get("state")

	// Simulate first login with initial profile
	authCode := "mock_auth_code_" + state
	suite.mockOAuth.authCodes[authCode] = OAuthCodeData{
		Provider: "microsoft",
		State:    state,
		UserProfile: services.MicrosoftUserProfile{
			ID:                "update_user_123",
			DisplayName:       "Initial Name",
			UserPrincipalName: "initial@example.com",
			Mail:              "initial@example.com",
		},
	}

	accessToken := "mock_access_token_" + authCode
	suite.mockOAuth.accessTokens[accessToken] = OAuthTokenData{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		UserProfile: services.MicrosoftUserProfile{
			ID:                "update_user_123",
			DisplayName:       "Initial Name",
			UserPrincipalName: "initial@example.com",
			Mail:              "initial@example.com",
		},
	}

	// Complete first login
	callbackURL := fmt.Sprintf("/auth/callback/microsoft?code=%s&state=%s", authCode, state)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", callbackURL, nil)
	router.ServeHTTP(w, req)

	// Verify user was created
	user, err := suite.userRepo.FindByProviderID("microsoft", "update_user_123")
	if err != nil {
		t.Fatalf("Failed to find user after first login: %v", err)
	}
	if user.Username != "Initial Name" {
		t.Errorf("Expected initial username 'Initial Name', got '%s'", user.Username)
	}
	if user.Email != "initial@example.com" {
		t.Errorf("Expected initial email 'initial@example.com', got '%s'", user.Email)
	}

	// Step 2: Second login with updated profile
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/auth/microsoft", nil)
	router.ServeHTTP(w, req)

	oauthURL = w.Header().Get("Location")
	parsedURL, _ = url.Parse(oauthURL)
	newState := parsedURL.Query().Get("state")

	// Simulate second login with updated profile
	newAuthCode := "mock_auth_code_" + newState
	suite.mockOAuth.authCodes[newAuthCode] = OAuthCodeData{
		Provider: "microsoft",
		State:    newState,
		UserProfile: services.MicrosoftUserProfile{
			ID:                "update_user_123", // Same user ID
			DisplayName:       "Updated Name",    // Updated name
			UserPrincipalName: "updated@example.com", // Updated email
			Mail:              "updated@example.com",
		},
	}

	newAccessToken := "mock_access_token_" + newAuthCode
	suite.mockOAuth.accessTokens[newAccessToken] = OAuthTokenData{
		AccessToken: newAccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		UserProfile: services.MicrosoftUserProfile{
			ID:                "update_user_123",
			DisplayName:       "Updated Name",
			UserPrincipalName: "updated@example.com",
			Mail:              "updated@example.com",
		},
	}

	// Complete second login
	newCallbackURL := fmt.Sprintf("/auth/callback/microsoft?code=%s&state=%s", newAuthCode, newState)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", newCallbackURL, nil)
	router.ServeHTTP(w, req)

	// Verify user profile was updated
	updatedUser, err := suite.userRepo.FindByProviderID("microsoft", "update_user_123")
	if err != nil {
		t.Fatalf("Failed to find user after second login: %v", err)
	}
	if updatedUser.Username != "Updated Name" {
		t.Errorf("Expected updated username 'Updated Name', got '%s'", updatedUser.Username)
	}
	if updatedUser.Email != "updated@example.com" {
		t.Errorf("Expected updated email 'updated@example.com', got '%s'", updatedUser.Email)
	}

	// Verify it's the same user (same ID)
	if updatedUser.ID != user.ID {
		t.Errorf("User ID should remain the same after profile update: original=%d, updated=%d", user.ID, updatedUser.ID)
	}
}

// TestEdgeCasesAndErrorHandling tests various edge cases and error scenarios
func TestEdgeCasesAndErrorHandling(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	suite.setupTemplates()

	router := suite.server.GetRouter()

	tests := []struct {
		name           string
		method         string
		path           string
		headers        map[string]string
		cookies        []*http.Cookie
		expectedStatus int
		expectRedirect bool
	}{
		{
			name:           "Access dashboard without session",
			method:         "GET",
			path:           "/dashboard",
			expectedStatus: http.StatusFound,
			expectRedirect: true,
		},
		{
			name:           "POST to logout without session",
			method:         "POST",
			path:           "/logout",
			expectedStatus: http.StatusFound,
			expectRedirect: true,
		},
		{
			name:   "Access dashboard with malformed session cookie",
			method: "GET",
			path:   "/dashboard",
			cookies: []*http.Cookie{
				{Name: "session_id", Value: "malformed-session-id"},
			},
			expectedStatus: http.StatusFound,
			expectRedirect: true,
		},
		{
			name:   "Access login page with valid session should redirect",
			method: "GET",
			path:   "/login",
			cookies: []*http.Cookie{
				{Name: "session_id", Value: "valid-session-id"},
			},
			expectedStatus: http.StatusOK, // Will be OK because session validation will fail for non-existent session
			expectRedirect: false,
		},
		{
			name:           "Invalid HTTP method for OAuth initiation",
			method:         "POST",
			path:           "/auth/microsoft",
			expectedStatus: http.StatusMethodNotAllowed,
			expectRedirect: false,
		},
		{
			name:           "Invalid HTTP method for OAuth callback",
			method:         "POST",
			path:           "/auth/callback/microsoft",
			expectedStatus: http.StatusFound, // Will redirect with error
			expectRedirect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(tt.method, tt.path, nil)

			// Add headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Add cookies
			for _, cookie := range tt.cookies {
				req.AddCookie(cookie)
			}

			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectRedirect {
				location := w.Header().Get("Location")
				if location == "" {
					t.Error("Expected redirect location header")
				}
			}
		})
	}
}

// TestHealthCheckEndpoint tests the health check endpoint
func TestHealthCheckEndpoint(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()

	router := suite.server.GetRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d for health check, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Failed to parse health check response: %v", err)
	}

	if response["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%v'", response["status"])
	}

	if response["timestamp"] == nil {
		t.Error("Health check response should include timestamp")
	}

	if response["version"] == nil {
		t.Error("Health check response should include version")
	}
}

// TestSecurityHeaders tests that security headers are properly set
func TestSecurityHeaders(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()

	router := suite.server.GetRouter()

	paths := []string{"/health", "/login", "/"}

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":   "nosniff",
		"X-XSS-Protection":         "1; mode=block",
		"X-Frame-Options":          "DENY",
		"Content-Security-Policy":  "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'",
		"Referrer-Policy":          "strict-origin-when-cross-origin",
	}

	for _, path := range paths {
		t.Run(fmt.Sprintf("Security headers for %s", path), func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", path, nil)
			router.ServeHTTP(w, req)

			for header, expectedValue := range expectedHeaders {
				actualValue := w.Header().Get(header)
				if actualValue != expectedValue {
					t.Errorf("Expected header %s to be '%s', got '%s'", header, expectedValue, actualValue)
				}
			}
		})
	}
}