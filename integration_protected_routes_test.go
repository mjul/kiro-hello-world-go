package main

import (
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"sso-web-app/config"
	"sso-web-app/handlers"
	"sso-web-app/models"
	"sso-web-app/services"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// MockDatabase implements the DatabaseHealth interface for testing
type MockDatabase struct {
	healthy bool
}

func (m *MockDatabase) IsHealthy() error {
	if !m.healthy {
		return &MockDatabaseError{message: "database unhealthy"}
	}
	return nil
}

func (m *MockDatabase) Close() error {
	return nil
}

type MockDatabaseError struct {
	message string
}

func (e *MockDatabaseError) Error() string {
	return e.message
}

// MockAuthService implements the AuthService interface for testing
type MockAuthService struct {
	sessions map[string]*models.Session
	users    map[int]*models.User
}

func NewMockAuthService() *MockAuthService {
	return &MockAuthService{
		sessions: make(map[string]*models.Session),
		users:    make(map[int]*models.User),
	}
}

func (m *MockAuthService) InitiateOAuth(provider services.SupportedProvider) (string, string, error) {
	return "http://example.com/auth", "test-state", nil
}

func (m *MockAuthService) HandleCallback(provider services.SupportedProvider, code, state string) (*models.User, *models.Session, error) {
	user := &models.User{
		ID:       1,
		Username: "testuser",
		Email:    "test@example.com",
		Provider: string(provider),
	}
	session := &models.Session{
		ID:        "test-session",
		UserID:    1,
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	m.users[user.ID] = user
	m.sessions[session.ID] = session
	return user, session, nil
}

func (m *MockAuthService) CreateSession(userID int, duration time.Duration) (*models.Session, error) {
	session := &models.Session{
		ID:        fmt.Sprintf("test-session-%d", userID),
		UserID:    userID,
		ExpiresAt: time.Now().Add(duration),
		CreatedAt: time.Now(),
	}
	m.sessions[session.ID] = session
	return session, nil
}

func (m *MockAuthService) ValidateSession(sessionID string) (*models.Session, error) {
	if session, exists := m.sessions[sessionID]; exists {
		if !session.IsExpired() {
			return session, nil
		}
		// Clean up expired session
		delete(m.sessions, sessionID)
	}
	return nil, &MockSessionError{message: "session not found"}
}

func (m *MockAuthService) DestroySession(sessionID string) error {
	delete(m.sessions, sessionID)
	return nil
}

type MockSessionError struct {
	message string
}

func (e *MockSessionError) Error() string {
	return e.message
}

// MockUserRepository implements the UserRepository interface for testing
type MockUserRepository struct {
	users map[int]*models.User
}

func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users: make(map[int]*models.User),
	}
}

func (m *MockUserRepository) FindByProviderID(provider, providerID string) (*models.User, error) {
	for _, user := range m.users {
		if user.Provider == provider && user.ProviderID == providerID {
			return user, nil
		}
	}
	return nil, nil
}

func (m *MockUserRepository) FindByID(id int) (*models.User, error) {
	if user, exists := m.users[id]; exists {
		return user, nil
	}
	return nil, nil
}

func (m *MockUserRepository) Create(user *models.User) error {
	user.ID = len(m.users) + 1
	m.users[user.ID] = user
	return nil
}

func (m *MockUserRepository) Update(user *models.User) error {
	if _, exists := m.users[user.ID]; exists {
		m.users[user.ID] = user
		return nil
	}
	return &MockUserError{message: "user not found"}
}

type MockUserError struct {
	message string
}

func (e *MockUserError) Error() string {
	return e.message
}

// createServerWithMocks creates a server with mock dependencies
func createServerWithMocks(cfg *config.Config, mockDB *MockDatabase, authService services.AuthService, userRepo services.UserRepository) *TestServer {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	router := gin.New()
	
	// Initialize template manager
	templateManager := handlers.NewTemplateManager("templates")
	
	// Add basic middleware
	router.Use(gin.Recovery())
	
	// Session middleware
	router.Use(func(c *gin.Context) {
		sessionID, err := c.Cookie("session_id")
		if err != nil {
			c.Next()
			return
		}

		session, err := authService.ValidateSession(sessionID)
		if err != nil {
			c.Next()
			return
		}

		c.Set("session", session)
		c.Set("session_id", sessionID)
		c.Next()
	})
	
	// Setup routes manually
	setupTestRoutes(router, authService, userRepo, templateManager)
	
	// Create a minimal server struct for testing
	testServer := &TestServer{
		router:          router,
		templateManager: templateManager,
	}
	
	return testServer
}

// TestServer is a minimal server implementation for testing
type TestServer struct {
	router          *gin.Engine
	templateManager *handlers.TemplateManager
}

// GetRouter returns the router for testing
func (ts *TestServer) GetRouter() *gin.Engine {
	return ts.router
}

// GetTemplateManager returns the template manager for testing
func (ts *TestServer) GetTemplateManager() *handlers.TemplateManager {
	return ts.templateManager
}

// setupTestRoutes sets up the routes for testing
func setupTestRoutes(router *gin.Engine, authService services.AuthService, userRepo services.UserRepository, templateManager *handlers.TemplateManager) {
	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})
	
	// Root redirect
	router.GET("/", func(c *gin.Context) {
		if session, exists := c.Get("session"); exists && session != nil {
			c.Redirect(http.StatusFound, "/dashboard")
			return
		}
		c.Redirect(http.StatusFound, "/login")
	})
	
	// Login page
	router.GET("/login", func(c *gin.Context) {
		if session, exists := c.Get("session"); exists && session != nil {
			c.Redirect(http.StatusFound, "/dashboard")
			return
		}
		
		data := handlers.LoginPageData{
			Title: "Login - SSO Web App",
			Error: c.Query("error"),
		}
		templateManager.RenderTemplate(c, "login.html", data)
	})
	
	// Protected routes
	protected := router.Group("/")
	protected.Use(func(c *gin.Context) {
		session, exists := c.Get("session")
		if !exists || session == nil {
			c.Redirect(http.StatusFound, "/login?error=Authentication required")
			c.Abort()
			return
		}

		userSession, ok := session.(*models.Session)
		if !ok {
			c.Redirect(http.StatusFound, "/login?error=Invalid session")
			c.Abort()
			return
		}

		user, err := userRepo.FindByID(userSession.UserID)
		if err != nil || user == nil {
			c.Redirect(http.StatusFound, "/login?error=User not found")
			c.Abort()
			return
		}

		c.Set("user", user)
		c.Next()
	})
	
	protected.GET("/dashboard", func(c *gin.Context) {
		userInterface, exists := c.Get("user")
		if !exists {
			c.Redirect(http.StatusFound, "/login?error=User not found")
			return
		}

		user, ok := userInterface.(*models.User)
		if !ok {
			c.Redirect(http.StatusFound, "/login?error=Invalid user")
			return
		}

		data := handlers.DashboardPageData{
			Title:    "Dashboard - SSO Web App",
			Username: user.Username,
			Email:    user.Email,
			Avatar:   user.AvatarURL,
			Provider: user.Provider,
		}

		templateManager.RenderTemplate(c, "dashboard.html", data)
	})
	
	protected.POST("/logout", func(c *gin.Context) {
		sessionID, exists := c.Get("session_id")
		if exists && sessionID != nil {
			if sessionIDString, ok := sessionID.(string); ok {
				authService.DestroySession(sessionIDString)
			}
		}

		// Clear session cookie
		c.SetCookie("session_id", "", -1, "/", "", false, true)
		c.Redirect(http.StatusFound, "/login")
	})
}

// createTestServerForProtectedRoutes creates a test server for protected route testing
func createTestServerForProtectedRoutes() (*TestServer, *MockAuthService, *MockUserRepository) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Port:          "8080",
		BaseURL:       "http://localhost:8080",
		SessionSecret: "test-secret",
		DatabaseURL:   ":memory:",
	}

	mockDB := &MockDatabase{healthy: true}
	mockAuthService := NewMockAuthService()
	mockUserRepo := NewMockUserRepository()

	// Add a test user
	testUser := &models.User{
		ID:         1,
		Provider:   "microsoft",
		ProviderID: "test-provider-id",
		Username:   "testuser",
		Email:      "test@example.com",
		AvatarURL:  "https://example.com/avatar.jpg",
	}
	mockUserRepo.users[1] = testUser

	// Create server with mocks
	server := createServerWithMocks(cfg, mockDB, mockAuthService, mockUserRepo)

	// Setup simple templates for testing
	templateManager := server.GetTemplateManager()
	if templateManager != nil {
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

	return server, mockAuthService, mockUserRepo
}

// TestProtectedRoutesWithoutAuthentication tests access to protected routes without authentication
func TestProtectedRoutesWithoutAuthentication(t *testing.T) {
	server, _, _ := createTestServerForProtectedRoutes()
	router := server.GetRouter()

	protectedRoutes := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		expectRedirect string
	}{
		{
			name:           "Dashboard without auth",
			method:         "GET",
			path:           "/dashboard",
			expectedStatus: http.StatusFound,
			expectRedirect: "/login",
		},
		{
			name:           "Logout without auth",
			method:         "POST",
			path:           "/logout",
			expectedStatus: http.StatusFound,
			expectRedirect: "/login",
		},
	}

	for _, tt := range protectedRoutes {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(tt.method, tt.path, nil)
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

// TestProtectedRoutesWithAuthentication tests access to protected routes with valid authentication
func TestProtectedRoutesWithAuthentication(t *testing.T) {
	server, mockAuthService, _ := createTestServerForProtectedRoutes()
	router := server.GetRouter()

	// Create a valid session
	session, err := mockAuthService.CreateSession(1, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	sessionCookie := &http.Cookie{
		Name:  "session_id",
		Value: session.ID,
	}

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		expectContent  string
	}{
		{
			name:           "Dashboard with auth",
			method:         "GET",
			path:           "/dashboard",
			expectedStatus: http.StatusOK,
			expectContent:  "Hello testuser!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(tt.method, tt.path, nil)
			req.AddCookie(sessionCookie)
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectContent != "" {
				body := w.Body.String()
				if !strings.Contains(body, tt.expectContent) {
					t.Errorf("Expected response to contain %s, got %s", tt.expectContent, body)
				}
			}
		})
	}
}

// TestRootRedirectBehavior tests the root path redirect behavior
func TestRootRedirectBehavior(t *testing.T) {
	server, mockAuthService, _ := createTestServerForProtectedRoutes()
	router := server.GetRouter()

	tests := []struct {
		name           string
		hasSession     bool
		expectedStatus int
		expectRedirect string
	}{
		{
			name:           "Root without session redirects to login",
			hasSession:     false,
			expectedStatus: http.StatusFound,
			expectRedirect: "/login",
		},
		{
			name:           "Root with session redirects to dashboard",
			hasSession:     true,
			expectedStatus: http.StatusFound,
			expectRedirect: "/dashboard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/", nil)

			if tt.hasSession {
				session, err := mockAuthService.CreateSession(1, time.Hour)
				if err != nil {
					t.Fatalf("Failed to create test session: %v", err)
				}
				req.AddCookie(&http.Cookie{
					Name:  "session_id",
					Value: session.ID,
				})
			}

			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			location := w.Header().Get("Location")
			if location != tt.expectRedirect {
				t.Errorf("Expected redirect to %s, got %s", tt.expectRedirect, location)
			}
		})
	}
}

// TestLoginPageRedirectBehavior tests login page redirect behavior for authenticated users
func TestLoginPageRedirectBehavior(t *testing.T) {
	server, mockAuthService, _ := createTestServerForProtectedRoutes()
	router := server.GetRouter()

	tests := []struct {
		name           string
		hasSession     bool
		expectedStatus int
		expectRedirect string
	}{
		{
			name:           "Login page without session shows page",
			hasSession:     false,
			expectedStatus: http.StatusOK,
			expectRedirect: "",
		},
		{
			name:           "Login page with session redirects to dashboard",
			hasSession:     true,
			expectedStatus: http.StatusFound,
			expectRedirect: "/dashboard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/login", nil)

			if tt.hasSession {
				session, err := mockAuthService.CreateSession(1, time.Hour)
				if err != nil {
					t.Fatalf("Failed to create test session: %v", err)
				}
				req.AddCookie(&http.Cookie{
					Name:  "session_id",
					Value: session.ID,
				})
			}

			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectRedirect != "" {
				location := w.Header().Get("Location")
				if location != tt.expectRedirect {
					t.Errorf("Expected redirect to %s, got %s", tt.expectRedirect, location)
				}
			}
		})
	}
}

// TestLogoutFunctionality tests the logout functionality and session cleanup
func TestLogoutFunctionality(t *testing.T) {
	server, mockAuthService, _ := createTestServerForProtectedRoutes()
	router := server.GetRouter()

	// Create a valid session
	session, err := mockAuthService.CreateSession(1, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	sessionCookie := &http.Cookie{
		Name:  "session_id",
		Value: session.ID,
	}

	// Step 1: Verify user can access dashboard with session
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(sessionCookie)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for dashboard access before logout, got %d", w.Code)
	}

	// Step 2: Perform logout
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/logout", nil)
	req.AddCookie(sessionCookie)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected redirect status for logout, got %d", w.Code)
	}

	location := w.Header().Get("Location")
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

	// Step 3: Verify session is destroyed and dashboard access is denied
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(sessionCookie) // Use old session cookie
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected redirect status for dashboard access after logout, got %d", w.Code)
	}

	location = w.Header().Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("Expected redirect to login after logout, got %s", location)
	}
}

// TestSessionExpiration tests session expiration and cleanup
func TestSessionExpiration(t *testing.T) {
	server, mockAuthService, _ := createTestServerForProtectedRoutes()
	router := server.GetRouter()

	// Create a session with very short duration
	shortSession, err := mockAuthService.CreateSession(1, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create short session: %v", err)
	}

	shortSessionCookie := &http.Cookie{
		Name:  "session_id",
		Value: shortSession.ID,
	}

	// Verify session is initially valid
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(shortSessionCookie)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for dashboard access with valid session, got %d", w.Code)
	}

	// Wait for session to expire
	time.Sleep(150 * time.Millisecond)

	// Try to access protected resource with expired session
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(shortSessionCookie)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected redirect status for expired session, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("Expected redirect to login for expired session, got %s", location)
	}
}

// TestInvalidSessionHandling tests handling of invalid session IDs
func TestInvalidSessionHandling(t *testing.T) {
	server, _, _ := createTestServerForProtectedRoutes()
	router := server.GetRouter()

	invalidSessionCookies := []*http.Cookie{
		{Name: "session_id", Value: "invalid_session_id"},
		{Name: "session_id", Value: ""},
		{Name: "session_id", Value: "malformed-session-id-123"},
	}

	for i, cookie := range invalidSessionCookies {
		t.Run(fmt.Sprintf("Invalid session %d", i), func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/dashboard", nil)
			req.AddCookie(cookie)
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
}

// TestErrorHandlingInProtectedRoutes tests error handling in protected routes
func TestErrorHandlingInProtectedRoutes(t *testing.T) {
	server, mockAuthService, mockUserRepo := createTestServerForProtectedRoutes()
	router := server.GetRouter()

	// Create a session for a user that doesn't exist in the repository
	session, err := mockAuthService.CreateSession(999, time.Hour) // User ID 999 doesn't exist
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	sessionCookie := &http.Cookie{
		Name:  "session_id",
		Value: session.ID,
	}

	// Clear the user from the repository to simulate user not found error
	delete(mockUserRepo.users, 999)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(sessionCookie)
	router.ServeHTTP(w, req)

	// Should redirect to login with error when user is not found
	if w.Code != http.StatusFound {
		t.Errorf("Expected redirect status when user not found, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("Expected redirect to login when user not found, got %s", location)
	}
}