package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"sso-web-app/config"
	"sso-web-app/models"
	"sso-web-app/services"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// MockAuthService is a mock implementation of AuthService for testing
type MockAuthService struct {
	sessions map[string]*models.Session
}

func NewMockAuthService() *MockAuthService {
	return &MockAuthService{
		sessions: make(map[string]*models.Session),
	}
}

func (m *MockAuthService) InitiateOAuth(provider services.SupportedProvider) (string, string, error) {
	return "http://example.com/auth", "test-state", nil
}

func (m *MockAuthService) HandleCallback(provider services.SupportedProvider, code, state string) (*models.User, *models.Session, error) {
	user := &models.User{ID: 1, Username: "testuser"}
	session := &models.Session{ID: "test-session", UserID: 1, ExpiresAt: time.Now().Add(time.Hour)}
	return user, session, nil
}

func (m *MockAuthService) CreateSession(userID int, duration time.Duration) (*models.Session, error) {
	session := &models.Session{
		ID:        "test-session",
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
	}
	return nil, errors.New("session not found")
}

func (m *MockAuthService) DestroySession(sessionID string) error {
	delete(m.sessions, sessionID)
	return nil
}

// MockDB is a mock implementation of database for testing
type MockDB struct {
	healthy bool
}

func NewMockDB() *MockDB {
	return &MockDB{healthy: true}
}

func (m *MockDB) IsHealthy() error {
	if !m.healthy {
		return sql.ErrConnDone
	}
	return nil
}

func (m *MockDB) Close() error {
	return nil
}

// MockUserRepository is a mock implementation of UserRepository for testing
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
	return errors.New("user not found")
}

// createTestServer creates a test server instance
func createTestServer() *Server {
	cfg := &config.Config{
		Port:          "8080",
		BaseURL:       "http://localhost:8080",
		SessionSecret: "test-secret",
	}
	
	mockDB := NewMockDB()
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
	
	// Create server directly with our mocks
	server := &Server{
		router:          gin.New(),
		config:          cfg,
		db:              mockDB,
		authService:     mockAuthService,
		templateManager: &TemplateManager{templates: make(map[string]*template.Template)},
		userRepo:        mockUserRepo,
	}
	
	// Setup middleware and routes
	server.setupMiddleware()
	server.setupRoutes()
	
	return server
}

func TestNewServer(t *testing.T) {
	server := createTestServer()
	
	if server == nil {
		t.Fatal("Expected server to be created, got nil")
	}
	
	if server.router == nil {
		t.Fatal("Expected router to be initialized, got nil")
	}
}

func TestHealthCheckHandler(t *testing.T) {
	server := createTestServer()
	
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	
	server.router.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}
	
	expectedContentType := "application/json; charset=utf-8"
	if w.Header().Get("Content-Type") != expectedContentType {
		t.Errorf("Expected Content-Type %s, got %s", expectedContentType, w.Header().Get("Content-Type"))
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	server := createTestServer()
	
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	
	server.router.ServeHTTP(w, req)
	
	// Test security headers
	expectedHeaders := map[string]string{
		"X-Content-Type-Options":   "nosniff",
		"X-XSS-Protection":         "1; mode=block",
		"X-Frame-Options":          "DENY",
		"Content-Security-Policy":  "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'",
		"Referrer-Policy":          "strict-origin-when-cross-origin",
	}
	
	for header, expectedValue := range expectedHeaders {
		if w.Header().Get(header) != expectedValue {
			t.Errorf("Expected header %s to be %s, got %s", header, expectedValue, w.Header().Get(header))
		}
	}
}

func TestCORSMiddleware(t *testing.T) {
	server := createTestServer()
	
	tests := []struct {
		name           string
		origin         string
		method         string
		expectedStatus int
		expectCORS     bool
	}{
		{
			name:           "Same origin request",
			origin:         "http://localhost:8080",
			method:         "GET",
			expectedStatus: http.StatusOK,
			expectCORS:     true,
		},
		{
			name:           "Different origin request",
			origin:         "http://evil.com",
			method:         "GET",
			expectedStatus: http.StatusOK,
			expectCORS:     false,
		},
		{
			name:           "Preflight request",
			origin:         "http://localhost:8080",
			method:         "OPTIONS",
			expectedStatus: http.StatusNoContent,
			expectCORS:     true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(tt.method, "/health", nil)
			req.Header.Set("Origin", tt.origin)
			
			server.router.ServeHTTP(w, req)
			
			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, w.Code)
			}
			
			corsHeader := w.Header().Get("Access-Control-Allow-Origin")
			if tt.expectCORS {
				if corsHeader != tt.origin {
					t.Errorf("Expected CORS header to be %s, got %s", tt.origin, corsHeader)
				}
			} else {
				if corsHeader != "" {
					t.Errorf("Expected no CORS header, got %s", corsHeader)
				}
			}
		})
	}
}

func TestSessionMiddleware(t *testing.T) {
	tests := []struct {
		name          string
		sessionCookie string
		expectSession bool
	}{
		{
			name:          "Valid session cookie",
			sessionCookie: "valid-session",
			expectSession: true,
		},
		{
			name:          "Invalid session cookie",
			sessionCookie: "invalid-session",
			expectSession: false,
		},
		{
			name:          "No session cookie",
			sessionCookie: "",
			expectSession: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh server for each test to avoid route conflicts
			server := createTestServer()
			mockAuthService := server.authService.(*MockAuthService)
			
			// Create a valid session
			session := &models.Session{
				ID:        "valid-session",
				UserID:    1,
				ExpiresAt: time.Now().Add(time.Hour),
				CreatedAt: time.Now(),
			}
			mockAuthService.sessions["valid-session"] = session
			
			// Add a test route that checks for session context
			server.router.GET("/test-session", func(c *gin.Context) {
				session, exists := c.Get("session")
				if tt.expectSession {
					if !exists {
						t.Error("Expected session in context, but not found")
					}
					if session == nil {
						t.Error("Expected session to not be nil")
					}
				} else {
					if exists && session != nil {
						t.Error("Expected no session in context, but found one")
					}
				}
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})
			
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test-session", nil)
			
			if tt.sessionCookie != "" {
				req.AddCookie(&http.Cookie{
					Name:  "session_id",
					Value: tt.sessionCookie,
				})
			}
			
			server.router.ServeHTTP(w, req)
			
			if w.Code != http.StatusOK {
				t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
			}
		})
	}
}

func TestSessionCookieHandling(t *testing.T) {
	server := createTestServer()
	
	// Test setting session cookie
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	
	server.setSessionCookie(c, "test-session-id", 3600)
	
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("Expected session cookie to be set")
	}
	
	cookie := cookies[0]
	if cookie.Name != "session_id" {
		t.Errorf("Expected cookie name to be 'session_id', got %s", cookie.Name)
	}
	
	if cookie.Value != "test-session-id" {
		t.Errorf("Expected cookie value to be 'test-session-id', got %s", cookie.Value)
	}
	
	if !cookie.HttpOnly {
		t.Error("Expected cookie to be HttpOnly")
	}
	
	if cookie.Path != "/" {
		t.Errorf("Expected cookie path to be '/', got %s", cookie.Path)
	}
}

func TestClearSessionCookie(t *testing.T) {
	server := createTestServer()
	
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	
	server.clearSessionCookie(c)
	
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("Expected session cookie to be cleared")
	}
	
	cookie := cookies[0]
	if cookie.Name != "session_id" {
		t.Errorf("Expected cookie name to be 'session_id', got %s", cookie.Name)
	}
	
	if cookie.Value != "" {
		t.Errorf("Expected cookie value to be empty, got %s", cookie.Value)
	}
	
	if cookie.MaxAge != -1 {
		t.Errorf("Expected cookie MaxAge to be -1, got %d", cookie.MaxAge)
	}
}

func TestLoginPageHandler(t *testing.T) {
	tests := []struct {
		name           string
		hasSession     bool
		errorParam     string
		expectedStatus int
		expectRedirect bool
	}{
		{
			name:           "No session - show login page",
			hasSession:     false,
			errorParam:     "",
			expectedStatus: http.StatusOK,
			expectRedirect: false,
		},
		{
			name:           "With session - redirect to dashboard",
			hasSession:     true,
			errorParam:     "",
			expectedStatus: http.StatusFound,
			expectRedirect: true,
		},
		{
			name:           "No session with error - show login page with error",
			hasSession:     false,
			errorParam:     "Authentication failed",
			expectedStatus: http.StatusOK,
			expectRedirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := createTestServer()
			
			// Create a simple template manager for testing
			server.templateManager = &TemplateManager{
				templates: make(map[string]*template.Template),
			}
			
			// Create a simple template for testing
			tmpl := template.Must(template.New("login.html").Parse(`
				<html><body>
					<h1>Login Page</h1>
					{{if .Error}}<p>Error: {{.Error}}</p>{{end}}
				</body></html>
			`))
			server.templateManager.templates["login.html"] = tmpl

			w := httptest.NewRecorder()
			url := "/login"
			if tt.errorParam != "" {
				url += "?error=" + tt.errorParam
			}
			req, _ := http.NewRequest("GET", url, nil)

			// Add session if needed
			if tt.hasSession {
				mockAuthService := server.authService.(*MockAuthService)
				session := &models.Session{
					ID:        "test-session",
					UserID:    1,
					ExpiresAt: time.Now().Add(time.Hour),
					CreatedAt: time.Now(),
				}
				mockAuthService.sessions["test-session"] = session
				req.AddCookie(&http.Cookie{
					Name:  "session_id",
					Value: "test-session",
				})
			}

			server.router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectRedirect {
				location := w.Header().Get("Location")
				if location != "/dashboard" {
					t.Errorf("Expected redirect to /dashboard, got %s", location)
				}
			}
		})
	}
}

func TestOAuthInitiateHandler(t *testing.T) {
	tests := []struct {
		name           string
		provider       string
		expectedStatus int
		expectRedirect bool
	}{
		{
			name:           "Microsoft provider",
			provider:       "microsoft",
			expectedStatus: http.StatusFound,
			expectRedirect: true,
		},
		{
			name:           "GitHub provider",
			provider:       "github",
			expectedStatus: http.StatusFound,
			expectRedirect: true,
		},
		{
			name:           "Unsupported provider",
			provider:       "invalid",
			expectedStatus: http.StatusFound,
			expectRedirect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := createTestServer()

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/auth/"+tt.provider, nil)

			server.router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectRedirect {
				location := w.Header().Get("Location")
				if location == "" {
					t.Error("Expected redirect location header")
				}

				if tt.provider == "invalid" {
					if !strings.Contains(location, "/login?error=") {
						t.Errorf("Expected redirect to login with error, got %s", location)
					}
				} else {
					// For valid providers, should redirect to OAuth provider
					if strings.Contains(location, "/login?error=") {
						t.Errorf("Expected redirect to OAuth provider, got error redirect: %s", location)
					}
				}
			}
		})
	}
}

func TestOAuthCallbackHandler(t *testing.T) {
	tests := []struct {
		name           string
		provider       string
		code           string
		state          string
		oauthError     string
		expectedStatus int
		expectRedirect string
	}{
		{
			name:           "Successful Microsoft callback",
			provider:       "microsoft",
			code:           "valid-code",
			state:          "valid-state",
			oauthError:     "",
			expectedStatus: http.StatusFound,
			expectRedirect: "/dashboard",
		},
		{
			name:           "Successful GitHub callback",
			provider:       "github",
			code:           "valid-code",
			state:          "valid-state",
			oauthError:     "",
			expectedStatus: http.StatusFound,
			expectRedirect: "/dashboard",
		},
		{
			name:           "OAuth error",
			provider:       "microsoft",
			code:           "",
			state:          "",
			oauthError:     "access_denied",
			expectedStatus: http.StatusFound,
			expectRedirect: "/login?error=",
		},
		{
			name:           "Missing code",
			provider:       "microsoft",
			code:           "",
			state:          "valid-state",
			oauthError:     "",
			expectedStatus: http.StatusFound,
			expectRedirect: "/login?error=",
		},
		{
			name:           "Missing state",
			provider:       "microsoft",
			code:           "valid-code",
			state:          "",
			oauthError:     "",
			expectedStatus: http.StatusFound,
			expectRedirect: "/login?error=",
		},
		{
			name:           "Unsupported provider",
			provider:       "invalid",
			code:           "valid-code",
			state:          "valid-state",
			oauthError:     "",
			expectedStatus: http.StatusFound,
			expectRedirect: "/login?error=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := createTestServer()

			w := httptest.NewRecorder()
			url := fmt.Sprintf("/auth/callback/%s", tt.provider)
			
			// Add query parameters
			params := make([]string, 0)
			if tt.code != "" {
				params = append(params, "code="+tt.code)
			}
			if tt.state != "" {
				params = append(params, "state="+tt.state)
			}
			if tt.oauthError != "" {
				params = append(params, "error="+tt.oauthError)
			}
			
			if len(params) > 0 {
				url += "?" + strings.Join(params, "&")
			}

			req, _ := http.NewRequest("GET", url, nil)

			server.router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			location := w.Header().Get("Location")
			if !strings.Contains(location, tt.expectRedirect) {
				t.Errorf("Expected redirect to contain %s, got %s", tt.expectRedirect, location)
			}
		})
	}
}

func TestRootHandler(t *testing.T) {
	tests := []struct {
		name           string
		hasSession     bool
		expectedStatus int
		expectRedirect string
	}{
		{
			name:           "No session - redirect to login",
			hasSession:     false,
			expectedStatus: http.StatusFound,
			expectRedirect: "/login",
		},
		{
			name:           "With session - redirect to dashboard",
			hasSession:     true,
			expectedStatus: http.StatusFound,
			expectRedirect: "/dashboard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := createTestServer()

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/", nil)

			// Add session if needed
			if tt.hasSession {
				mockAuthService := server.authService.(*MockAuthService)
				session := &models.Session{
					ID:        "test-session",
					UserID:    1,
					ExpiresAt: time.Now().Add(time.Hour),
					CreatedAt: time.Now(),
				}
				mockAuthService.sessions["test-session"] = session
				req.AddCookie(&http.Cookie{
					Name:  "session_id",
					Value: "test-session",
				})
			}

			server.router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			location := w.Header().Get("Location")
			if location != tt.expectRedirect {
				t.Errorf("Expected redirect to %s, got %s", tt.expectRedirect, location)
			}
		})
	}
}

func TestDashboardHandler(t *testing.T) {
	tests := []struct {
		name           string
		hasSession     bool
		userExists     bool
		expectedStatus int
		expectRedirect bool
	}{
		{
			name:           "No session - redirect to login",
			hasSession:     false,
			userExists:     false,
			expectedStatus: http.StatusFound,
			expectRedirect: true,
		},
		{
			name:           "Valid session and user - show dashboard",
			hasSession:     true,
			userExists:     true,
			expectedStatus: http.StatusOK,
			expectRedirect: false,
		},
		{
			name:           "Valid session but user not found - redirect to login",
			hasSession:     true,
			userExists:     false,
			expectedStatus: http.StatusFound,
			expectRedirect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := createTestServer()
			
			// Create a simple template for testing
			tmpl := template.Must(template.New("dashboard.html").Parse(`
				<html><body>
					<h1>Dashboard</h1>
					<p>Hello {{.Username}}</p>
					<p>Email: {{.Email}}</p>
				</body></html>
			`))
			server.templateManager.templates["dashboard.html"] = tmpl

			// Clear users if user shouldn't exist
			if !tt.userExists {
				mockUserRepo := server.userRepo.(*MockUserRepository)
				mockUserRepo.users = make(map[int]*models.User)
			}

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/dashboard", nil)

			// Add session if needed
			if tt.hasSession {
				mockAuthService := server.authService.(*MockAuthService)
				session := &models.Session{
					ID:        "test-session",
					UserID:    1,
					ExpiresAt: time.Now().Add(time.Hour),
					CreatedAt: time.Now(),
				}
				mockAuthService.sessions["test-session"] = session
				req.AddCookie(&http.Cookie{
					Name:  "session_id",
					Value: "test-session",
				})
			}

			server.router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectRedirect {
				location := w.Header().Get("Location")
				if !strings.Contains(location, "/login") {
					t.Errorf("Expected redirect to login, got %s", location)
				}
			}
		})
	}
}

func TestLogoutHandler(t *testing.T) {
	tests := []struct {
		name           string
		hasSession     bool
		expectedStatus int
	}{
		{
			name:           "Logout with session",
			hasSession:     true,
			expectedStatus: http.StatusFound,
		},
		{
			name:           "Logout without session",
			hasSession:     false,
			expectedStatus: http.StatusFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := createTestServer()

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/logout", nil)

			// Add session if needed
			if tt.hasSession {
				mockAuthService := server.authService.(*MockAuthService)
				session := &models.Session{
					ID:        "test-session",
					UserID:    1,
					ExpiresAt: time.Now().Add(time.Hour),
					CreatedAt: time.Now(),
				}
				mockAuthService.sessions["test-session"] = session
				req.AddCookie(&http.Cookie{
					Name:  "session_id",
					Value: "test-session",
				})
			}

			server.router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			// Should always redirect to login after logout
			location := w.Header().Get("Location")
			if location != "/login" {
				t.Errorf("Expected redirect to /login, got %s", location)
			}

			// Check that session cookie is cleared
			cookies := w.Result().Cookies()
			for _, cookie := range cookies {
				if cookie.Name == "session_id" && cookie.MaxAge != -1 {
					t.Error("Expected session cookie to be cleared (MaxAge should be -1)")
				}
			}
		})
	}
}

func TestRequireAuthMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		hasSession     bool
		userExists     bool
		expectedStatus int
		expectRedirect bool
		expectAbort    bool
	}{
		{
			name:           "No session - redirect to login",
			hasSession:     false,
			userExists:     false,
			expectedStatus: http.StatusFound,
			expectRedirect: true,
			expectAbort:    true,
		},
		{
			name:           "Valid session and user - continue",
			hasSession:     true,
			userExists:     true,
			expectedStatus: http.StatusOK,
			expectRedirect: false,
			expectAbort:    false,
		},
		{
			name:           "Valid session but user not found - redirect to login",
			hasSession:     true,
			userExists:     false,
			expectedStatus: http.StatusFound,
			expectRedirect: true,
			expectAbort:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := createTestServer()
			
			// Clear users if user shouldn't exist
			if !tt.userExists {
				mockUserRepo := server.userRepo.(*MockUserRepository)
				mockUserRepo.users = make(map[int]*models.User)
			}

			// Create a test route that uses the auth middleware
			server.router.GET("/test-protected", server.requireAuthMiddleware(), func(c *gin.Context) {
				// Check if user is in context
				user, exists := c.Get("user")
				if !exists {
					t.Error("Expected user in context after auth middleware")
				}
				if user == nil {
					t.Error("Expected user to not be nil")
				}
				c.JSON(http.StatusOK, gin.H{"status": "protected"})
			})

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test-protected", nil)

			// Add session if needed
			if tt.hasSession {
				mockAuthService := server.authService.(*MockAuthService)
				session := &models.Session{
					ID:        "test-session",
					UserID:    1,
					ExpiresAt: time.Now().Add(time.Hour),
					CreatedAt: time.Now(),
				}
				mockAuthService.sessions["test-session"] = session
				req.AddCookie(&http.Cookie{
					Name:  "session_id",
					Value: "test-session",
				})
			}

			server.router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectRedirect {
				location := w.Header().Get("Location")
				if !strings.Contains(location, "/login") {
					t.Errorf("Expected redirect to login, got %s", location)
				}
			}
		})
	}
}

func TestRedirectIfAuthenticatedMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		hasSession     bool
		expectedStatus int
		expectRedirect bool
	}{
		{
			name:           "No session - continue to handler",
			hasSession:     false,
			expectedStatus: http.StatusOK,
			expectRedirect: false,
		},
		{
			name:           "With session - redirect to dashboard",
			hasSession:     true,
			expectedStatus: http.StatusFound,
			expectRedirect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := createTestServer()

			// Create a test route that uses the redirect middleware
			server.router.GET("/test-public", server.redirectIfAuthenticatedMiddleware(), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "public"})
			})

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test-public", nil)

			// Add session if needed
			if tt.hasSession {
				mockAuthService := server.authService.(*MockAuthService)
				session := &models.Session{
					ID:        "test-session",
					UserID:    1,
					ExpiresAt: time.Now().Add(time.Hour),
					CreatedAt: time.Now(),
				}
				mockAuthService.sessions["test-session"] = session
				req.AddCookie(&http.Cookie{
					Name:  "session_id",
					Value: "test-session",
				})
			}

			server.router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectRedirect {
				location := w.Header().Get("Location")
				if location != "/dashboard" {
					t.Errorf("Expected redirect to /dashboard, got %s", location)
				}
			}
		})
	}
}

func TestMiddlewareIntegration(t *testing.T) {
	server := createTestServer()

	tests := []struct {
		name           string
		path           string
		hasSession     bool
		expectedStatus int
		expectRedirect string
	}{
		{
			name:           "Login page without session - show page",
			path:           "/login",
			hasSession:     false,
			expectedStatus: http.StatusOK,
			expectRedirect: "",
		},
		{
			name:           "Login page with session - redirect to dashboard",
			path:           "/login",
			hasSession:     true,
			expectedStatus: http.StatusFound,
			expectRedirect: "/dashboard",
		},
		{
			name:           "Dashboard without session - redirect to login",
			path:           "/dashboard",
			hasSession:     false,
			expectedStatus: http.StatusFound,
			expectRedirect: "/login",
		},
		{
			name:           "Dashboard with session - show dashboard",
			path:           "/dashboard",
			hasSession:     true,
			expectedStatus: http.StatusOK,
			expectRedirect: "",
		},
		{
			name:           "Root without session - redirect to login",
			path:           "/",
			hasSession:     false,
			expectedStatus: http.StatusFound,
			expectRedirect: "/login",
		},
		{
			name:           "Root with session - redirect to dashboard",
			path:           "/",
			hasSession:     true,
			expectedStatus: http.StatusFound,
			expectRedirect: "/dashboard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a simple template for testing
			if tt.path == "/login" || tt.path == "/dashboard" {
				tmpl := template.Must(template.New(strings.TrimPrefix(tt.path, "/")+".html").Parse(`
					<html><body><h1>{{.Title}}</h1></body></html>
				`))
				server.templateManager.templates[strings.TrimPrefix(tt.path, "/")+".html"] = tmpl
			}

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", tt.path, nil)

			// Add session if needed
			if tt.hasSession {
				mockAuthService := server.authService.(*MockAuthService)
				session := &models.Session{
					ID:        "test-session",
					UserID:    1,
					ExpiresAt: time.Now().Add(time.Hour),
					CreatedAt: time.Now(),
				}
				mockAuthService.sessions["test-session"] = session
				req.AddCookie(&http.Cookie{
					Name:  "session_id",
					Value: "test-session",
				})
			}

			server.router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, w.Code)
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