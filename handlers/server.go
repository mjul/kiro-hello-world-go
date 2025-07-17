package handlers

import (
	"fmt"
	"log"
	"net/http"
	"sso-web-app/config"
	"sso-web-app/database"
	"sso-web-app/models"
	"sso-web-app/services"
	"time"

	"github.com/gin-gonic/gin"
)

// DatabaseHealth defines the interface for database health checking
type DatabaseHealth interface {
	IsHealthy() error
}

// Server holds the Gin router and application dependencies
type Server struct {
	router          *gin.Engine
	config          *config.Config
	db              DatabaseHealth
	authService     services.AuthService
	templateManager *TemplateManager
	userRepo        services.UserRepository
}

// NewServer creates a new server instance with all dependencies
func NewServer(cfg *config.Config, db *database.DB, authService services.AuthService, userRepo services.UserRepository) *Server {
	// Set Gin mode based on environment
	if cfg.Port == "8080" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	
	// Initialize template manager
	templateManager := NewTemplateManager("templates")
	if err := templateManager.LoadTemplates(); err != nil {
		log.Printf("Warning: Failed to load templates: %v", err)
	}
	
	server := &Server{
		router:          router,
		config:          cfg,
		db:              db,
		authService:     authService,
		templateManager: templateManager,
		userRepo:        userRepo,
	}

	// Setup middleware
	server.setupMiddleware()
	
	// Setup routes
	server.setupRoutes()

	return server
}

// setupMiddleware configures all middleware for the Gin router
func (s *Server) setupMiddleware() {
	// Custom error handling middleware - replaces default recovery
	s.router.Use(s.ErrorHandlerMiddleware())

	// Server context middleware - injects server instance for error handling
	s.router.Use(s.serverContextMiddleware())

	// Enhanced structured logging middleware
	s.router.Use(s.enhancedLoggingMiddleware())

	// CORS middleware for cross-origin requests
	s.router.Use(s.corsMiddleware())

	// Security headers middleware
	s.router.Use(s.securityHeadersMiddleware())

	// Session middleware for cookie handling
	s.router.Use(s.sessionMiddleware())
}

// serverContextMiddleware injects the server instance into the context for error handling
func (s *Server) serverContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("server", s)
		c.Next()
	}
}

// loggingMiddleware provides structured request logging
func (s *Server) loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		log.Printf("[%s] %s %s %d %s %s",
			param.TimeStamp.Format("2006/01/02 - 15:04:05"),
			param.Method,
			param.Path,
			param.StatusCode,
			param.Latency,
			param.ClientIP,
		)
		return ""
	})
}

// corsMiddleware handles Cross-Origin Resource Sharing
func (s *Server) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// Allow requests from the same origin or localhost for development
		if origin == s.config.BaseURL || origin == "http://localhost:8080" {
			c.Header("Access-Control-Allow-Origin", origin)
		}
		
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// securityHeadersMiddleware adds security headers to all responses
func (s *Server) securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")
		
		// Enable XSS protection
		c.Header("X-XSS-Protection", "1; mode=block")
		
		// Prevent clickjacking
		c.Header("X-Frame-Options", "DENY")
		
		// Enforce HTTPS in production
		if s.config.BaseURL != "http://localhost:8080" {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		
		// Content Security Policy
		c.Header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'")
		
		// Referrer Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		c.Next()
	}
}

// sessionMiddleware handles session cookie management
func (s *Server) sessionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session cookie
		sessionID, err := c.Cookie("session_id")
		if err != nil {
			// No session cookie found, continue without session
			c.Next()
			return
		}

		// Validate session
		session, err := s.authService.ValidateSession(sessionID)
		if err != nil {
			// Invalid or expired session, clear the cookie
			s.clearSessionCookie(c)
			c.Next()
			return
		}

		// Store session in context for use by handlers
		c.Set("session", session)
		c.Set("session_id", sessionID)
		
		c.Next()
	}
}

// setSessionCookie sets a secure session cookie
func (s *Server) setSessionCookie(c *gin.Context, sessionID string, maxAge int) {
	secure := s.config.BaseURL != "http://localhost:8080" // HTTPS only in production
	
	c.SetCookie(
		"session_id",           // name
		sessionID,              // value
		maxAge,                 // maxAge (seconds)
		"/",                    // path
		"",                     // domain (empty for same domain)
		secure,                 // secure (HTTPS only)
		true,                   // httpOnly (prevent XSS)
	)
	
	// Set SameSite attribute manually for additional CSRF protection
	if secure {
		c.Header("Set-Cookie", c.Writer.Header().Get("Set-Cookie")+"; SameSite=Strict")
	} else {
		c.Header("Set-Cookie", c.Writer.Header().Get("Set-Cookie")+"; SameSite=Lax")
	}
}

// clearSessionCookie clears the session cookie
func (s *Server) clearSessionCookie(c *gin.Context) {
	c.SetCookie(
		"session_id",
		"",
		-1,    // maxAge -1 deletes the cookie
		"/",
		"",
		false, // secure
		true,  // httpOnly
	)
}

// setupRoutes configures all application routes
func (s *Server) setupRoutes() {
	// Health check endpoint
	s.router.GET("/health", s.healthCheckHandler)
	
	// Public routes (redirect authenticated users)
	public := s.router.Group("/")
	public.Use(s.redirectIfAuthenticatedMiddleware())
	{
		public.GET("/login", s.loginPageHandler)
	}
	
	// Authentication routes (no middleware needed)
	s.router.GET("/auth/:provider", s.oauthInitiateHandler)
	s.router.GET("/auth/callback/:provider", s.oauthCallbackHandler)
	
	// Protected routes (require authentication)
	protected := s.router.Group("/")
	protected.Use(s.requireAuthMiddleware())
	{
		protected.GET("/dashboard", s.dashboardHandler)
		protected.POST("/logout", s.logoutHandler)
	}
	
	// Root route (special handling)
	s.router.GET("/", s.rootHandler)
}

// healthCheckHandler provides a health check endpoint for monitoring
func (s *Server) healthCheckHandler(c *gin.Context) {
	// Check database health
	if err := s.db.IsHealthy(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "unhealthy",
			"error":  "database connection failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   "1.0.0",
	})
}

// Start starts the HTTP server
func (s *Server) Start() error {
	log.Printf("Starting server on port %s", s.config.Port)
	return s.router.Run(":" + s.config.Port)
}

// GetRouter returns the Gin router for testing purposes
func (s *Server) GetRouter() *gin.Engine {
	return s.router
}

// Router returns the Gin router instance
func (s *Server) Router() *gin.Engine {
	return s.router
}

// GetTemplateManager returns the template manager for testing purposes
func (s *Server) GetTemplateManager() *TemplateManager {
	return s.templateManager
}

// loginPageHandler displays the login page with OAuth provider options
func (s *Server) loginPageHandler(c *gin.Context) {
	// Check if user is already authenticated
	if session, exists := c.Get("session"); exists && session != nil {
		// User is already logged in, redirect to dashboard
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}

	// Get error message from query parameters (if any)
	errorMsg := c.Query("error")

	// Prepare template data
	data := LoginPageData{
		Title: "Login - SSO Web App",
		Error: errorMsg,
	}

	// Render login template
	s.templateManager.RenderTemplate(c, "login.html", data)
}

// oauthInitiateHandler initiates the OAuth2 flow for the specified provider
func (s *Server) oauthInitiateHandler(c *gin.Context) {
	providerParam := c.Param("provider")
	
	// Convert string to SupportedProvider
	var provider services.SupportedProvider
	switch providerParam {
	case "microsoft":
		provider = services.ProviderMicrosoft
	case "github":
		provider = services.ProviderGitHub
	default:
		err := NewValidationError("OAUTH_INVALID_PROVIDER", 
			fmt.Sprintf("Unsupported OAuth provider: %s", providerParam),
			"The selected authentication provider is not supported.", nil)
		s.HandleError(c, err)
		return
	}

	// Initiate OAuth flow
	authURL, state, err := s.authService.InitiateOAuth(provider)
	if err != nil {
		appErr := NewOAuthError("OAUTH_INITIATE_FAILED", 
			fmt.Sprintf("Failed to initiate OAuth for provider %s", provider), err)
		s.HandleError(c, appErr)
		return
	}

	// Store state in session for CSRF protection (optional additional security)
	c.SetCookie("oauth_state", state, 600, "/", "", false, true) // 10 minutes

	// Redirect to OAuth provider
	c.Redirect(http.StatusFound, authURL)
}

// oauthCallbackHandler handles the OAuth2 callback from the provider
func (s *Server) oauthCallbackHandler(c *gin.Context) {
	providerParam := c.Param("provider")
	
	// Convert string to SupportedProvider
	var provider services.SupportedProvider
	switch providerParam {
	case "microsoft":
		provider = services.ProviderMicrosoft
	case "github":
		provider = services.ProviderGitHub
	default:
		err := NewValidationError("OAUTH_INVALID_PROVIDER", 
			fmt.Sprintf("Unsupported OAuth provider: %s", providerParam),
			"The selected authentication provider is not supported.", nil)
		s.HandleError(c, err)
		return
	}

	// Get authorization code and state from query parameters
	code := c.Query("code")
	state := c.Query("state")

	// Check for OAuth errors
	if oauthError := c.Query("error"); oauthError != "" {
		errorDescription := c.Query("error_description")
		details := fmt.Sprintf("OAuth error from %s: %s - %s", provider, oauthError, errorDescription)
		err := NewOAuthError("OAUTH_PROVIDER_ERROR", details, nil)
		s.HandleError(c, err)
		return
	}

	// Validate required parameters
	if code == "" {
		err := NewOAuthError("OAUTH_MISSING_CODE", 
			fmt.Sprintf("Missing authorization code in OAuth callback for %s", provider), nil)
		s.HandleError(c, err)
		return
	}

	if state == "" {
		err := NewOAuthError("OAUTH_MISSING_STATE", 
			fmt.Sprintf("Missing state parameter in OAuth callback for %s", provider), nil)
		s.HandleError(c, err)
		return
	}

	// Optional: Verify state cookie matches (additional CSRF protection)
	if stateCookie, err := c.Cookie("oauth_state"); err == nil {
		if stateCookie != state {
			details := fmt.Sprintf("State parameter mismatch for %s: cookie=%s, param=%s", provider, stateCookie, state)
			appErr := NewOAuthError("OAUTH_STATE_MISMATCH", details, nil)
			s.HandleError(c, appErr)
			return
		}
		// Clear the state cookie
		c.SetCookie("oauth_state", "", -1, "/", "", false, true)
	}

	// Handle OAuth callback
	user, session, err := s.authService.HandleCallback(provider, code, state)
	if err != nil {
		// Log failed authentication attempt
		logger := NewLogger(LogLevelInfo)
		logger.LogAuthentication("callback_failed", 0, string(provider), false, map[string]interface{}{
			"error": err.Error(),
			"code":  code,
		})
		
		appErr := NewOAuthError("OAUTH_CALLBACK_FAILED", 
			fmt.Sprintf("Failed to handle OAuth callback for %s", provider), err)
		s.HandleError(c, appErr)
		return
	}

	// Set session cookie
	s.setSessionCookie(c, session.ID, int(session.TimeUntilExpiry().Seconds()))

	// Log successful authentication
	logger := NewLogger(LogLevelInfo)
	logger.LogAuthentication("login_success", user.ID, string(provider), true, map[string]interface{}{
		"username":   user.Username,
		"session_id": session.ID,
	})

	// Redirect to dashboard
	c.Redirect(http.StatusFound, "/dashboard")
}

// rootHandler handles the root path and redirects based on authentication status
func (s *Server) rootHandler(c *gin.Context) {
	// Check if user is authenticated
	if session, exists := c.Get("session"); exists && session != nil {
		// User is authenticated, redirect to dashboard
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}

	// User is not authenticated, redirect to login
	c.Redirect(http.StatusFound, "/login")
}

// dashboardHandler displays the user dashboard for authenticated users
func (s *Server) dashboardHandler(c *gin.Context) {
	// Get user from context (set by requireAuthMiddleware)
	userInterface, exists := c.Get("user")
	if !exists {
		err := NewAuthenticationError("AUTH_USER_NOT_FOUND", "User not found in context", nil)
		s.HandleError(c, err)
		return
	}

	user, ok := userInterface.(*models.User)
	if !ok {
		err := NewAuthenticationError("AUTH_INVALID_USER_TYPE", "Invalid user type in context", nil)
		s.HandleError(c, err)
		return
	}

	// Prepare template data with actual user information
	data := DashboardPageData{
		Title:    "Dashboard - SSO Web App",
		Username: user.Username,
		Email:    user.Email,
		Avatar:   user.AvatarURL,
		Provider: user.Provider,
	}

	log.Printf("Dashboard accessed by user %s (ID: %d)", user.Username, user.ID)
	
	// Render dashboard template
	s.templateManager.RenderTemplate(c, "dashboard.html", data)
}

// logoutHandler handles user logout by destroying the session
func (s *Server) logoutHandler(c *gin.Context) {
	var userID int
	var sessionIDStr string
	
	// Get user information for logging
	if userInterface, exists := c.Get("user"); exists {
		if user, ok := userInterface.(*models.User); ok {
			userID = user.ID
		}
	}
	
	// Get session ID from context
	sessionID, exists := c.Get("session_id")
	if exists && sessionID != nil {
		if sessionIDString, ok := sessionID.(string); ok {
			sessionIDStr = sessionIDString
			// Destroy the session
			if err := s.authService.DestroySession(sessionIDStr); err != nil {
				// Log failed logout attempt
				logger := NewLogger(LogLevelInfo)
				logger.LogAuthentication("logout_failed", userID, "", false, map[string]interface{}{
					"session_id": sessionIDStr,
					"error":      err.Error(),
				})
			} else {
				// Log successful logout
				logger := NewLogger(LogLevelInfo)
				logger.LogAuthentication("logout_success", userID, "", true, map[string]interface{}{
					"session_id": sessionIDStr,
				})
			}
		}
	}

	// Clear the session cookie
	s.clearSessionCookie(c)

	// Redirect to login page
	c.Redirect(http.StatusFound, "/login")
}

// requireAuthMiddleware is middleware that requires user authentication
func (s *Server) requireAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if user is authenticated
		session, exists := c.Get("session")
		if !exists || session == nil {
			// User is not authenticated, redirect to login
			err := NewAuthenticationError("AUTH_SESSION_REQUIRED", "Authentication required", nil)
			s.HandleError(c, err)
			c.Abort()
			return
		}

		// Validate session type
		userSession, ok := session.(*models.Session)
		if !ok {
			err := NewSessionError("SESSION_INVALID", "Invalid session type in context", nil)
			s.HandleError(c, err)
			c.Abort()
			return
		}

		// Get user information and store in context for handlers
		user, err := s.userRepo.FindByID(userSession.UserID)
		if err != nil {
			appErr := NewDatabaseError("DB_USER_FETCH_FAILED", 
				fmt.Sprintf("Failed to fetch user %d", userSession.UserID), err)
			s.HandleError(c, appErr)
			c.Abort()
			return
		}

		if user == nil {
			err := NewDatabaseError("DB_USER_NOT_FOUND", 
				fmt.Sprintf("User %d not found", userSession.UserID), nil)
			s.HandleError(c, err)
			c.Abort()
			return
		}

		// Store user in context for use by handlers
		c.Set("user", user)
		c.Next()
	}
}

// redirectIfAuthenticatedMiddleware redirects authenticated users away from auth pages
func (s *Server) redirectIfAuthenticatedMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if user is already authenticated
		if session, exists := c.Get("session"); exists && session != nil {
			// User is already logged in, redirect to dashboard
			c.Redirect(http.StatusFound, "/dashboard")
			c.Abort()
			return
		}
		c.Next()
	}
}