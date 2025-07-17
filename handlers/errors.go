package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorType represents different types of application errors
type ErrorType string

const (
	ErrorTypeAuthentication ErrorType = "authentication"
	ErrorTypeDatabase       ErrorType = "database"
	ErrorTypeValidation     ErrorType = "validation"
	ErrorTypeOAuth          ErrorType = "oauth"
	ErrorTypeSession        ErrorType = "session"
	ErrorTypeTemplate       ErrorType = "template"
	ErrorTypeInternal       ErrorType = "internal"
)

// AppError represents a structured application error
type AppError struct {
	Type        ErrorType `json:"type"`
	Code        string    `json:"code"`
	Message     string    `json:"message"`
	UserMessage string    `json:"user_message"`
	Details     string    `json:"details,omitempty"`
	StatusCode  int       `json:"status_code"`
	Cause       error     `json:"-"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error for error unwrapping
func (e *AppError) Unwrap() error {
	return e.Cause
}

// NewAppError creates a new application error
func NewAppError(errorType ErrorType, code, message, userMessage string, statusCode int, cause error) *AppError {
	return &AppError{
		Type:        errorType,
		Code:        code,
		Message:     message,
		UserMessage: userMessage,
		StatusCode:  statusCode,
		Cause:       cause,
	}
}

// Predefined error constructors for common scenarios

// NewAuthenticationError creates an authentication-related error
func NewAuthenticationError(code, message string, cause error) *AppError {
	userMessage := "Authentication failed. Please try logging in again."
	if code == "AUTH_INVALID_CREDENTIALS" {
		userMessage = "Invalid credentials provided."
	} else if code == "AUTH_SESSION_EXPIRED" {
		userMessage = "Your session has expired. Please log in again."
	}
	
	return NewAppError(ErrorTypeAuthentication, code, message, userMessage, http.StatusUnauthorized, cause)
}

// NewDatabaseError creates a database-related error
func NewDatabaseError(code, message string, cause error) *AppError {
	userMessage := "A database error occurred. Please try again later."
	if code == "DB_CONNECTION_FAILED" {
		userMessage = "Unable to connect to the database. Please try again later."
	} else if code == "DB_RECORD_NOT_FOUND" {
		userMessage = "The requested information was not found."
	}
	
	return NewAppError(ErrorTypeDatabase, code, message, userMessage, http.StatusInternalServerError, cause)
}

// NewValidationError creates a validation-related error
func NewValidationError(code, message, userMessage string, cause error) *AppError {
	if userMessage == "" {
		userMessage = "Invalid input provided. Please check your data and try again."
	}
	
	return NewAppError(ErrorTypeValidation, code, message, userMessage, http.StatusBadRequest, cause)
}

// NewOAuthError creates an OAuth-related error
func NewOAuthError(code, message string, cause error) *AppError {
	userMessage := "Authentication with the external provider failed. Please try again."
	if code == "OAUTH_STATE_MISMATCH" {
		userMessage = "Security validation failed. Please try logging in again."
	} else if code == "OAUTH_PROVIDER_ERROR" {
		userMessage = "The authentication provider returned an error. Please try again."
	}
	
	return NewAppError(ErrorTypeOAuth, code, message, userMessage, http.StatusBadRequest, cause)
}

// NewSessionError creates a session-related error
func NewSessionError(code, message string, cause error) *AppError {
	userMessage := "Session error occurred. Please log in again."
	if code == "SESSION_INVALID" {
		userMessage = "Your session is invalid. Please log in again."
	} else if code == "SESSION_EXPIRED" {
		userMessage = "Your session has expired. Please log in again."
	}
	
	return NewAppError(ErrorTypeSession, code, message, userMessage, http.StatusUnauthorized, cause)
}

// NewTemplateError creates a template-related error
func NewTemplateError(code, message string, cause error) *AppError {
	userMessage := "A page rendering error occurred. Please try again."
	
	return NewAppError(ErrorTypeTemplate, code, message, userMessage, http.StatusInternalServerError, cause)
}

// NewInternalError creates an internal server error
func NewInternalError(code, message string, cause error) *AppError {
	userMessage := "An internal server error occurred. Please try again later."
	
	return NewAppError(ErrorTypeInternal, code, message, userMessage, http.StatusInternalServerError, cause)
}

// ErrorPageData represents data for the error page template
type ErrorPageData struct {
	Title       string
	ErrorCode   string
	Message     string
	Details     string
	ShowDetails bool
	BackURL     string
}

// HandleError processes application errors and responds appropriately
func (s *Server) HandleError(c *gin.Context, err error) {
	var appErr *AppError
	
	// Check if it's already an AppError
	if e, ok := err.(*AppError); ok {
		appErr = e
	} else {
		// Wrap unknown errors as internal errors
		appErr = NewInternalError("INTERNAL_UNKNOWN", "Unknown error occurred", err)
	}
	
	// Log the error with context
	s.logError(c, appErr)
	
	// Determine response format based on request
	if s.isAPIRequest(c) {
		s.handleAPIError(c, appErr)
	} else {
		s.handleWebError(c, appErr)
	}
}

// logError logs the error with appropriate context using structured logging
func (s *Server) logError(c *gin.Context, appErr *AppError) {
	logger := NewLogger(LogLevelInfo)
	logger.LogError(c, appErr)
}

// isAPIRequest determines if the request expects a JSON response
func (s *Server) isAPIRequest(c *gin.Context) bool {
	// Check Accept header
	accept := c.GetHeader("Accept")
	if accept == "application/json" || accept == "application/json, */*" {
		return true
	}
	
	// Check Content-Type header
	contentType := c.GetHeader("Content-Type")
	if contentType == "application/json" {
		return true
	}
	
	// Check if path starts with /api/
	if len(c.Request.URL.Path) >= 5 && c.Request.URL.Path[:5] == "/api/" {
		return true
	}
	
	return false
}

// handleAPIError handles errors for API requests (JSON response)
func (s *Server) handleAPIError(c *gin.Context, appErr *AppError) {
	response := gin.H{
		"error": gin.H{
			"type":    appErr.Type,
			"code":    appErr.Code,
			"message": appErr.UserMessage,
		},
		"success": false,
	}
	
	// Add details in development mode
	if gin.Mode() == gin.DebugMode {
		response["error"].(gin.H)["details"] = appErr.Message
		if appErr.Details != "" {
			response["error"].(gin.H)["internal_details"] = appErr.Details
		}
	}
	
	c.JSON(appErr.StatusCode, response)
}

// handleWebError handles errors for web requests (HTML response)
func (s *Server) handleWebError(c *gin.Context, appErr *AppError) {
	// For authentication and session errors, redirect to login
	if appErr.Type == ErrorTypeAuthentication || appErr.Type == ErrorTypeSession {
		// For logout and dashboard requests, redirect without error message
		if c.Request.URL.Path == "/logout" || c.Request.URL.Path == "/dashboard" {
			c.Redirect(http.StatusFound, "/login")
			return
		}
		// For other requests, include error message
		redirectURL := fmt.Sprintf("/login?error=%s", appErr.UserMessage)
		c.Redirect(http.StatusFound, redirectURL)
		return
	}
	
	// For OAuth errors during callback, redirect to login with error
	if appErr.Type == ErrorTypeOAuth {
		redirectURL := fmt.Sprintf("/login?error=%s", appErr.UserMessage)
		c.Redirect(http.StatusFound, redirectURL)
		return
	}
	
	// For validation errors (like invalid provider), redirect to login with error
	if appErr.Type == ErrorTypeValidation {
		redirectURL := fmt.Sprintf("/login?error=%s", appErr.UserMessage)
		c.Redirect(http.StatusFound, redirectURL)
		return
	}
	
	// For database errors related to user not found, redirect to login
	if appErr.Type == ErrorTypeDatabase && appErr.Code == "DB_USER_NOT_FOUND" {
		redirectURL := fmt.Sprintf("/login?error=%s", appErr.UserMessage)
		c.Redirect(http.StatusFound, redirectURL)
		return
	}
	
	// For template errors, use fallback HTML to avoid infinite loop
	if appErr.Type == ErrorTypeTemplate {
		s.renderFallbackError(c, appErr)
		return
	}
	
	// For other errors, try to show error page template
	data := ErrorPageData{
		Title:       "Error - SSO Web App",
		ErrorCode:   appErr.Code,
		Message:     appErr.UserMessage,
		Details:     appErr.Message,
		ShowDetails: gin.Mode() == gin.DebugMode,
		BackURL:     s.getBackURL(c),
	}
	
	c.Status(appErr.StatusCode)
	
	// Check if error template exists before trying to render it
	if s.templateManager.HasTemplate("error.html") {
		s.templateManager.RenderTemplate(c, "error.html", data)
	} else {
		// Fallback to simple HTML if error template is missing
		s.renderFallbackError(c, appErr)
	}
}

// getBackURL determines the appropriate back URL for error pages
func (s *Server) getBackURL(c *gin.Context) string {
	// Check referer header
	if referer := c.GetHeader("Referer"); referer != "" {
		return referer
	}
	
	// Default back URLs based on current path
	path := c.Request.URL.Path
	if path == "/dashboard" || path == "/logout" {
		return "/dashboard"
	}
	
	return "/login"
}

// renderFallbackError renders a simple HTML error page without using templates
// This prevents infinite loops when template errors occur
func (s *Server) renderFallbackError(c *gin.Context, appErr *AppError) {
	c.Status(appErr.StatusCode)
	c.Header("Content-Type", "text/html; charset=utf-8")
	
	// Simple HTML error page
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - SSO Web App</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .error-container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .error-title { color: #d32f2f; font-size: 24px; margin-bottom: 20px; }
        .error-message { color: #333; font-size: 16px; margin-bottom: 20px; }
        .error-code { color: #666; font-size: 14px; margin-bottom: 20px; font-family: monospace; }
        .back-link { display: inline-block; padding: 10px 20px; background-color: #1976d2; color: white; text-decoration: none; border-radius: 4px; }
        .back-link:hover { background-color: #1565c0; }
    </style>
</head>
<body>
    <div class="error-container">
        <h1 class="error-title">Error</h1>
        <p class="error-message">%s</p>
        <p class="error-code">Error Code: %s</p>
        <a href="%s" class="back-link">Go Back</a>
    </div>
</body>
</html>`, appErr.UserMessage, appErr.Code, s.getBackURL(c))
	
	c.Writer.WriteString(html)
}

// ErrorHandlerMiddleware is a middleware that catches panics and converts them to errors
func (s *Server) ErrorHandlerMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		var err error
		
		// Convert panic to error
		if e, ok := recovered.(error); ok {
			err = e
		} else {
			err = fmt.Errorf("panic: %v", recovered)
		}
		
		// Create internal error
		appErr := NewInternalError("INTERNAL_PANIC", "Application panic occurred", err)
		
		// Handle the error
		s.HandleError(c, appErr)
		
		// Abort the request
		c.Abort()
	})
}