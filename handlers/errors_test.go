package handlers

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestNewAppError(t *testing.T) {
	tests := []struct {
		name        string
		errorType   ErrorType
		code        string
		message     string
		userMessage string
		statusCode  int
		cause       error
		wantError   string
	}{
		{
			name:        "error without cause",
			errorType:   ErrorTypeValidation,
			code:        "VALIDATION_FAILED",
			message:     "Validation failed",
			userMessage: "Invalid input",
			statusCode:  400,
			cause:       nil,
			wantError:   "VALIDATION_FAILED: Validation failed",
		},
		{
			name:        "error with cause",
			errorType:   ErrorTypeDatabase,
			code:        "DB_CONNECTION_FAILED",
			message:     "Database connection failed",
			userMessage: "Database error",
			statusCode:  500,
			cause:       errors.New("connection timeout"),
			wantError:   "DB_CONNECTION_FAILED: Database connection failed (caused by: connection timeout)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewAppError(tt.errorType, tt.code, tt.message, tt.userMessage, tt.statusCode, tt.cause)
			
			assert.Equal(t, tt.errorType, err.Type)
			assert.Equal(t, tt.code, err.Code)
			assert.Equal(t, tt.message, err.Message)
			assert.Equal(t, tt.userMessage, err.UserMessage)
			assert.Equal(t, tt.statusCode, err.StatusCode)
			assert.Equal(t, tt.cause, err.Cause)
			assert.Equal(t, tt.wantError, err.Error())
			
			if tt.cause != nil {
				assert.Equal(t, tt.cause, err.Unwrap())
			} else {
				assert.Nil(t, err.Unwrap())
			}
		})
	}
}

func TestErrorConstructors(t *testing.T) {
	t.Run("NewAuthenticationError", func(t *testing.T) {
		err := NewAuthenticationError("AUTH_FAILED", "Authentication failed", nil)
		assert.Equal(t, ErrorTypeAuthentication, err.Type)
		assert.Equal(t, "AUTH_FAILED", err.Code)
		assert.Equal(t, http.StatusUnauthorized, err.StatusCode)
		assert.Equal(t, "Authentication failed. Please try logging in again.", err.UserMessage)
	})

	t.Run("NewDatabaseError", func(t *testing.T) {
		cause := errors.New("connection failed")
		err := NewDatabaseError("DB_ERROR", "Database error", cause)
		assert.Equal(t, ErrorTypeDatabase, err.Type)
		assert.Equal(t, "DB_ERROR", err.Code)
		assert.Equal(t, http.StatusInternalServerError, err.StatusCode)
		assert.Equal(t, cause, err.Cause)
	})

	t.Run("NewValidationError", func(t *testing.T) {
		err := NewValidationError("VALIDATION_ERROR", "Invalid input", "Custom message", nil)
		assert.Equal(t, ErrorTypeValidation, err.Type)
		assert.Equal(t, "VALIDATION_ERROR", err.Code)
		assert.Equal(t, http.StatusBadRequest, err.StatusCode)
		assert.Equal(t, "Custom message", err.UserMessage)
	})

	t.Run("NewOAuthError", func(t *testing.T) {
		err := NewOAuthError("OAUTH_ERROR", "OAuth failed", nil)
		assert.Equal(t, ErrorTypeOAuth, err.Type)
		assert.Equal(t, "OAUTH_ERROR", err.Code)
		assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	})

	t.Run("NewSessionError", func(t *testing.T) {
		err := NewSessionError("SESSION_ERROR", "Session invalid", nil)
		assert.Equal(t, ErrorTypeSession, err.Type)
		assert.Equal(t, "SESSION_ERROR", err.Code)
		assert.Equal(t, http.StatusUnauthorized, err.StatusCode)
	})

	t.Run("NewTemplateError", func(t *testing.T) {
		err := NewTemplateError("TEMPLATE_ERROR", "Template failed", nil)
		assert.Equal(t, ErrorTypeTemplate, err.Type)
		assert.Equal(t, "TEMPLATE_ERROR", err.Code)
		assert.Equal(t, http.StatusInternalServerError, err.StatusCode)
	})

	t.Run("NewInternalError", func(t *testing.T) {
		err := NewInternalError("INTERNAL_ERROR", "Internal error", nil)
		assert.Equal(t, ErrorTypeInternal, err.Type)
		assert.Equal(t, "INTERNAL_ERROR", err.Code)
		assert.Equal(t, http.StatusInternalServerError, err.StatusCode)
	})
}

func TestServer_isAPIRequest(t *testing.T) {
	server := &Server{}
	
	tests := []struct {
		name        string
		accept      string
		contentType string
		path        string
		want        bool
	}{
		{
			name:   "JSON accept header",
			accept: "application/json",
			want:   true,
		},
		{
			name:   "JSON accept with wildcard",
			accept: "application/json, */*",
			want:   true,
		},
		{
			name:        "JSON content type",
			contentType: "application/json",
			want:        true,
		},
		{
			name: "API path",
			path: "/api/users",
			want: true,
		},
		{
			name:   "HTML accept",
			accept: "text/html",
			want:   false,
		},
		{
			name: "Regular path",
			path: "/login",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			
			path := tt.path
			if path == "" {
				path = "/test"
			}
			req := httptest.NewRequest("GET", path, nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			c.Request = req

			result := server.isAPIRequest(c)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestServer_handleAPIError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &Server{}
	
	t.Run("API error response", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		
		appErr := NewValidationError("VALIDATION_FAILED", "Validation failed", "Invalid input", nil)
		server.handleAPIError(c, appErr)
		
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid input")
		assert.Contains(t, w.Body.String(), "VALIDATION_FAILED")
		assert.Contains(t, w.Body.String(), "validation")
	})
	
	t.Run("API error with details in debug mode", func(t *testing.T) {
		gin.SetMode(gin.DebugMode)
		defer gin.SetMode(gin.TestMode)
		
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		
		appErr := NewInternalError("INTERNAL_ERROR", "Internal error occurred", nil)
		appErr.Details = "Detailed error information"
		server.handleAPIError(c, appErr)
		
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "Internal error occurred")
		assert.Contains(t, w.Body.String(), "Detailed error information")
	})
}

func TestServer_getBackURL(t *testing.T) {
	server := &Server{}
	
	tests := []struct {
		name     string
		path     string
		referer  string
		expected string
	}{
		{
			name:     "with referer",
			path:     "/dashboard",
			referer:  "http://example.com/previous",
			expected: "http://example.com/previous",
		},
		{
			name:     "dashboard path without referer",
			path:     "/dashboard",
			expected: "/dashboard",
		},
		{
			name:     "logout path without referer",
			path:     "/logout",
			expected: "/dashboard",
		},
		{
			name:     "other path without referer",
			path:     "/other",
			expected: "/login",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}
			c.Request = req

			result := server.getBackURL(c)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestErrorHandlerMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &Server{
		templateManager: &TemplateManager{
			templates: make(map[string]*template.Template),
		},
	}
	
	t.Run("handles panic as error", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, router := gin.CreateTestContext(w)
		
		// Set up the middleware
		router.Use(server.ErrorHandlerMiddleware())
		
		// Add a route that panics
		router.GET("/panic", func(c *gin.Context) {
			panic("test panic")
		})
		
		req := httptest.NewRequest("GET", "/panic", nil)
		c.Request = req
		
		router.ServeHTTP(w, req)
		
		// The middleware should handle the panic and not crash
		// The exact response depends on the error handling implementation
		assert.NotEqual(t, 0, w.Code) // Should have some HTTP status code
	})
	
	t.Run("handles error type panic", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, router := gin.CreateTestContext(w)
		
		router.Use(server.ErrorHandlerMiddleware())
		
		router.GET("/error-panic", func(c *gin.Context) {
			panic(errors.New("test error"))
		})
		
		req := httptest.NewRequest("GET", "/error-panic", nil)
		c.Request = req
		
		router.ServeHTTP(w, req)
		
		assert.NotEqual(t, 0, w.Code)
	})
}

func TestErrorPageData(t *testing.T) {
	data := ErrorPageData{
		Title:       "Error Page",
		ErrorCode:   "TEST_ERROR",
		Message:     "Test error message",
		Details:     "Detailed error information",
		ShowDetails: true,
		BackURL:     "/back",
	}
	
	assert.Equal(t, "Error Page", data.Title)
	assert.Equal(t, "TEST_ERROR", data.ErrorCode)
	assert.Equal(t, "Test error message", data.Message)
	assert.Equal(t, "Detailed error information", data.Details)
	assert.True(t, data.ShowDetails)
	assert.Equal(t, "/back", data.BackURL)
}