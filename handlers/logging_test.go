package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogger(t *testing.T) {
	logger := NewLogger(LogLevelInfo)
	assert.NotNil(t, logger)
	assert.Equal(t, LogLevelInfo, logger.level)
	assert.NotNil(t, logger.output)
}

func TestLogger_shouldLog(t *testing.T) {
	tests := []struct {
		name         string
		loggerLevel  LogLevel
		messageLevel LogLevel
		shouldLog    bool
	}{
		{
			name:         "debug logger logs debug message",
			loggerLevel:  LogLevelDebug,
			messageLevel: LogLevelDebug,
			shouldLog:    true,
		},
		{
			name:         "debug logger logs info message",
			loggerLevel:  LogLevelDebug,
			messageLevel: LogLevelInfo,
			shouldLog:    true,
		},
		{
			name:         "info logger does not log debug message",
			loggerLevel:  LogLevelInfo,
			messageLevel: LogLevelDebug,
			shouldLog:    false,
		},
		{
			name:         "info logger logs info message",
			loggerLevel:  LogLevelInfo,
			messageLevel: LogLevelInfo,
			shouldLog:    true,
		},
		{
			name:         "warn logger logs error message",
			loggerLevel:  LogLevelWarn,
			messageLevel: LogLevelError,
			shouldLog:    true,
		},
		{
			name:         "error logger does not log warn message",
			loggerLevel:  LogLevelError,
			messageLevel: LogLevelWarn,
			shouldLog:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.loggerLevel)
			result := logger.shouldLog(tt.messageLevel)
			assert.Equal(t, tt.shouldLog, result)
		})
	}
}

func TestLogger_log(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:  LogLevelInfo,
		output: &buf,
	}

	entry := LogEntry{
		Level:     LogLevelInfo,
		Message:   "test message",
		Component: "test",
		Extra: map[string]interface{}{
			"key": "value",
		},
	}

	logger.log(entry)

	output := buf.String()
	assert.Contains(t, output, "test message")
	assert.Contains(t, output, "INFO")
	assert.Contains(t, output, "test")
	assert.Contains(t, output, "key")
	assert.Contains(t, output, "value")

	// Verify it's valid JSON
	var loggedEntry LogEntry
	err := json.Unmarshal([]byte(strings.TrimSpace(output)), &loggedEntry)
	require.NoError(t, err)
	assert.Equal(t, LogLevelInfo, loggedEntry.Level)
	assert.Equal(t, "test message", loggedEntry.Message)
	assert.Equal(t, "test", loggedEntry.Component)
}

func TestLogger_Debug(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:  LogLevelDebug,
		output: &buf,
	}

	fields := map[string]interface{}{
		"user_id": 123,
		"action":  "test",
	}

	logger.Debug("debug message", fields)

	output := buf.String()
	assert.Contains(t, output, "debug message")
	assert.Contains(t, output, "DEBUG")
	assert.Contains(t, output, "123")
	assert.Contains(t, output, "test")
}

func TestLogger_Info(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:  LogLevelInfo,
		output: &buf,
	}

	fields := map[string]interface{}{
		"request_id": "req-123",
	}

	logger.Info("info message", fields)

	output := buf.String()
	assert.Contains(t, output, "info message")
	assert.Contains(t, output, "INFO")
	assert.Contains(t, output, "req-123")
}

func TestLogger_Warn(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:  LogLevelWarn,
		output: &buf,
	}

	fields := map[string]interface{}{
		"warning_type": "validation",
	}

	logger.Warn("warning message", fields)

	output := buf.String()
	assert.Contains(t, output, "warning message")
	assert.Contains(t, output, "WARN")
	assert.Contains(t, output, "validation")
}

func TestLogger_Error(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:  LogLevelError,
		output: &buf,
	}

	fields := map[string]interface{}{
		"error_code": "DB_ERROR",
	}

	logger.Error("error message", fields)

	output := buf.String()
	assert.Contains(t, output, "error message")
	assert.Contains(t, output, "ERROR")
	assert.Contains(t, output, "DB_ERROR")
}

func TestLogger_LogRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := &Logger{
		level:  LogLevelInfo,
		output: &buf,
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/test?param=value", nil)
	req.Header.Set("User-Agent", "test-agent")
	c.Request = req

	// Set user context
	c.Set("user", &mockUser{id: 123})
	c.Set("session_id", "session-123")
	c.Set("request_id", "req-123")

	duration := 100 * time.Millisecond
	statusCode := 200

	logger.LogRequest(c, duration, statusCode)

	output := buf.String()
	assert.Contains(t, output, "HTTP Request")
	assert.Contains(t, output, "GET")
	assert.Contains(t, output, "/test")
	assert.Contains(t, output, "200")
	assert.Contains(t, output, "test-agent")
	assert.Contains(t, output, "123") // user ID
	assert.Contains(t, output, "session-123")
	assert.Contains(t, output, "req-123")
}

func TestLogger_LogAuthentication(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:  LogLevelInfo,
		output: &buf,
	}

	details := map[string]interface{}{
		"username": "testuser",
		"ip":       "192.168.1.1",
	}

	logger.LogAuthentication("login_attempt", 123, "github", true, details)

	output := buf.String()
	assert.Contains(t, output, "Authentication login_attempt")
	assert.Contains(t, output, "123")
	assert.Contains(t, output, "github")
	assert.Contains(t, output, "testuser")
	assert.Contains(t, output, "192.168.1.1")
	assert.Contains(t, output, "true")
}

func TestLogger_LogError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := &Logger{
		level:  LogLevelInfo,
		output: &buf,
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("POST", "/api/test", nil)
	c.Request = req
	c.Set("user", &mockUser{id: 456})
	c.Set("session_id", "session-456")

	appErr := NewDatabaseError("DB_CONNECTION_FAILED", "Database connection failed", nil)
	appErr.Details = "Connection timeout after 30s"

	logger.LogError(c, appErr)

	output := buf.String()
	assert.Contains(t, output, "Database connection failed")
	assert.Contains(t, output, "ERROR")
	assert.Contains(t, output, "DB_CONNECTION_FAILED")
	assert.Contains(t, output, "database")
	assert.Contains(t, output, "POST")
	assert.Contains(t, output, "/api/test")
	assert.Contains(t, output, "456")
	assert.Contains(t, output, "session-456")
	assert.Contains(t, output, "Connection timeout after 30s")
}

func TestResponseWriter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	responseWriter := newResponseWriter(c.Writer)

	// Test writing data
	data := []byte("test response")
	n, err := responseWriter.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, "test response", responseWriter.body.String())

	// Test writing header
	responseWriter.WriteHeader(http.StatusCreated)
	assert.Equal(t, http.StatusCreated, responseWriter.statusCode)
}

func TestShouldLogRequestBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name        string
		method      string
		contentType string
		length      int64
		expected    bool
	}{
		{
			name:     "GET request",
			method:   "GET",
			expected: false,
		},
		{
			name:        "POST with JSON",
			method:      "POST",
			contentType: "application/json",
			length:      100,
			expected:    true,
		},
		{
			name:        "POST with multipart form",
			method:      "POST",
			contentType: "multipart/form-data",
			expected:    false,
		},
		{
			name:        "POST with binary content",
			method:      "POST",
			contentType: "application/octet-stream",
			expected:    false,
		},
		{
			name:        "POST with image",
			method:      "POST",
			contentType: "image/jpeg",
			expected:    false,
		},
		{
			name:        "POST with large payload",
			method:      "POST",
			contentType: "application/json",
			length:      2048,
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			req := httptest.NewRequest(tt.method, "/test", nil)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			req.ContentLength = tt.length
			c.Request = req

			result := shouldLogRequestBody(c)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestShouldLogResponseBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{
			name:        "JSON response",
			contentType: "application/json",
			expected:    true,
		},
		{
			name:        "Text response",
			contentType: "text/plain",
			expected:    true,
		},
		{
			name:        "XML response",
			contentType: "application/xml",
			expected:    true,
		},
		{
			name:        "HTML response",
			contentType: "text/html",
			expected:    false,
		},
		{
			name:        "Image response",
			contentType: "image/jpeg",
			expected:    false,
		},
		{
			name:        "Video response",
			contentType: "video/mp4",
			expected:    false,
		},
		{
			name:        "Binary response",
			contentType: "application/octet-stream",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			responseWriter := newResponseWriter(c.Writer)
			responseWriter.Header().Set("Content-Type", tt.contentType)

			result := shouldLogResponseBody(c, responseWriter)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestServer_enhancedLoggingMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &Server{}

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	// Note: In a real scenario, we would capture log output here
	// For this test, we're just verifying the middleware runs without error

	router.Use(server.enhancedLoggingMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "test"})
	})

	req := httptest.NewRequest("GET", "/test", nil)

	router.ServeHTTP(w, req)

	// The middleware should run without error and return the expected status
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestServer_RequestResponseLoggingMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &Server{}

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	router.Use(server.RequestResponseLoggingMiddleware())
	router.POST("/api/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"result": "success"})
	})

	body := strings.NewReader(`{"test": "data"}`)
	req := httptest.NewRequest("POST", "/api/test?param=value", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	router.ServeHTTP(w, req)

	// The middleware should run without error and return the expected status
	assert.Equal(t, http.StatusOK, w.Code)
}

// mockUser implements the interface needed for user ID extraction
type mockUser struct {
	id int
}

func (u *mockUser) GetID() int {
	return u.id
}