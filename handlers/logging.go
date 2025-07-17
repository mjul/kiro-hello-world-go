package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// LogLevel represents different logging levels
type LogLevel string

const (
	LogLevelDebug LogLevel = "DEBUG"
	LogLevelInfo  LogLevel = "INFO"
	LogLevelWarn  LogLevel = "WARN"
	LogLevelError LogLevel = "ERROR"
)

// Logger provides structured logging functionality
type Logger struct {
	level  LogLevel
	output io.Writer
}

// NewLogger creates a new logger instance
func NewLogger(level LogLevel) *Logger {
	return &Logger{
		level:  level,
		output: os.Stdout,
	}
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp   time.Time              `json:"timestamp"`
	Level       LogLevel               `json:"level"`
	Message     string                 `json:"message"`
	Component   string                 `json:"component,omitempty"`
	UserID      int                    `json:"user_id,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	Method      string                 `json:"method,omitempty"`
	Path        string                 `json:"path,omitempty"`
	StatusCode  int                    `json:"status_code,omitempty"`
	Duration    time.Duration          `json:"duration,omitempty"`
	RemoteAddr  string                 `json:"remote_addr,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	Error       string                 `json:"error,omitempty"`
	ErrorType   string                 `json:"error_type,omitempty"`
	ErrorCode   string                 `json:"error_code,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

// shouldLog determines if a message should be logged based on level
func (l *Logger) shouldLog(level LogLevel) bool {
	levels := map[LogLevel]int{
		LogLevelDebug: 0,
		LogLevelInfo:  1,
		LogLevelWarn:  2,
		LogLevelError: 3,
	}
	
	currentLevel, exists := levels[l.level]
	if !exists {
		currentLevel = 1 // Default to INFO
	}
	
	messageLevel, exists := levels[level]
	if !exists {
		messageLevel = 1 // Default to INFO
	}
	
	return messageLevel >= currentLevel
}

// log writes a structured log entry
func (l *Logger) log(entry LogEntry) {
	if !l.shouldLog(entry.Level) {
		return
	}
	
	entry.Timestamp = time.Now().UTC()
	
	// Format as JSON for structured logging
	jsonData, err := json.Marshal(entry)
	if err != nil {
		// Fallback to simple logging if JSON marshaling fails
		fmt.Fprintf(l.output, "[%s] %s %s: %s\n", 
			entry.Timestamp.Format(time.RFC3339), 
			entry.Level, 
			entry.Component, 
			entry.Message)
		return
	}
	
	fmt.Fprintln(l.output, string(jsonData))
}

// Debug logs a debug message
func (l *Logger) Debug(message string, fields map[string]interface{}) {
	entry := LogEntry{
		Level:   LogLevelDebug,
		Message: message,
		Extra:   fields,
	}
	l.log(entry)
}

// Info logs an info message
func (l *Logger) Info(message string, fields map[string]interface{}) {
	entry := LogEntry{
		Level:   LogLevelInfo,
		Message: message,
		Extra:   fields,
	}
	l.log(entry)
}

// Warn logs a warning message
func (l *Logger) Warn(message string, fields map[string]interface{}) {
	entry := LogEntry{
		Level:   LogLevelWarn,
		Message: message,
		Extra:   fields,
	}
	l.log(entry)
}

// Error logs an error message
func (l *Logger) Error(message string, fields map[string]interface{}) {
	entry := LogEntry{
		Level:   LogLevelError,
		Message: message,
		Extra:   fields,
	}
	l.log(entry)
}

// LogRequest logs HTTP request information
func (l *Logger) LogRequest(c *gin.Context, duration time.Duration, statusCode int) {
	entry := LogEntry{
		Level:      LogLevelInfo,
		Message:    "HTTP Request",
		Component:  "http",
		Method:     c.Request.Method,
		Path:       c.Request.URL.Path,
		StatusCode: statusCode,
		Duration:   duration,
		RemoteAddr: c.ClientIP(),
		UserAgent:  c.Request.UserAgent(),
	}
	
	// Add user context if available
	if userInterface, exists := c.Get("user"); exists {
		if user, ok := userInterface.(interface{ GetID() int }); ok {
			entry.UserID = user.GetID()
		}
	}
	
	// Add session context if available
	if sessionID, exists := c.Get("session_id"); exists {
		if sessionIDStr, ok := sessionID.(string); ok {
			entry.SessionID = sessionIDStr
		}
	}
	
	// Add request ID if available
	if requestID, exists := c.Get("request_id"); exists {
		if requestIDStr, ok := requestID.(string); ok {
			entry.RequestID = requestIDStr
		}
	}
	
	l.log(entry)
}

// LogAuthentication logs authentication events
func (l *Logger) LogAuthentication(event string, userID int, provider string, success bool, details map[string]interface{}) {
	level := LogLevelInfo
	if !success {
		level = LogLevelWarn
	}
	
	entry := LogEntry{
		Level:     level,
		Message:   fmt.Sprintf("Authentication %s", event),
		Component: "auth",
		UserID:    userID,
		Extra: map[string]interface{}{
			"event":    event,
			"provider": provider,
			"success":  success,
		},
	}
	
	// Merge additional details
	if details != nil {
		for k, v := range details {
			entry.Extra[k] = v
		}
	}
	
	l.log(entry)
}

// LogError logs application errors with context
func (l *Logger) LogError(c *gin.Context, appErr *AppError) {
	entry := LogEntry{
		Level:     LogLevelError,
		Message:   appErr.Message,
		Component: "error",
		Error:     appErr.Error(),
		ErrorType: string(appErr.Type),
		ErrorCode: appErr.Code,
	}
	
	// Add HTTP context if available
	if c != nil {
		entry.Method = c.Request.Method
		entry.Path = c.Request.URL.Path
		entry.RemoteAddr = c.ClientIP()
		entry.UserAgent = c.Request.UserAgent()
		entry.StatusCode = appErr.StatusCode
		
		// Add user context if available
		if userInterface, exists := c.Get("user"); exists {
			if user, ok := userInterface.(interface{ GetID() int }); ok {
				entry.UserID = user.GetID()
			}
		}
		
		// Add session context if available
		if sessionID, exists := c.Get("session_id"); exists {
			if sessionIDStr, ok := sessionID.(string); ok {
				entry.SessionID = sessionIDStr
			}
		}
		
		// Add request ID if available
		if requestID, exists := c.Get("request_id"); exists {
			if requestIDStr, ok := requestID.(string); ok {
				entry.RequestID = requestIDStr
			}
		}
	}
	
	// Add additional error details
	entry.Extra = map[string]interface{}{
		"user_message": appErr.UserMessage,
	}
	
	if appErr.Details != "" {
		entry.Extra["details"] = appErr.Details
	}
	
	if appErr.Cause != nil {
		entry.Extra["cause"] = appErr.Cause.Error()
	}
	
	l.log(entry)
}

// responseWriter wraps gin.ResponseWriter to capture response data
type responseWriter struct {
	gin.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func newResponseWriter(w gin.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		body:           bytes.NewBuffer(nil),
		statusCode:     http.StatusOK,
	}
}

func (w *responseWriter) Write(data []byte) (int, error) {
	w.body.Write(data)
	return w.ResponseWriter.Write(data)
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// RequestResponseLoggingMiddleware creates middleware for detailed request/response logging
func (s *Server) RequestResponseLoggingMiddleware() gin.HandlerFunc {
	logger := NewLogger(LogLevelInfo)
	
	return func(c *gin.Context) {
		start := time.Now()
		
		// Generate request ID for tracing
		requestID := fmt.Sprintf("%d-%s", start.UnixNano(), c.ClientIP())
		c.Set("request_id", requestID)
		
		// Capture request body for logging (be careful with large payloads)
		var requestBody []byte
		if c.Request.Body != nil && shouldLogRequestBody(c) {
			requestBody, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(requestBody))
		}
		
		// Wrap response writer to capture response
		responseWriter := newResponseWriter(c.Writer)
		c.Writer = responseWriter
		
		// Process request
		c.Next()
		
		// Calculate duration
		duration := time.Since(start)
		
		// Log request details
		logFields := map[string]interface{}{
			"request_id":    requestID,
			"method":        c.Request.Method,
			"path":          c.Request.URL.Path,
			"query":         c.Request.URL.RawQuery,
			"status_code":   responseWriter.statusCode,
			"duration_ms":   duration.Milliseconds(),
			"remote_addr":   c.ClientIP(),
			"user_agent":    c.Request.UserAgent(),
			"content_type":  c.Request.Header.Get("Content-Type"),
			"accept":        c.Request.Header.Get("Accept"),
		}
		
		// Add user context if available
		if userInterface, exists := c.Get("user"); exists {
			if user, ok := userInterface.(interface{ GetID() int }); ok {
				logFields["user_id"] = user.GetID()
			}
		}
		
		// Add session context if available
		if sessionID, exists := c.Get("session_id"); exists {
			logFields["session_id"] = sessionID
		}
		
		// Add request body if captured
		if len(requestBody) > 0 && len(requestBody) < 1024 { // Only log small payloads
			logFields["request_body"] = string(requestBody)
		}
		
		// Add response body if it's small and not binary
		if shouldLogResponseBody(c, responseWriter) {
			responseBody := responseWriter.body.String()
			if len(responseBody) < 1024 {
				logFields["response_body"] = responseBody
			}
		}
		
		// Determine log level based on status code
		var level LogLevel
		if responseWriter.statusCode >= 500 {
			level = LogLevelError
		} else if responseWriter.statusCode >= 400 {
			level = LogLevelWarn
		} else {
			level = LogLevelInfo
		}
		
		message := fmt.Sprintf("%s %s - %d", c.Request.Method, c.Request.URL.Path, responseWriter.statusCode)
		
		switch level {
		case LogLevelError:
			logger.Error(message, logFields)
		case LogLevelWarn:
			logger.Warn(message, logFields)
		default:
			logger.Info(message, logFields)
		}
	}
}

// shouldLogRequestBody determines if request body should be logged
func shouldLogRequestBody(c *gin.Context) bool {
	// Don't log request body for GET requests
	if c.Request.Method == "GET" {
		return false
	}
	
	// Don't log binary content
	contentType := c.Request.Header.Get("Content-Type")
	if strings.Contains(contentType, "multipart/form-data") ||
		strings.Contains(contentType, "application/octet-stream") ||
		strings.Contains(contentType, "image/") ||
		strings.Contains(contentType, "video/") ||
		strings.Contains(contentType, "audio/") {
		return false
	}
	
	// Don't log large payloads
	if c.Request.ContentLength > 1024 {
		return false
	}
	
	return true
}

// shouldLogResponseBody determines if response body should be logged
func shouldLogResponseBody(c *gin.Context, w *responseWriter) bool {
	// Don't log binary responses
	contentType := w.Header().Get("Content-Type")
	if strings.Contains(contentType, "image/") ||
		strings.Contains(contentType, "video/") ||
		strings.Contains(contentType, "audio/") ||
		strings.Contains(contentType, "application/octet-stream") {
		return false
	}
	
	// Don't log HTML responses (too verbose)
	if strings.Contains(contentType, "text/html") {
		return false
	}
	
	// Only log JSON and text responses
	return strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "text/plain") ||
		strings.Contains(contentType, "application/xml")
}

// Enhanced logging middleware that replaces the basic one
func (s *Server) enhancedLoggingMiddleware() gin.HandlerFunc {
	logger := NewLogger(LogLevelInfo)
	
	return func(c *gin.Context) {
		start := time.Now()
		
		// Generate request ID for tracing
		requestID := fmt.Sprintf("%d-%s", start.UnixNano(), c.ClientIP())
		c.Set("request_id", requestID)
		
		// Process request
		c.Next()
		
		// Calculate duration
		duration := time.Since(start)
		
		// Log the request
		logger.LogRequest(c, duration, c.Writer.Status())
	}
}