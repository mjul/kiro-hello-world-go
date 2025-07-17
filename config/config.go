package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// OAuth2Config holds OAuth2 provider configuration
type OAuth2Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
}

// Config holds all application configuration
type Config struct {
	Port          string
	DatabaseURL   string
	SessionSecret string
	BaseURL       string
	Microsoft     OAuth2Config
	GitHub        OAuth2Config
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("configuration validation failed for %s: %s", e.Field, e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "no validation errors"
	}
	
	var messages []string
	for _, err := range e {
		messages = append(messages, err.Error())
	}
	return fmt.Sprintf("configuration validation failed:\n  - %s", strings.Join(messages, "\n  - "))
}

// Load loads configuration from environment variables with comprehensive validation
func Load() (*Config, error) {
	config := &Config{
		Port:          getEnv("PORT", "3000"),
		DatabaseURL:   parseDatabaseURL(getEnv("DATABASE_URL", "./database/app.db")),
		SessionSecret: getEnv("SESSION_SECRET", ""),
		BaseURL:       getEnv("BASE_URL", "http://localhost:3000"),
	}

	// Microsoft OAuth2 configuration
	config.Microsoft = OAuth2Config{
		ClientID:     getEnv("MICROSOFT_CLIENT_ID", ""),
		ClientSecret: getEnv("MICROSOFT_CLIENT_SECRET", ""),
		RedirectURL:  config.BaseURL + "/auth/callback/microsoft",
		Scopes:       []string{"openid", "profile", "email"},
		AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
	}

	// GitHub OAuth2 configuration
	config.GitHub = OAuth2Config{
		ClientID:     getEnv("GITHUB_CLIENT_ID", ""),
		ClientSecret: getEnv("GITHUB_CLIENT_SECRET", ""),
		RedirectURL:  config.BaseURL + "/auth/callback/github",
		Scopes:       []string{"user:email"},
		AuthURL:      "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
		UserInfoURL:  "https://api.github.com/user",
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// Validate performs comprehensive validation of the configuration
func (c *Config) Validate() error {
	var errors ValidationErrors

	// Validate PORT
	if c.Port == "" {
		errors = append(errors, ValidationError{
			Field:   "PORT",
			Message: "port cannot be empty",
		})
	} else if port, err := strconv.Atoi(c.Port); err != nil {
		errors = append(errors, ValidationError{
			Field:   "PORT",
			Message: fmt.Sprintf("port must be a valid integer, got: %s", c.Port),
		})
	} else if port < 1 || port > 65535 {
		errors = append(errors, ValidationError{
			Field:   "PORT",
			Message: fmt.Sprintf("port must be between 1 and 65535, got: %d", port),
		})
	}

	// Validate DATABASE_URL
	if c.DatabaseURL == "" {
		errors = append(errors, ValidationError{
			Field:   "DATABASE_URL",
			Message: "database URL cannot be empty",
		})
	} else {
		// Validate database directory exists or can be created
		dbDir := filepath.Dir(c.DatabaseURL)
		if dbDir != "." && dbDir != "" {
			if _, err := os.Stat(dbDir); os.IsNotExist(err) {
				if err := os.MkdirAll(dbDir, 0755); err != nil {
					errors = append(errors, ValidationError{
						Field:   "DATABASE_URL",
						Message: fmt.Sprintf("cannot create database directory %s: %v", dbDir, err),
					})
				}
			}
		}
	}

	// Validate SESSION_SECRET
	if c.SessionSecret == "" {
		errors = append(errors, ValidationError{
			Field:   "SESSION_SECRET",
			Message: "session secret is required for secure session management",
		})
	} else if len(c.SessionSecret) < 32 {
		errors = append(errors, ValidationError{
			Field:   "SESSION_SECRET",
			Message: "session secret must be at least 32 characters long for security",
		})
	}

	// Validate BASE_URL
	if c.BaseURL == "" {
		errors = append(errors, ValidationError{
			Field:   "BASE_URL",
			Message: "base URL cannot be empty",
		})
	} else if _, err := url.Parse(c.BaseURL); err != nil {
		errors = append(errors, ValidationError{
			Field:   "BASE_URL",
			Message: fmt.Sprintf("base URL must be a valid URL, got: %s", c.BaseURL),
		})
	} else if !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		errors = append(errors, ValidationError{
			Field:   "BASE_URL",
			Message: "base URL must start with http:// or https://",
		})
	}

	// Validate Microsoft OAuth2 configuration
	if err := c.validateOAuth2Config("Microsoft", c.Microsoft); err != nil {
		errors = append(errors, err...)
	}

	// Validate GitHub OAuth2 configuration
	if err := c.validateOAuth2Config("GitHub", c.GitHub); err != nil {
		errors = append(errors, err...)
	}

	if len(errors) > 0 {
		return errors
	}

	return nil
}

// validateOAuth2Config validates OAuth2 provider configuration
func (c *Config) validateOAuth2Config(provider string, config OAuth2Config) ValidationErrors {
	var errors ValidationErrors
	prefix := strings.ToUpper(provider)

	// Validate ClientID
	if config.ClientID == "" {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("%s_CLIENT_ID", prefix),
			Message: fmt.Sprintf("%s OAuth2 client ID is required", provider),
		})
	}

	// Validate ClientSecret
	if config.ClientSecret == "" {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("%s_CLIENT_SECRET", prefix),
			Message: fmt.Sprintf("%s OAuth2 client secret is required", provider),
		})
	}

	// Validate URLs
	urls := map[string]string{
		"AuthURL":     config.AuthURL,
		"TokenURL":    config.TokenURL,
		"UserInfoURL": config.UserInfoURL,
		"RedirectURL": config.RedirectURL,
	}

	for name, urlStr := range urls {
		if urlStr == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("%s_%s", prefix, strings.ToUpper(name)),
				Message: fmt.Sprintf("%s %s cannot be empty", provider, name),
			})
		} else if _, err := url.Parse(urlStr); err != nil {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("%s_%s", prefix, strings.ToUpper(name)),
				Message: fmt.Sprintf("%s %s must be a valid URL: %v", provider, name, err),
			})
		}
	}

	// Validate Scopes
	if len(config.Scopes) == 0 {
		errors = append(errors, ValidationError{
			Field:   fmt.Sprintf("%s_SCOPES", prefix),
			Message: fmt.Sprintf("%s OAuth2 scopes cannot be empty", provider),
		})
	}

	return errors
}

// PrintConfigurationHelp prints helpful information about configuration
func PrintConfigurationHelp() {
	fmt.Print(`
SSO Web App Configuration Help
==============================

Required Environment Variables:
  SESSION_SECRET          - Secure random string (min 32 chars) for session encryption
  MICROSOFT_CLIENT_ID     - Microsoft Azure AD application client ID
  MICROSOFT_CLIENT_SECRET - Microsoft Azure AD application client secret
  GITHUB_CLIENT_ID        - GitHub OAuth app client ID
  GITHUB_CLIENT_SECRET    - GitHub OAuth app client secret

Optional Environment Variables:
  PORT                    - Server port (default: 3000)
  BASE_URL               - Application base URL (default: http://localhost:3000)
  DATABASE_URL           - SQLite database file path (default: ./database/app.db)

Configuration Tips:
  - Generate SESSION_SECRET with: openssl rand -hex 32
  - Ensure BASE_URL matches your deployment URL for OAuth callbacks
  - Database directory will be created automatically if it doesn't exist
  - OAuth redirect URLs are automatically configured as BASE_URL/auth/callback/{provider}

Example .env file:
  SESSION_SECRET=your-secure-32-character-session-secret-here
  MICROSOFT_CLIENT_ID=12345678-1234-1234-1234-123456789012
  MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
  GITHUB_CLIENT_ID=your-github-client-id
  GITHUB_CLIENT_SECRET=your-github-client-secret
  BASE_URL=https://your-domain.com
`)
}

// getEnv gets an environment variable with a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvAsInt gets an environment variable as integer with a default value
func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// parseDatabaseURL parses a database URL and extracts the file path for SQLite
func parseDatabaseURL(databaseURL string) string {
	// Handle SQLite URL formats:
	// - sqlite:filename
	// - sqlite://filename
	// - sqlite:///absolute/path/to/file
	// - plain file path (no prefix)
	
	if strings.HasPrefix(databaseURL, "sqlite:") {
		// Remove the sqlite: prefix
		path := strings.TrimPrefix(databaseURL, "sqlite:")
		
		// Handle sqlite:// format
		if strings.HasPrefix(path, "//") {
			path = strings.TrimPrefix(path, "//")
		}
		
		// Handle sqlite:/// format (absolute path)
		if strings.HasPrefix(path, "/") && len(path) > 1 {
			return path
		}
		
		// Relative path or simple filename
		return path
	}
	
	// Return as-is if no sqlite: prefix (plain file path)
	return databaseURL
}