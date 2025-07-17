package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoad_ValidConfiguration(t *testing.T) {
	// Set up valid environment variables
	envVars := map[string]string{
		"PORT":                     "8080",
		"DATABASE_URL":             "./test.db",
		"SESSION_SECRET":           "this-is-a-very-secure-32-character-session-secret",
		"BASE_URL":                 "https://example.com",
		"MICROSOFT_CLIENT_ID":      "test-microsoft-client-id",
		"MICROSOFT_CLIENT_SECRET":  "test-microsoft-client-secret",
		"GITHUB_CLIENT_ID":         "test-github-client-id",
		"GITHUB_CLIENT_SECRET":     "test-github-client-secret",
	}

	// Set environment variables
	for key, value := range envVars {
		os.Setenv(key, value)
	}
	defer func() {
		for key := range envVars {
			os.Unsetenv(key)
		}
	}()

	config, err := Load()
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify configuration values
	if config.Port != "8080" {
		t.Errorf("Expected port 8080, got: %s", config.Port)
	}
	if config.DatabaseURL != "./test.db" {
		t.Errorf("Expected database URL ./test.db, got: %s", config.DatabaseURL)
	}
	if config.SessionSecret != "this-is-a-very-secure-32-character-session-secret" {
		t.Errorf("Expected session secret to match, got: %s", config.SessionSecret)
	}
	if config.BaseURL != "https://example.com" {
		t.Errorf("Expected base URL https://example.com, got: %s", config.BaseURL)
	}
}

func TestLoad_MissingRequiredConfiguration(t *testing.T) {
	// Clear all environment variables
	envVars := []string{
		"PORT", "DATABASE_URL", "SESSION_SECRET", "BASE_URL",
		"MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET",
		"GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET",
	}
	
	for _, key := range envVars {
		os.Unsetenv(key)
	}

	_, err := Load()
	if err == nil {
		t.Fatal("Expected error for missing configuration, got nil")
	}

	// Check that error mentions required fields
	errStr := err.Error()
	requiredFields := []string{"SESSION_SECRET", "MICROSOFT_CLIENT_ID", "GITHUB_CLIENT_ID"}
	for _, field := range requiredFields {
		if !strings.Contains(errStr, field) {
			t.Errorf("Expected error to mention %s, got: %s", field, errStr)
		}
	}
}

func TestValidate_InvalidPort(t *testing.T) {
	tests := []struct {
		name     string
		port     string
		wantErr  bool
		errField string
	}{
		{
			name:     "empty port",
			port:     "",
			wantErr:  true,
			errField: "PORT",
		},
		{
			name:     "non-numeric port",
			port:     "abc",
			wantErr:  true,
			errField: "PORT",
		},
		{
			name:     "port too low",
			port:     "0",
			wantErr:  true,
			errField: "PORT",
		},
		{
			name:     "port too high",
			port:     "65536",
			wantErr:  true,
			errField: "PORT",
		},
		{
			name:    "valid port",
			port:    "8080",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Port:          tt.port,
				DatabaseURL:   "./test.db",
				SessionSecret: "this-is-a-very-secure-32-character-session-secret",
				BaseURL:       "https://example.com",
				Microsoft: OAuth2Config{
					ClientID:     "test-id",
					ClientSecret: "test-secret",
					RedirectURL:  "https://example.com/auth/callback/microsoft",
					Scopes:       []string{"openid"},
					AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
					TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
					UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
				},
				GitHub: OAuth2Config{
					ClientID:     "test-id",
					ClientSecret: "test-secret",
					RedirectURL:  "https://example.com/auth/callback/github",
					Scopes:       []string{"user:email"},
					AuthURL:      "https://github.com/login/oauth/authorize",
					TokenURL:     "https://github.com/login/oauth/access_token",
					UserInfoURL:  "https://api.github.com/user",
				},
			}

			err := config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.name)
					return
				}
				if !strings.Contains(err.Error(), tt.errField) {
					t.Errorf("Expected error to mention %s, got: %s", tt.errField, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s, got: %v", tt.name, err)
				}
			}
		})
	}
}

func TestValidate_SessionSecret(t *testing.T) {
	tests := []struct {
		name          string
		sessionSecret string
		wantErr       bool
	}{
		{
			name:          "empty session secret",
			sessionSecret: "",
			wantErr:       true,
		},
		{
			name:          "short session secret",
			sessionSecret: "short",
			wantErr:       true,
		},
		{
			name:          "valid session secret",
			sessionSecret: "this-is-a-very-secure-32-character-session-secret",
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Port:          "8080",
				DatabaseURL:   "./test.db",
				SessionSecret: tt.sessionSecret,
				BaseURL:       "https://example.com",
				Microsoft: OAuth2Config{
					ClientID:     "test-id",
					ClientSecret: "test-secret",
					RedirectURL:  "https://example.com/auth/callback/microsoft",
					Scopes:       []string{"openid"},
					AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
					TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
					UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
				},
				GitHub: OAuth2Config{
					ClientID:     "test-id",
					ClientSecret: "test-secret",
					RedirectURL:  "https://example.com/auth/callback/github",
					Scopes:       []string{"user:email"},
					AuthURL:      "https://github.com/login/oauth/authorize",
					TokenURL:     "https://github.com/login/oauth/access_token",
					UserInfoURL:  "https://api.github.com/user",
				},
			}

			err := config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.name)
					return
				}
				if !strings.Contains(err.Error(), "SESSION_SECRET") {
					t.Errorf("Expected error to mention SESSION_SECRET, got: %s", err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s, got: %v", tt.name, err)
				}
			}
		})
	}
}

func TestValidate_BaseURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		wantErr bool
	}{
		{
			name:    "empty base URL",
			baseURL: "",
			wantErr: true,
		},
		{
			name:    "invalid URL",
			baseURL: "not-a-url",
			wantErr: true,
		},
		{
			name:    "URL without protocol",
			baseURL: "example.com",
			wantErr: true,
		},
		{
			name:    "valid HTTP URL",
			baseURL: "http://example.com",
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL",
			baseURL: "https://example.com",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Port:          "8080",
				DatabaseURL:   "./test.db",
				SessionSecret: "this-is-a-very-secure-32-character-session-secret",
				BaseURL:       tt.baseURL,
				Microsoft: OAuth2Config{
					ClientID:     "test-id",
					ClientSecret: "test-secret",
					RedirectURL:  tt.baseURL + "/auth/callback/microsoft",
					Scopes:       []string{"openid"},
					AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
					TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
					UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
				},
				GitHub: OAuth2Config{
					ClientID:     "test-id",
					ClientSecret: "test-secret",
					RedirectURL:  tt.baseURL + "/auth/callback/github",
					Scopes:       []string{"user:email"},
					AuthURL:      "https://github.com/login/oauth/authorize",
					TokenURL:     "https://github.com/login/oauth/access_token",
					UserInfoURL:  "https://api.github.com/user",
				},
			}

			err := config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.name)
					return
				}
				if !strings.Contains(err.Error(), "BASE_URL") {
					t.Errorf("Expected error to mention BASE_URL, got: %s", err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s, got: %v", tt.name, err)
				}
			}
		})
	}
}

func TestValidateOAuth2Config(t *testing.T) {
	config := &Config{}

	tests := []struct {
		name         string
		provider     string
		oauth2Config OAuth2Config
		wantErr      bool
		errFields    []string
	}{
		{
			name:     "missing client ID",
			provider: "Microsoft",
			oauth2Config: OAuth2Config{
				ClientID:     "",
				ClientSecret: "test-secret",
				RedirectURL:  "https://example.com/callback",
				Scopes:       []string{"openid"},
				AuthURL:      "https://login.microsoftonline.com/oauth2/authorize",
				TokenURL:     "https://login.microsoftonline.com/oauth2/token",
				UserInfoURL:  "https://graph.microsoft.com/me",
			},
			wantErr:   true,
			errFields: []string{"MICROSOFT_CLIENT_ID"},
		},
		{
			name:     "missing client secret",
			provider: "GitHub",
			oauth2Config: OAuth2Config{
				ClientID:     "test-id",
				ClientSecret: "",
				RedirectURL:  "https://example.com/callback",
				Scopes:       []string{"user:email"},
				AuthURL:      "https://github.com/login/oauth/authorize",
				TokenURL:     "https://github.com/login/oauth/access_token",
				UserInfoURL:  "https://api.github.com/user",
			},
			wantErr:   true,
			errFields: []string{"GITHUB_CLIENT_SECRET"},
		},
		{
			name:     "empty URLs",
			provider: "Microsoft",
			oauth2Config: OAuth2Config{
				ClientID:     "test-id",
				ClientSecret: "test-secret",
				RedirectURL:  "",
				Scopes:       []string{"openid"},
				AuthURL:      "",
				TokenURL:     "",
				UserInfoURL:  "",
			},
			wantErr:   true,
			errFields: []string{"MICROSOFT_REDIRECTURL", "MICROSOFT_AUTHURL", "MICROSOFT_TOKENURL", "MICROSOFT_USERINFOURL"},
		},
		{
			name:     "empty scopes",
			provider: "GitHub",
			oauth2Config: OAuth2Config{
				ClientID:     "test-id",
				ClientSecret: "test-secret",
				RedirectURL:  "https://example.com/callback",
				Scopes:       []string{},
				AuthURL:      "https://github.com/login/oauth/authorize",
				TokenURL:     "https://github.com/login/oauth/access_token",
				UserInfoURL:  "https://api.github.com/user",
			},
			wantErr:   true,
			errFields: []string{"GITHUB_SCOPES"},
		},
		{
			name:     "valid configuration",
			provider: "Microsoft",
			oauth2Config: OAuth2Config{
				ClientID:     "test-id",
				ClientSecret: "test-secret",
				RedirectURL:  "https://example.com/callback",
				Scopes:       []string{"openid", "profile"},
				AuthURL:      "https://login.microsoftonline.com/oauth2/authorize",
				TokenURL:     "https://login.microsoftonline.com/oauth2/token",
				UserInfoURL:  "https://graph.microsoft.com/me",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := config.validateOAuth2Config(tt.provider, tt.oauth2Config)
			
			if tt.wantErr {
				if len(errors) == 0 {
					t.Errorf("Expected errors for %s, got none", tt.name)
					return
				}
				
				errStr := errors.Error()
				for _, field := range tt.errFields {
					if !strings.Contains(errStr, field) {
						t.Errorf("Expected error to mention %s, got: %s", field, errStr)
					}
				}
			} else {
				if len(errors) > 0 {
					t.Errorf("Expected no errors for %s, got: %v", tt.name, errors)
				}
			}
		})
	}
}

func TestValidationError_Error(t *testing.T) {
	err := ValidationError{
		Field:   "TEST_FIELD",
		Message: "test message",
	}

	expected := "configuration validation failed for TEST_FIELD: test message"
	if err.Error() != expected {
		t.Errorf("Expected error message %q, got %q", expected, err.Error())
	}
}

func TestValidationErrors_Error(t *testing.T) {
	tests := []struct {
		name     string
		errors   ValidationErrors
		expected string
	}{
		{
			name:     "no errors",
			errors:   ValidationErrors{},
			expected: "no validation errors",
		},
		{
			name: "single error",
			errors: ValidationErrors{
				{Field: "FIELD1", Message: "message1"},
			},
			expected: "configuration validation failed:\n  - configuration validation failed for FIELD1: message1",
		},
		{
			name: "multiple errors",
			errors: ValidationErrors{
				{Field: "FIELD1", Message: "message1"},
				{Field: "FIELD2", Message: "message2"},
			},
			expected: "configuration validation failed:\n  - configuration validation failed for FIELD1: message1\n  - configuration validation failed for FIELD2: message2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.errors.Error()
			if result != tt.expected {
				t.Errorf("Expected error message %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestPrintConfigurationHelp(t *testing.T) {
	// This test just ensures the function doesn't panic
	// In a real scenario, you might want to capture stdout and verify the output
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("PrintConfigurationHelp panicked: %v", r)
		}
	}()
	
	PrintConfigurationHelp()
}

func TestParseDatabaseURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain file path",
			input:    "./database/app.db",
			expected: "./database/app.db",
		},
		{
			name:     "sqlite: prefix with filename",
			input:    "sqlite:app.db",
			expected: "app.db",
		},
		{
			name:     "sqlite:// prefix with filename",
			input:    "sqlite://app.db",
			expected: "app.db",
		},
		{
			name:     "sqlite:/// prefix with absolute path",
			input:    "sqlite:///var/lib/app.db",
			expected: "/var/lib/app.db",
		},
		{
			name:     "sqlite: prefix with relative path",
			input:    "sqlite:./database/app.db",
			expected: "./database/app.db",
		},
		{
			name:     "sqlite:// prefix with relative path",
			input:    "sqlite://./database/app.db",
			expected: "./database/app.db",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDatabaseURL(tt.input)
			if result != tt.expected {
				t.Errorf("parseDatabaseURL(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}