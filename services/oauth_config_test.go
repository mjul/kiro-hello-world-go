package services

import (
	"strings"
	"testing"

	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/microsoft"
)

func TestSupportedProvider_String(t *testing.T) {
	tests := []struct {
		provider SupportedProvider
		expected string
	}{
		{ProviderMicrosoft, "microsoft"},
		{ProviderGitHub, "github"},
	}

	for _, tt := range tests {
		t.Run(string(tt.provider), func(t *testing.T) {
			if got := tt.provider.String(); got != tt.expected {
				t.Errorf("SupportedProvider.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSupportedProvider_IsValid(t *testing.T) {
	tests := []struct {
		provider SupportedProvider
		expected bool
	}{
		{ProviderMicrosoft, true},
		{ProviderGitHub, true},
		{SupportedProvider("invalid"), false},
		{SupportedProvider(""), false},
		{SupportedProvider("google"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.provider), func(t *testing.T) {
			if got := tt.provider.IsValid(); got != tt.expected {
				t.Errorf("SupportedProvider.IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseProvider(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected SupportedProvider
		wantErr  bool
	}{
		{"valid microsoft", "microsoft", ProviderMicrosoft, false},
		{"valid github", "github", ProviderGitHub, false},
		{"case insensitive microsoft", "MICROSOFT", ProviderMicrosoft, false},
		{"case insensitive github", "GitHub", ProviderGitHub, false},
		{"mixed case", "MiCrOsOfT", ProviderMicrosoft, false},
		{"invalid provider", "google", "", true},
		{"empty string", "", "", true},
		{"random string", "invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseProvider(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseProvider() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("ParseProvider() unexpected error: %v", err)
				return
			}
			if got != tt.expected {
				t.Errorf("ParseProvider() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetSupportedProviders(t *testing.T) {
	providers := GetSupportedProviders()
	
	if len(providers) != 2 {
		t.Errorf("GetSupportedProviders() returned %d providers, want 2", len(providers))
	}
	
	expectedProviders := map[SupportedProvider]bool{
		ProviderMicrosoft: false,
		ProviderGitHub:    false,
	}
	
	for _, provider := range providers {
		if _, exists := expectedProviders[provider]; !exists {
			t.Errorf("GetSupportedProviders() returned unexpected provider: %v", provider)
		}
		expectedProviders[provider] = true
	}
	
	for provider, found := range expectedProviders {
		if !found {
			t.Errorf("GetSupportedProviders() missing expected provider: %v", provider)
		}
	}
}

func TestProviderConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  ProviderConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: ProviderConfig{
				ClientID:     "client123",
				ClientSecret: "secret123",
				RedirectURL:  "http://localhost:8080/callback",
				Scopes:       []string{"openid", "profile"},
			},
			wantErr: false,
		},
		{
			name: "empty client_id",
			config: ProviderConfig{
				ClientID:     "",
				ClientSecret: "secret123",
				RedirectURL:  "http://localhost:8080/callback",
				Scopes:       []string{"openid", "profile"},
			},
			wantErr: true,
			errMsg:  "client_id is required",
		},
		{
			name: "whitespace only client_id",
			config: ProviderConfig{
				ClientID:     "   ",
				ClientSecret: "secret123",
				RedirectURL:  "http://localhost:8080/callback",
				Scopes:       []string{"openid", "profile"},
			},
			wantErr: true,
			errMsg:  "client_id is required",
		},
		{
			name: "empty client_secret",
			config: ProviderConfig{
				ClientID:     "client123",
				ClientSecret: "",
				RedirectURL:  "http://localhost:8080/callback",
				Scopes:       []string{"openid", "profile"},
			},
			wantErr: true,
			errMsg:  "client_secret is required",
		},
		{
			name: "empty redirect_url",
			config: ProviderConfig{
				ClientID:     "client123",
				ClientSecret: "secret123",
				RedirectURL:  "",
				Scopes:       []string{"openid", "profile"},
			},
			wantErr: true,
			errMsg:  "redirect_url is required",
		},
		{
			name: "empty scopes",
			config: ProviderConfig{
				ClientID:     "client123",
				ClientSecret: "secret123",
				RedirectURL:  "http://localhost:8080/callback",
				Scopes:       []string{},
			},
			wantErr: true,
			errMsg:  "at least one scope is required",
		},
		{
			name: "nil scopes",
			config: ProviderConfig{
				ClientID:     "client123",
				ClientSecret: "secret123",
				RedirectURL:  "http://localhost:8080/callback",
				Scopes:       nil,
			},
			wantErr: true,
			errMsg:  "at least one scope is required",
		},
		{
			name: "empty scope in list",
			config: ProviderConfig{
				ClientID:     "client123",
				ClientSecret: "secret123",
				RedirectURL:  "http://localhost:8080/callback",
				Scopes:       []string{"openid", "", "profile"},
			},
			wantErr: true,
			errMsg:  "scope at index 1 cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("ProviderConfig.Validate() expected error but got none")
					return
				}
				if err.Error() != tt.errMsg {
					t.Errorf("ProviderConfig.Validate() error = %v, want %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ProviderConfig.Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestOAuth2Config_Validate(t *testing.T) {
	validConfig := ProviderConfig{
		ClientID:     "client123",
		ClientSecret: "secret123",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"openid", "profile"},
	}

	tests := []struct {
		name    string
		config  OAuth2Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: OAuth2Config{
				Microsoft: validConfig,
				GitHub:    validConfig,
			},
			wantErr: false,
		},
		{
			name: "invalid microsoft config",
			config: OAuth2Config{
				Microsoft: ProviderConfig{
					ClientID:     "",
					ClientSecret: "secret123",
					RedirectURL:  "http://localhost:8080/callback",
					Scopes:       []string{"openid", "profile"},
				},
				GitHub: validConfig,
			},
			wantErr: true,
			errMsg:  "microsoft configuration invalid: client_id is required",
		},
		{
			name: "invalid github config",
			config: OAuth2Config{
				Microsoft: validConfig,
				GitHub: ProviderConfig{
					ClientID:     "client123",
					ClientSecret: "",
					RedirectURL:  "http://localhost:8080/callback",
					Scopes:       []string{"user:email"},
				},
			},
			wantErr: true,
			errMsg:  "github configuration invalid: client_secret is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("OAuth2Config.Validate() expected error but got none")
					return
				}
				if err.Error() != tt.errMsg {
					t.Errorf("OAuth2Config.Validate() error = %v, want %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("OAuth2Config.Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestOAuth2Config_GetProviderConfig(t *testing.T) {
	microsoftConfig := ProviderConfig{
		ClientID:     "ms_client",
		ClientSecret: "ms_secret",
		RedirectURL:  "http://localhost:8080/auth/callback/microsoft",
		Scopes:       []string{"openid", "profile", "email"},
	}

	githubConfig := ProviderConfig{
		ClientID:     "gh_client",
		ClientSecret: "gh_secret",
		RedirectURL:  "http://localhost:8080/auth/callback/github",
		Scopes:       []string{"user:email", "read:user"},
	}

	config := OAuth2Config{
		Microsoft: microsoftConfig,
		GitHub:    githubConfig,
	}

	tests := []struct {
		name     string
		provider SupportedProvider
		expected *ProviderConfig
		wantErr  bool
	}{
		{
			name:     "microsoft provider",
			provider: ProviderMicrosoft,
			expected: &microsoftConfig,
			wantErr:  false,
		},
		{
			name:     "github provider",
			provider: ProviderGitHub,
			expected: &githubConfig,
			wantErr:  false,
		},
		{
			name:     "invalid provider",
			provider: SupportedProvider("invalid"),
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := config.GetProviderConfig(tt.provider)
			if tt.wantErr {
				if err == nil {
					t.Errorf("OAuth2Config.GetProviderConfig() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("OAuth2Config.GetProviderConfig() unexpected error: %v", err)
				return
			}
			if got.ClientID != tt.expected.ClientID {
				t.Errorf("OAuth2Config.GetProviderConfig() ClientID = %v, want %v", got.ClientID, tt.expected.ClientID)
			}
		})
	}
}

func TestProviderConfig_ToOAuth2Config(t *testing.T) {
	validConfig := ProviderConfig{
		ClientID:     "client123",
		ClientSecret: "secret123",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"openid", "profile"},
	}

	tests := []struct {
		name     string
		config   ProviderConfig
		provider SupportedProvider
		wantErr  bool
	}{
		{
			name:     "valid microsoft config",
			config:   validConfig,
			provider: ProviderMicrosoft,
			wantErr:  false,
		},
		{
			name:     "valid github config",
			config:   validConfig,
			provider: ProviderGitHub,
			wantErr:  false,
		},
		{
			name: "invalid config",
			config: ProviderConfig{
				ClientID:     "",
				ClientSecret: "secret123",
				RedirectURL:  "http://localhost:8080/callback",
				Scopes:       []string{"openid", "profile"},
			},
			provider: ProviderMicrosoft,
			wantErr:  true,
		},
		{
			name:     "invalid provider",
			config:   validConfig,
			provider: SupportedProvider("invalid"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.config.ToOAuth2Config(tt.provider)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ProviderConfig.ToOAuth2Config() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("ProviderConfig.ToOAuth2Config() unexpected error: %v", err)
				return
			}

			// Verify the oauth2.Config fields
			if got.ClientID != tt.config.ClientID {
				t.Errorf("ToOAuth2Config() ClientID = %v, want %v", got.ClientID, tt.config.ClientID)
			}
			if got.ClientSecret != tt.config.ClientSecret {
				t.Errorf("ToOAuth2Config() ClientSecret = %v, want %v", got.ClientSecret, tt.config.ClientSecret)
			}
			if got.RedirectURL != tt.config.RedirectURL {
				t.Errorf("ToOAuth2Config() RedirectURL = %v, want %v", got.RedirectURL, tt.config.RedirectURL)
			}

			// Verify endpoint is set correctly
			switch tt.provider {
			case ProviderMicrosoft:
				expectedEndpoint := microsoft.AzureADEndpoint("common")
				if got.Endpoint != expectedEndpoint {
					t.Errorf("ToOAuth2Config() Microsoft endpoint not set correctly")
				}
			case ProviderGitHub:
				if got.Endpoint != github.Endpoint {
					t.Errorf("ToOAuth2Config() GitHub endpoint not set correctly")
				}
			}
		})
	}
}

func TestGetDefaultScopes(t *testing.T) {
	tests := []struct {
		provider      SupportedProvider
		expectedCount int
		mustContain   []string
	}{
		{
			provider:      ProviderMicrosoft,
			expectedCount: 3,
			mustContain:   []string{"openid", "profile", "email"},
		},
		{
			provider:      ProviderGitHub,
			expectedCount: 2,
			mustContain:   []string{"user:email", "read:user"},
		},
		{
			provider:      SupportedProvider("invalid"),
			expectedCount: 0,
			mustContain:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.provider), func(t *testing.T) {
			scopes := GetDefaultScopes(tt.provider)
			
			if len(scopes) != tt.expectedCount {
				t.Errorf("GetDefaultScopes() returned %d scopes, want %d", len(scopes), tt.expectedCount)
			}

			for _, mustHave := range tt.mustContain {
				found := false
				for _, scope := range scopes {
					if scope == mustHave {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("GetDefaultScopes() missing required scope: %s", mustHave)
				}
			}
		})
	}
}

func TestNewOAuth2Config(t *testing.T) {
	config := NewOAuth2Config()
	
	if config == nil {
		t.Errorf("NewOAuth2Config() returned nil")
		return
	}

	// Check that default scopes are set
	microsoftScopes := GetDefaultScopes(ProviderMicrosoft)
	githubScopes := GetDefaultScopes(ProviderGitHub)

	if len(config.Microsoft.Scopes) != len(microsoftScopes) {
		t.Errorf("NewOAuth2Config() Microsoft scopes count = %d, want %d", 
			len(config.Microsoft.Scopes), len(microsoftScopes))
	}

	if len(config.GitHub.Scopes) != len(githubScopes) {
		t.Errorf("NewOAuth2Config() GitHub scopes count = %d, want %d", 
			len(config.GitHub.Scopes), len(githubScopes))
	}
}

func TestOAuth2Config_LoadFromEnvironment(t *testing.T) {
	tests := []struct {
		name    string
		config  OAuth2Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "missing microsoft client_id",
			config: OAuth2Config{
				Microsoft: ProviderConfig{
					ClientID:     "",
					ClientSecret: "secret",
					RedirectURL:  "http://localhost:8080/callback",
					Scopes:       []string{"openid"},
				},
				GitHub: ProviderConfig{
					ClientID:     "gh_client",
					ClientSecret: "gh_secret",
					RedirectURL:  "http://localhost:8080/callback",
					Scopes:       []string{"user:email"},
				},
			},
			wantErr: true,
			errMsg:  "MICROSOFT_CLIENT_ID environment variable is required",
		},
		{
			name: "missing github client_secret",
			config: OAuth2Config{
				Microsoft: ProviderConfig{
					ClientID:     "ms_client",
					ClientSecret: "ms_secret",
					RedirectURL:  "http://localhost:8080/callback",
					Scopes:       []string{"openid"},
				},
				GitHub: ProviderConfig{
					ClientID:     "gh_client",
					ClientSecret: "",
					RedirectURL:  "http://localhost:8080/callback",
					Scopes:       []string{"user:email"},
				},
			},
			wantErr: true,
			errMsg:  "GITHUB_CLIENT_SECRET environment variable is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.LoadFromEnvironment()
			if tt.wantErr {
				if err == nil {
					t.Errorf("OAuth2Config.LoadFromEnvironment() expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("OAuth2Config.LoadFromEnvironment() error = %v, want to contain %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("OAuth2Config.LoadFromEnvironment() unexpected error: %v", err)
				}
			}
		})
	}
}