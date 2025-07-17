package services

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/microsoft"
)

// ProviderConfig holds OAuth2 configuration for a specific provider
type ProviderConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
}

// OAuth2Config manages OAuth2 configurations for multiple providers
type OAuth2Config struct {
	Microsoft ProviderConfig `json:"microsoft"`
	GitHub    ProviderConfig `json:"github"`
}

// SupportedProvider represents the supported OAuth2 providers
type SupportedProvider string

const (
	ProviderMicrosoft SupportedProvider = "microsoft"
	ProviderGitHub    SupportedProvider = "github"
)

// String returns the string representation of the provider
func (p SupportedProvider) String() string {
	return string(p)
}

// IsValid checks if the provider is supported
func (p SupportedProvider) IsValid() bool {
	switch p {
	case ProviderMicrosoft, ProviderGitHub:
		return true
	default:
		return false
	}
}

// ParseProvider parses a string into a SupportedProvider
func ParseProvider(provider string) (SupportedProvider, error) {
	p := SupportedProvider(strings.ToLower(provider))
	if !p.IsValid() {
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
	return p, nil
}

// GetSupportedProviders returns a list of all supported providers
func GetSupportedProviders() []SupportedProvider {
	return []SupportedProvider{ProviderMicrosoft, ProviderGitHub}
}

// Validate validates the provider configuration
func (pc *ProviderConfig) Validate() error {
	if strings.TrimSpace(pc.ClientID) == "" {
		return errors.New("client_id is required")
	}
	
	if strings.TrimSpace(pc.ClientSecret) == "" {
		return errors.New("client_secret is required")
	}
	
	if strings.TrimSpace(pc.RedirectURL) == "" {
		return errors.New("redirect_url is required")
	}
	
	if len(pc.Scopes) == 0 {
		return errors.New("at least one scope is required")
	}
	
	// Validate that scopes are not empty
	for i, scope := range pc.Scopes {
		if strings.TrimSpace(scope) == "" {
			return fmt.Errorf("scope at index %d cannot be empty", i)
		}
	}
	
	return nil
}

// Validate validates the entire OAuth2 configuration
func (oc *OAuth2Config) Validate() error {
	// Validate Microsoft configuration
	if err := oc.Microsoft.Validate(); err != nil {
		return fmt.Errorf("microsoft configuration invalid: %w", err)
	}
	
	// Validate GitHub configuration
	if err := oc.GitHub.Validate(); err != nil {
		return fmt.Errorf("github configuration invalid: %w", err)
	}
	
	return nil
}

// GetProviderConfig returns the configuration for a specific provider
func (oc *OAuth2Config) GetProviderConfig(provider SupportedProvider) (*ProviderConfig, error) {
	switch provider {
	case ProviderMicrosoft:
		return &oc.Microsoft, nil
	case ProviderGitHub:
		return &oc.GitHub, nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

// ToOAuth2Config converts a ProviderConfig to golang.org/x/oauth2.Config
func (pc *ProviderConfig) ToOAuth2Config(provider SupportedProvider) (*oauth2.Config, error) {
	if err := pc.Validate(); err != nil {
		return nil, fmt.Errorf("invalid provider configuration: %w", err)
	}
	
	config := &oauth2.Config{
		ClientID:     pc.ClientID,
		ClientSecret: pc.ClientSecret,
		RedirectURL:  pc.RedirectURL,
		Scopes:       pc.Scopes,
	}
	
	// Set the appropriate endpoint based on provider
	switch provider {
	case ProviderMicrosoft:
		// Use the common tenant for Microsoft Azure AD
		config.Endpoint = microsoft.AzureADEndpoint("common")
	case ProviderGitHub:
		config.Endpoint = github.Endpoint
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
	
	return config, nil
}

// GetOAuth2Config returns the oauth2.Config for a specific provider
func (oc *OAuth2Config) GetOAuth2Config(provider SupportedProvider) (*oauth2.Config, error) {
	providerConfig, err := oc.GetProviderConfig(provider)
	if err != nil {
		return nil, err
	}
	
	return providerConfig.ToOAuth2Config(provider)
}

// GetDefaultScopes returns the default scopes for each provider
func GetDefaultScopes(provider SupportedProvider) []string {
	switch provider {
	case ProviderMicrosoft:
		return []string{"openid", "profile", "email"}
	case ProviderGitHub:
		return []string{"user:email", "read:user"}
	default:
		return []string{}
	}
}

// NewOAuth2Config creates a new OAuth2Config with default values
func NewOAuth2Config() *OAuth2Config {
	return &OAuth2Config{
		Microsoft: ProviderConfig{
			Scopes: GetDefaultScopes(ProviderMicrosoft),
		},
		GitHub: ProviderConfig{
			Scopes: GetDefaultScopes(ProviderGitHub),
		},
	}
}

// LoadFromConfig loads OAuth2 configuration from the application config
func (oc *OAuth2Config) LoadFromConfig(cfg interface{}) error {
	// Since the config loading is complex with different structures,
	// we'll use environment variables for now
	// In a real implementation, we would properly map the config fields
	return oc.LoadFromEnvironment()
}

// LoadFromEnvironment loads OAuth2 configuration from environment variables
// This is a placeholder - actual implementation would use os.Getenv or a config library
func (oc *OAuth2Config) LoadFromEnvironment() error {
	// Microsoft configuration
	// In a real implementation, these would come from environment variables
	// For now, we'll just validate that the structure is correct
	
	// Validate that all required fields would be present
	if oc.Microsoft.ClientID == "" {
		return errors.New("MICROSOFT_CLIENT_ID environment variable is required")
	}
	if oc.Microsoft.ClientSecret == "" {
		return errors.New("MICROSOFT_CLIENT_SECRET environment variable is required")
	}
	if oc.Microsoft.RedirectURL == "" {
		return errors.New("MICROSOFT_REDIRECT_URL environment variable is required")
	}
	
	// GitHub configuration
	if oc.GitHub.ClientID == "" {
		return errors.New("GITHUB_CLIENT_ID environment variable is required")
	}
	if oc.GitHub.ClientSecret == "" {
		return errors.New("GITHUB_CLIENT_SECRET environment variable is required")
	}
	if oc.GitHub.RedirectURL == "" {
		return errors.New("GITHUB_REDIRECT_URL environment variable is required")
	}
	
	return oc.Validate()
}