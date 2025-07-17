package models

import (
	"testing"
	"time"
)

func TestUser_Validate(t *testing.T) {
	tests := []struct {
		name    string
		user    User
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid user with microsoft provider",
			user: User{
				Provider:   "microsoft",
				ProviderID: "12345",
				Username:   "john.doe",
				Email:      "john@example.com",
			},
			wantErr: false,
		},
		{
			name: "valid user with github provider",
			user: User{
				Provider:   "github",
				ProviderID: "67890",
				Username:   "johndoe",
				Email:      "john@github.com",
			},
			wantErr: false,
		},
		{
			name: "empty provider",
			user: User{
				Provider:   "",
				ProviderID: "12345",
				Username:   "john.doe",
			},
			wantErr: true,
			errMsg:  "provider is required",
		},
		{
			name: "whitespace only provider",
			user: User{
				Provider:   "   ",
				ProviderID: "12345",
				Username:   "john.doe",
			},
			wantErr: true,
			errMsg:  "provider is required",
		},
		{
			name: "empty provider_id",
			user: User{
				Provider:   "microsoft",
				ProviderID: "",
				Username:   "john.doe",
			},
			wantErr: true,
			errMsg:  "provider_id is required",
		},
		{
			name: "whitespace only provider_id",
			user: User{
				Provider:   "microsoft",
				ProviderID: "   ",
				Username:   "john.doe",
			},
			wantErr: true,
			errMsg:  "provider_id is required",
		},
		{
			name: "empty username",
			user: User{
				Provider:   "microsoft",
				ProviderID: "12345",
				Username:   "",
			},
			wantErr: true,
			errMsg:  "username is required",
		},
		{
			name: "whitespace only username",
			user: User{
				Provider:   "microsoft",
				ProviderID: "12345",
				Username:   "   ",
			},
			wantErr: true,
			errMsg:  "username is required",
		},
		{
			name: "invalid provider",
			user: User{
				Provider:   "google",
				ProviderID: "12345",
				Username:   "john.doe",
			},
			wantErr: true,
			errMsg:  "provider must be 'microsoft' or 'github'",
		},
		{
			name: "case insensitive provider validation - uppercase",
			user: User{
				Provider:   "MICROSOFT",
				ProviderID: "12345",
				Username:   "john.doe",
			},
			wantErr: false,
		},
		{
			name: "case insensitive provider validation - mixed case",
			user: User{
				Provider:   "GitHub",
				ProviderID: "12345",
				Username:   "john.doe",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.user.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("User.Validate() expected error but got nil")
					return
				}
				if err.Error() != tt.errMsg {
					t.Errorf("User.Validate() error = %v, want %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("User.Validate() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestUser_IsValid(t *testing.T) {
	tests := []struct {
		name string
		user User
		want bool
	}{
		{
			name: "valid user",
			user: User{
				Provider:   "microsoft",
				ProviderID: "12345",
				Username:   "john.doe",
			},
			want: true,
		},
		{
			name: "invalid user - missing provider",
			user: User{
				ProviderID: "12345",
				Username:   "john.doe",
			},
			want: false,
		},
		{
			name: "invalid user - missing provider_id",
			user: User{
				Provider: "microsoft",
				Username: "john.doe",
			},
			want: false,
		},
		{
			name: "invalid user - missing username",
			user: User{
				Provider:   "microsoft",
				ProviderID: "12345",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.user.IsValid(); got != tt.want {
				t.Errorf("User.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser_StructFields(t *testing.T) {
	// Test that all required fields are present and have correct types
	now := time.Now()
	user := User{
		ID:         1,
		Provider:   "microsoft",
		ProviderID: "12345",
		Username:   "john.doe",
		Email:      "john@example.com",
		AvatarURL:  "https://example.com/avatar.jpg",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	// Verify field values
	if user.ID != 1 {
		t.Errorf("Expected ID to be 1, got %d", user.ID)
	}
	if user.Provider != "microsoft" {
		t.Errorf("Expected Provider to be 'microsoft', got %s", user.Provider)
	}
	if user.ProviderID != "12345" {
		t.Errorf("Expected ProviderID to be '12345', got %s", user.ProviderID)
	}
	if user.Username != "john.doe" {
		t.Errorf("Expected Username to be 'john.doe', got %s", user.Username)
	}
	if user.Email != "john@example.com" {
		t.Errorf("Expected Email to be 'john@example.com', got %s", user.Email)
	}
	if user.AvatarURL != "https://example.com/avatar.jpg" {
		t.Errorf("Expected AvatarURL to be 'https://example.com/avatar.jpg', got %s", user.AvatarURL)
	}
}