package models

import (
	"testing"
	"time"
)

func TestSession_Validate(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	
	tests := []struct {
		name    string
		session Session
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid session",
			session: Session{
				ID:        "session123",
				UserID:    1,
				ExpiresAt: future,
				CreatedAt: now,
			},
			wantErr: false,
		},
		{
			name: "empty session id",
			session: Session{
				ID:        "",
				UserID:    1,
				ExpiresAt: future,
				CreatedAt: now,
			},
			wantErr: true,
			errMsg:  "session id is required",
		},
		{
			name: "whitespace only session id",
			session: Session{
				ID:        "   ",
				UserID:    1,
				ExpiresAt: future,
				CreatedAt: now,
			},
			wantErr: true,
			errMsg:  "session id is required",
		},
		{
			name: "zero user id",
			session: Session{
				ID:        "session123",
				UserID:    0,
				ExpiresAt: future,
				CreatedAt: now,
			},
			wantErr: true,
			errMsg:  "user_id must be a positive integer",
		},
		{
			name: "negative user id",
			session: Session{
				ID:        "session123",
				UserID:    -1,
				ExpiresAt: future,
				CreatedAt: now,
			},
			wantErr: true,
			errMsg:  "user_id must be a positive integer",
		},
		{
			name: "zero expires_at",
			session: Session{
				ID:        "session123",
				UserID:    1,
				ExpiresAt: time.Time{},
				CreatedAt: now,
			},
			wantErr: true,
			errMsg:  "expires_at is required",
		},
		{
			name: "zero created_at",
			session: Session{
				ID:        "session123",
				UserID:    1,
				ExpiresAt: future,
				CreatedAt: time.Time{},
			},
			wantErr: true,
			errMsg:  "created_at is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.session.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Session.Validate() expected error but got nil")
					return
				}
				if err.Error() != tt.errMsg {
					t.Errorf("Session.Validate() error = %v, want %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Session.Validate() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestSession_IsValid(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	
	tests := []struct {
		name    string
		session Session
		want    bool
	}{
		{
			name: "valid session",
			session: Session{
				ID:        "session123",
				UserID:    1,
				ExpiresAt: future,
				CreatedAt: now,
			},
			want: true,
		},
		{
			name: "invalid session - missing id",
			session: Session{
				UserID:    1,
				ExpiresAt: future,
				CreatedAt: now,
			},
			want: false,
		},
		{
			name: "invalid session - zero user id",
			session: Session{
				ID:        "session123",
				UserID:    0,
				ExpiresAt: future,
				CreatedAt: now,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.session.IsValid(); got != tt.want {
				t.Errorf("Session.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_IsExpired(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	
	tests := []struct {
		name    string
		session Session
		want    bool
	}{
		{
			name: "not expired session",
			session: Session{
				ID:        "session123",
				UserID:    1,
				ExpiresAt: future,
				CreatedAt: now,
			},
			want: false,
		},
		{
			name: "expired session",
			session: Session{
				ID:        "session123",
				UserID:    1,
				ExpiresAt: past,
				CreatedAt: past,
			},
			want: true,
		},
		{
			name: "session expiring right now (should be expired)",
			session: Session{
				ID:        "session123",
				UserID:    1,
				ExpiresAt: now.Add(-time.Millisecond),
				CreatedAt: past,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.session.IsExpired(); got != tt.want {
				t.Errorf("Session.IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_IsActive(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	
	tests := []struct {
		name    string
		session Session
		want    bool
	}{
		{
			name: "active session (valid and not expired)",
			session: Session{
				ID:        "session123",
				UserID:    1,
				ExpiresAt: future,
				CreatedAt: now,
			},
			want: true,
		},
		{
			name: "inactive session (expired)",
			session: Session{
				ID:        "session123",
				UserID:    1,
				ExpiresAt: past,
				CreatedAt: past,
			},
			want: false,
		},
		{
			name: "inactive session (invalid - missing id)",
			session: Session{
				UserID:    1,
				ExpiresAt: future,
				CreatedAt: now,
			},
			want: false,
		},
		{
			name: "inactive session (invalid and expired)",
			session: Session{
				UserID:    0, // invalid user id
				ExpiresAt: past,
				CreatedAt: past,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.session.IsActive(); got != tt.want {
				t.Errorf("Session.IsActive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_TimeUntilExpiry(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	
	tests := []struct {
		name    string
		session Session
		want    time.Duration
	}{
		{
			name: "expired session returns 0",
			session: Session{
				ID:        "session123",
				UserID:    1,
				ExpiresAt: past,
				CreatedAt: past,
			},
			want: 0,
		},
		{
			name: "active session returns positive duration",
			session: Session{
				ID:        "session123",
				UserID:    1,
				ExpiresAt: future,
				CreatedAt: now,
			},
			want: time.Hour, // approximately
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.session.TimeUntilExpiry()
			if tt.name == "expired session returns 0" {
				if got != 0 {
					t.Errorf("Session.TimeUntilExpiry() = %v, want %v", got, tt.want)
				}
			} else {
				// For active sessions, check that we get a positive duration close to expected
				if got <= 0 || got > time.Hour+time.Minute {
					t.Errorf("Session.TimeUntilExpiry() = %v, expected positive duration around %v", got, tt.want)
				}
			}
		})
	}
}

func TestSession_StructFields(t *testing.T) {
	// Test that all required fields are present and have correct types
	now := time.Now()
	future := now.Add(time.Hour)
	
	session := Session{
		ID:        "session123",
		UserID:    1,
		ExpiresAt: future,
		CreatedAt: now,
	}

	// Verify field values
	if session.ID != "session123" {
		t.Errorf("Expected ID to be 'session123', got %s", session.ID)
	}
	if session.UserID != 1 {
		t.Errorf("Expected UserID to be 1, got %d", session.UserID)
	}
	if !session.ExpiresAt.Equal(future) {
		t.Errorf("Expected ExpiresAt to be %v, got %v", future, session.ExpiresAt)
	}
	if !session.CreatedAt.Equal(now) {
		t.Errorf("Expected CreatedAt to be %v, got %v", now, session.CreatedAt)
	}
}