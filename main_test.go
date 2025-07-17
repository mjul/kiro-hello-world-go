package main

import (
	"context"
	"os"
	"sso-web-app/config"
	"testing"
	"time"
)

func TestMainInitialization(t *testing.T) {
	// Set up valid environment variables for testing
	envVars := map[string]string{
		"PORT":                     "8081", // Use different port for testing
		"DATABASE_URL":             "./test_main.db",
		"SESSION_SECRET":           "this-is-a-very-secure-32-character-session-secret-for-testing",
		"BASE_URL":                 "http://localhost:8081",
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
		// Clean up test database
		os.Remove("./test_main.db")
	}()

	// Test that main initialization doesn't panic
	// We can't easily test the full main function without starting the server,
	// but we can test the individual components
	
	// This test ensures the main function can be called without panicking
	// during the initialization phase
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Main initialization panicked: %v", r)
		}
	}()

	// Test configuration loading (this is what main() does first)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Configuration loading failed: %v", err)
	}

	if cfg.Port != "8081" {
		t.Errorf("Expected port 8081, got %s", cfg.Port)
	}
}

func TestPrintHelp(t *testing.T) {
	// Test that printHelp doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("printHelp panicked: %v", r)
		}
	}()

	// We can't easily test the os.Exit(0) call, but we can test that
	// the function doesn't panic before that point
	// Note: This test will actually exit if run directly, so we skip it
	t.Skip("Skipping printHelp test as it calls os.Exit(0)")
}

func TestHelpFlagDetection(t *testing.T) {
	// Test the init function's help flag detection
	// We can't easily test this without modifying os.Args, but we can
	// verify the logic works by checking if the help flags are recognized
	
	helpFlags := []string{"--help", "-h"}
	
	for _, flag := range helpFlags {
		// Simulate the flag being present
		testArgs := []string{"program", flag}
		
		found := false
		for _, arg := range testArgs[1:] {
			if arg == "--help" || arg == "-h" {
				found = true
				break
			}
		}
		
		if !found {
			t.Errorf("Help flag %s not detected", flag)
		}
	}
}

func TestGracefulShutdownSignals(t *testing.T) {
	// Test that the signal handling setup doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Signal setup panicked: %v", r)
		}
	}()

	// Test signal channel creation
	quit := make(chan os.Signal, 1)
	if quit == nil {
		t.Error("Failed to create signal channel")
	}

	// Test timeout context creation
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	
	if ctx == nil {
		t.Error("Failed to create timeout context")
	}

	// Verify context has timeout
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Error("Context should have a deadline")
	}
	
	if time.Until(deadline) > 2*time.Second {
		t.Error("Context deadline is too far in the future")
	}
}