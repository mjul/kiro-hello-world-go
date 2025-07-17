package main

import (
	"bytes"
	"html/template"
	"testing"
)

type LoginPageData struct {
	Title string
	Error string
}

func TestLoginTemplateRendering(t *testing.T) {
	// Parse both base and login templates
	tmpl, err := template.ParseFiles("base.html", "login.html")
	if err != nil {
		t.Fatalf("Failed to parse login template: %v", err)
	}

	// Test rendering without error
	var buf bytes.Buffer
	data := LoginPageData{
		Title: "Login Test",
		Error: "",
	}
	
	err = tmpl.ExecuteTemplate(&buf, "base.html", data)
	if err != nil {
		t.Fatalf("Failed to execute login template: %v", err)
	}

	output := buf.Bytes()

	// Check for login-specific content
	if !bytes.Contains(output, []byte("<title>Login - SSO Web App</title>")) {
		t.Error("Template should contain custom login title")
	}

	if !bytes.Contains(output, []byte("Sign In")) {
		t.Error("Template should contain 'Sign In' header")
	}

	if !bytes.Contains(output, []byte("Sign in with Microsoft 365")) {
		t.Error("Template should contain Microsoft 365 login button")
	}

	if !bytes.Contains(output, []byte("Sign in with GitHub")) {
		t.Error("Template should contain GitHub login button")
	}

	if !bytes.Contains(output, []byte(`href="/auth/microsoft"`)) {
		t.Error("Template should contain Microsoft OAuth URL")
	}

	if !bytes.Contains(output, []byte(`href="/auth/github"`)) {
		t.Error("Template should contain GitHub OAuth URL")
	}

	// Check for proper CSS classes
	if !bytes.Contains(output, []byte("btn-microsoft")) {
		t.Error("Template should contain Microsoft button styling")
	}

	if !bytes.Contains(output, []byte("btn-github")) {
		t.Error("Template should contain GitHub button styling")
	}

	// Check for SVG icons
	if !bytes.Contains(output, []byte("<svg")) {
		t.Error("Template should contain SVG icons for providers")
	}

	// Verify no error message is displayed when Error is empty
	// Look for the actual div with alert-error class, not just the CSS definition
	if bytes.Contains(output, []byte(`<div class="alert alert-error"`)) {
		t.Error("Template should not show error alert div when no error is provided")
	}
}

func TestLoginTemplateWithError(t *testing.T) {
	// Parse both base and login templates
	tmpl, err := template.ParseFiles("base.html", "login.html")
	if err != nil {
		t.Fatalf("Failed to parse login template: %v", err)
	}

	// Test rendering with error message
	var buf bytes.Buffer
	data := LoginPageData{
		Title: "Login Test",
		Error: "Authentication failed. Please try again.",
	}
	
	err = tmpl.ExecuteTemplate(&buf, "base.html", data)
	if err != nil {
		t.Fatalf("Failed to execute login template with error: %v", err)
	}

	output := buf.Bytes()

	// Check that error message is displayed
	if !bytes.Contains(output, []byte("alert-error")) {
		t.Error("Template should show error alert when error is provided")
	}

	if !bytes.Contains(output, []byte("Authentication failed. Please try again.")) {
		t.Error("Template should display the specific error message")
	}
}

func TestLoginTemplateStructure(t *testing.T) {
	// Parse both base and login templates
	tmpl, err := template.ParseFiles("base.html", "login.html")
	if err != nil {
		t.Fatalf("Failed to parse login template: %v", err)
	}

	// Test rendering to check overall structure
	var buf bytes.Buffer
	err = tmpl.ExecuteTemplate(&buf, "base.html", nil)
	if err != nil {
		t.Fatalf("Failed to execute login template: %v", err)
	}

	output := buf.Bytes()

	// Check for responsive design elements
	if !bytes.Contains(output, []byte("@media (max-width: 768px)")) {
		t.Error("Template should include responsive CSS from base template")
	}

	// Check for proper card structure
	if !bytes.Contains(output, []byte(`class="card"`)) {
		t.Error("Template should use card layout from base template")
	}

	// Check for JavaScript functionality
	if !bytes.Contains(output, []byte("Redirecting...")) {
		t.Error("Template should include JavaScript for button feedback")
	}

	// Check for accessibility and UX elements
	if !bytes.Contains(output, []byte("About This Application")) {
		t.Error("Template should include informational content about the app")
	}

	if !bytes.Contains(output, []byte("terms of service")) {
		t.Error("Template should include terms of service notice")
	}
}