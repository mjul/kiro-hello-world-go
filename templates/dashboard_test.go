package main

import (
	"bytes"
	"html/template"
	"testing"
	"time"
)

type DashboardPageData struct {
	Username  string
	Email     string
	Avatar    string
	Provider  string
	CreatedAt time.Time
}

func TestDashboardTemplateRendering(t *testing.T) {
	// Parse all templates
	tmpl, err := template.ParseFiles("base.html", "dashboard.html")
	if err != nil {
		t.Fatalf("Failed to parse dashboard template: %v", err)
	}

	// Test rendering with user data
	var buf bytes.Buffer
	data := DashboardPageData{
		Username:  "johndoe",
		Email:     "john.doe@example.com",
		Avatar:    "https://example.com/avatar.jpg",
		Provider:  "microsoft",
		CreatedAt: time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
	}
	
	err = tmpl.ExecuteTemplate(&buf, "base.html", data)
	if err != nil {
		t.Fatalf("Failed to execute dashboard template: %v", err)
	}

	output := buf.Bytes()

	// Check for dashboard-specific content
	if !bytes.Contains(output, []byte("<title>Dashboard - SSO Web App</title>")) {
		t.Error("Template should contain custom dashboard title")
	}

	if !bytes.Contains(output, []byte("Dashboard")) {
		t.Error("Template should contain 'Dashboard' header")
	}

	// Check for prominent username display with "hello" format
	if !bytes.Contains(output, []byte("hello johndoe")) {
		t.Error("Template should display 'hello {username}' prominently")
	}

	// Check for user information display
	if !bytes.Contains(output, []byte("john.doe@example.com")) {
		t.Error("Template should display user email")
	}

	if !bytes.Contains(output, []byte("https://example.com/avatar.jpg")) {
		t.Error("Template should display user avatar")
	}

	if !bytes.Contains(output, []byte("microsoft")) {
		t.Error("Template should display authentication provider")
	}

	// Check for logout button with proper form submission
	if !bytes.Contains(output, []byte(`<form method="POST" action="/logout"`)) {
		t.Error("Template should contain logout form with POST method")
	}

	if !bytes.Contains(output, []byte("Sign Out")) {
		t.Error("Template should contain logout button text")
	}

	// Check for account information section
	if !bytes.Contains(output, []byte("Account Information")) {
		t.Error("Template should contain account information section")
	}

	// Check for formatted date
	if !bytes.Contains(output, []byte("January 15, 2024")) {
		t.Error("Template should format and display creation date")
	}
}

func TestDashboardTemplateMinimalData(t *testing.T) {
	// Parse all templates
	tmpl, err := template.ParseFiles("base.html", "dashboard.html")
	if err != nil {
		t.Fatalf("Failed to parse dashboard template: %v", err)
	}

	// Test rendering with minimal user data (only username required)
	var buf bytes.Buffer
	data := DashboardPageData{
		Username: "testuser",
		Provider: "github",
	}
	
	err = tmpl.ExecuteTemplate(&buf, "base.html", data)
	if err != nil {
		t.Fatalf("Failed to execute dashboard template with minimal data: %v", err)
	}

	output := buf.Bytes()

	// Check that template still renders with minimal data
	if !bytes.Contains(output, []byte("hello testuser")) {
		t.Error("Template should display username even with minimal data")
	}

	if !bytes.Contains(output, []byte("github")) {
		t.Error("Template should display provider even with minimal data")
	}

	// Check that optional fields don't break the template
	if !bytes.Contains(output, []byte("Sign Out")) {
		t.Error("Template should still show logout functionality with minimal data")
	}
}

func TestDashboardTemplateStructure(t *testing.T) {
	// Parse all templates
	tmpl, err := template.ParseFiles("base.html", "dashboard.html")
	if err != nil {
		t.Fatalf("Failed to parse dashboard template: %v", err)
	}

	// Test rendering to check overall structure
	var buf bytes.Buffer
	data := DashboardPageData{
		Username: "structuretest",
		Provider: "microsoft",
	}
	
	err = tmpl.ExecuteTemplate(&buf, "base.html", data)
	if err != nil {
		t.Fatalf("Failed to execute dashboard template: %v", err)
	}

	output := buf.Bytes()

	// Check for proper card structure
	if !bytes.Contains(output, []byte(`class="card"`)) {
		t.Error("Template should use card layout from base template")
	}

	// Check for JavaScript functionality
	if !bytes.Contains(output, []byte("refreshSession")) {
		t.Error("Template should include JavaScript for session refresh")
	}

	if !bytes.Contains(output, []byte("Are you sure you want to sign out?")) {
		t.Error("Template should include logout confirmation")
	}

	// Check for SVG icons
	if !bytes.Contains(output, []byte("<svg")) {
		t.Error("Template should contain SVG icons for buttons")
	}

	// Check for responsive grid layout
	if !bytes.Contains(output, []byte("grid-template-columns")) {
		t.Error("Template should include responsive grid layout for account info")
	}

	// Check for Quick Actions section
	if !bytes.Contains(output, []byte("Quick Actions")) {
		t.Error("Template should include Quick Actions section")
	}
}