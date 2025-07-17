package main

import (
	"fmt"
	"html/template"
	"strings"
	"testing"
	"time"
)

// Simple template manager for testing
type SimpleTemplateManager struct {
	templates map[string]*template.Template
}

func NewSimpleTemplateManager() *SimpleTemplateManager {
	return &SimpleTemplateManager{
		templates: make(map[string]*template.Template),
	}
}

func (stm *SimpleTemplateManager) LoadTemplates() error {
	// Parse all templates together
	tmpl, err := template.ParseFiles("base.html", "login.html", "dashboard.html")
	if err != nil {
		return err
	}

	// Store templates by name
	for _, t := range tmpl.Templates() {
		stm.templates[t.Name()] = t
	}

	return nil
}

func (stm *SimpleTemplateManager) Render(templateName string, data interface{}) (string, error) {
	tmpl, exists := stm.templates[templateName]
	if !exists {
		return "", fmt.Errorf("template %s not found", templateName)
	}

	var buf strings.Builder
	err := tmpl.Execute(&buf, data)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// Test data structure
type TestTemplateData struct {
	Title     string
	Error     string
	Username  string
	Email     string
	Avatar    string
	Provider  string
	CreatedAt time.Time
}

func TestSimpleTemplateManagerLoadAndRender(t *testing.T) {
	stm := NewSimpleTemplateManager()
	
	err := stm.LoadTemplates()
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	// Test login template rendering
	loginData := TestTemplateData{
		Title: "Login Test",
		Error: "",
	}
	
	output, err := stm.Render("base.html", loginData)
	if err != nil {
		t.Fatalf("Failed to render base template: %v", err)
	}

	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Error("Template should render valid HTML")
	}

	if !strings.Contains(output, "SSO Web App") {
		t.Error("Template should contain default title")
	}
}

func TestTemplateInheritance(t *testing.T) {
	stm := NewSimpleTemplateManager()
	
	err := stm.LoadTemplates()
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	// Test that templates can be parsed together (inheritance works)
	if len(stm.templates) == 0 {
		t.Error("No templates were loaded")
	}

	// Check that all expected templates are present
	expectedTemplates := []string{"base.html", "login.html", "dashboard.html"}
	for _, expected := range expectedTemplates {
		if _, exists := stm.templates[expected]; !exists {
			t.Errorf("Expected template %s was not loaded", expected)
		}
	}
}

func TestTemplateErrorHandling(t *testing.T) {
	stm := NewSimpleTemplateManager()
	
	err := stm.LoadTemplates()
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	// Test rendering non-existent template
	_, err = stm.Render("nonexistent.html", nil)
	if err == nil {
		t.Error("Should return error for non-existent template")
	}
}

func TestTemplateWithData(t *testing.T) {
	stm := NewSimpleTemplateManager()
	
	err := stm.LoadTemplates()
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	// Test with user data
	userData := TestTemplateData{
		Username:  "testuser",
		Email:     "test@example.com",
		Provider:  "microsoft",
		CreatedAt: time.Now(),
	}
	
	output, err := stm.Render("base.html", userData)
	if err != nil {
		t.Fatalf("Failed to render template with data: %v", err)
	}

	// Basic checks that template rendered
	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Error("Template should render valid HTML")
	}

	if len(output) < 100 {
		t.Error("Template output seems too short")
	}
}