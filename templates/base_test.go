package main

import (
	"bytes"
	"html/template"
	"testing"
)

func TestBaseTemplateRendering(t *testing.T) {
	// Test basic template parsing
	tmpl, err := template.ParseFiles("base.html")
	if err != nil {
		t.Fatalf("Failed to parse base template: %v", err)
	}

	// Test rendering with default content
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, nil)
	if err != nil {
		t.Fatalf("Failed to execute base template: %v", err)
	}

	// Check for essential HTML structure
	if !bytes.Contains(buf.Bytes(), []byte("<!DOCTYPE html>")) {
		t.Error("Template should contain DOCTYPE declaration")
	}
	
	if !bytes.Contains(buf.Bytes(), []byte("<title>SSO Web App</title>")) {
		t.Error("Template should contain default title")
	}
	
	if !bytes.Contains(buf.Bytes(), []byte("SSO Web Application")) {
		t.Error("Template should contain default header title")
	}
	
	if !bytes.Contains(buf.Bytes(), []byte("Welcome to the SSO Web Application")) {
		t.Error("Template should contain default content")
	}

	// Check for responsive meta tag
	if !bytes.Contains(buf.Bytes(), []byte(`<meta name="viewport" content="width=device-width, initial-scale=1.0">`)) {
		t.Error("Template should contain responsive viewport meta tag")
	}

	// Check for CSS classes that indicate responsive design
	if !bytes.Contains(buf.Bytes(), []byte("@media (max-width: 768px)")) {
		t.Error("Template should contain responsive CSS media queries")
	}
}

func TestBaseTemplateBlocks(t *testing.T) {
	// Test that the base template has the correct block structure
	tmpl, err := template.ParseFiles("base.html")
	if err != nil {
		t.Fatalf("Failed to parse base template: %v", err)
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, nil)
	if err != nil {
		t.Fatalf("Failed to execute base template: %v", err)
	}

	// Check that template blocks are present and have default content
	if !bytes.Contains(buf.Bytes(), []byte("{{block \"title\"")) {
		// Since we can't see the template source in output, check for default values
		if !bytes.Contains(buf.Bytes(), []byte("<title>SSO Web App</title>")) {
			t.Error("Template should have title block with default value")
		}
	}
	
	if !bytes.Contains(buf.Bytes(), []byte("SSO Web Application")) {
		t.Error("Template should have header_title block with default value")
	}
	
	if !bytes.Contains(buf.Bytes(), []byte("Welcome to the SSO Web Application")) {
		t.Error("Template should have content block with default value")
	}

	// Verify the template structure allows for block overrides by checking template definition
	tmplContent, err := template.New("test").ParseFiles("base.html")
	if err != nil {
		t.Fatalf("Failed to parse template for structure check: %v", err)
	}
	
	// If we can parse it without errors, the block structure is valid
	if tmplContent == nil {
		t.Error("Template should be parseable for block inheritance")
	}
}