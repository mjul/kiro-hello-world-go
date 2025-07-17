package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

// TemplateManager handles template loading and rendering
type TemplateManager struct {
	templates map[string]*template.Template
	basePath  string
}

// NewTemplateManager creates a new template manager
func NewTemplateManager(basePath string) *TemplateManager {
	return &TemplateManager{
		templates: make(map[string]*template.Template),
		basePath:  basePath,
	}
}

// LoadTemplates loads all templates from the templates directory
func (tm *TemplateManager) LoadTemplates() error {
	// Define template files
	templateFiles := []string{
		filepath.Join(tm.basePath, "base.html"),
		filepath.Join(tm.basePath, "login.html"),
		filepath.Join(tm.basePath, "dashboard.html"),
		filepath.Join(tm.basePath, "error.html"),
	}

	// Parse all templates together to enable template inheritance
	tmpl, err := template.ParseFiles(templateFiles...)
	if err != nil {
		return fmt.Errorf("failed to parse templates: %w", err)
	}

	// Store each template by name
	for _, t := range tmpl.Templates() {
		tm.templates[t.Name()] = t
	}

	return nil
}

// RenderTemplate renders a template with the given data and writes to Gin context
func (tm *TemplateManager) RenderTemplate(c *gin.Context, templateName string, data interface{}) {
	tmpl, exists := tm.templates[templateName]
	if !exists {
		// For template not found errors, don't call HandleError to avoid infinite loops
		// Instead, return a simple error response
		c.Status(http.StatusInternalServerError)
		c.Header("Content-Type", "text/html; charset=utf-8")
		
		html := fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Template Error</title></head>
<body><h1>Template Error</h1><p>Template %s not found</p></body></html>`, templateName)
		c.Writer.WriteString(html)
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	
	if err := tmpl.Execute(c.Writer, data); err != nil {
		// For template render errors, also avoid HandleError to prevent loops
		c.Status(http.StatusInternalServerError)
		c.Header("Content-Type", "text/html; charset=utf-8")
		
		html := fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Template Error</title></head>
<body><h1>Template Render Error</h1><p>Failed to render template %s: %v</p></body></html>`, templateName, err)
		c.Writer.WriteString(html)
		return
	}
}

// LoginPageData represents data for the login page template
type LoginPageData struct {
	Title string
	Error string
}

// DashboardPageData represents data for the dashboard page template
type DashboardPageData struct {
	Title    string
	Username string
	Email    string
	Avatar   string
	Provider string
}

// SetTemplate sets a template for testing purposes
func (tm *TemplateManager) SetTemplate(name string, tmpl *template.Template) {
	tm.templates[name] = tmpl
}

// HasTemplate checks if a template exists
func (tm *TemplateManager) HasTemplate(templateName string) bool {
	_, exists := tm.templates[templateName]
	return exists
}