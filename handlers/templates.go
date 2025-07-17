package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"time"

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
	// Parse each template individually with the base template to enable inheritance
	templateConfigs := map[string][]string{
		"login.html": {
			filepath.Join(tm.basePath, "base.html"),
			filepath.Join(tm.basePath, "login.html"),
		},
		"dashboard.html": {
			filepath.Join(tm.basePath, "base.html"),
			filepath.Join(tm.basePath, "dashboard.html"),
		},
		"error.html": {
			filepath.Join(tm.basePath, "base.html"),
			filepath.Join(tm.basePath, "error.html"),
		},
	}

	// Parse each template set separately
	for templateName, files := range templateConfigs {
		tmpl, err := template.ParseFiles(files...)
		if err != nil {
			return fmt.Errorf("failed to parse template %s: %w", templateName, err)
		}
		tm.templates[templateName] = tmpl
	}

	return nil
}

// RenderTemplate renders a template with the given data and writes to Gin context
func (tm *TemplateManager) RenderTemplate(c *gin.Context, templateName string, data interface{}) {
	// Check if the specific template exists
	tmpl, exists := tm.templates[templateName]
	if !exists {
		c.Status(http.StatusInternalServerError)
		c.Header("Content-Type", "text/html; charset=utf-8")
		
		html := fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Template Error</title></head>
<body><h1>Template Error</h1><p>Template %s not found</p></body></html>`, templateName)
		c.Writer.WriteString(html)
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	
	// Execute the base template from the specific template set
	// This will render the base.html template with the specific template's defined blocks
	if err := tmpl.ExecuteTemplate(c.Writer, "base.html", data); err != nil {
		// For template render errors, return 500 status code, not 200
		c.Status(http.StatusInternalServerError)
		c.Header("Content-Type", "text/html; charset=utf-8")
		
		html := fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Template Render Error</title></head>
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
	Title     string
	Username  string
	Email     string
	Avatar    string
	Provider  string
	CreatedAt time.Time
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