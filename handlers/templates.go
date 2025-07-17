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
		// Create a template error and handle it through the error system
		err := NewTemplateError("TEMPLATE_NOT_FOUND", 
			fmt.Sprintf("Template %s not found", templateName), nil)
		
		// Try to get server from context to handle error properly
		if serverInterface, exists := c.Get("server"); exists {
			if server, ok := serverInterface.(*Server); ok {
				server.HandleError(c, err)
				return
			}
		}
		
		// Fallback to JSON response if server not available
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Template %s not found", templateName),
		})
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	
	if err := tmpl.Execute(c.Writer, data); err != nil {
		// Create a template error and handle it through the error system
		templateErr := NewTemplateError("TEMPLATE_RENDER_FAILED", 
			fmt.Sprintf("Failed to render template %s", templateName), err)
		
		// Try to get server from context to handle error properly
		if serverInterface, exists := c.Get("server"); exists {
			if server, ok := serverInterface.(*Server); ok {
				server.HandleError(c, templateErr)
				return
			}
		}
		
		// Fallback to JSON response if server not available
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to render template: %v", err),
		})
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