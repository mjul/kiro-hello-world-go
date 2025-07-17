package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sso-web-app/config"
	"sso-web-app/database"
	"sso-web-app/handlers"
	"sso-web-app/services"
	"syscall"
	"time"
)

func main() {
	log.Println("=== SSO Web App Starting ===")
	
	// Load and validate configuration
	log.Println("Loading configuration...")
	cfg, err := config.Load()
	if err != nil {
		log.Printf("Configuration validation failed:")
		if validationErrors, ok := err.(config.ValidationErrors); ok {
			for _, validationErr := range validationErrors {
				log.Printf("  - %s", validationErr.Error())
			}
			log.Println("\nFor configuration help, run with --help flag")
		}
		log.Fatalf("Failed to load configuration: %v", err)
	}
	log.Println("✓ Configuration loaded and validated successfully")

	// Log startup information
	log.Printf("Server configuration:")
	log.Printf("  - Port: %s", cfg.Port)
	log.Printf("  - Base URL: %s", cfg.BaseURL)
	log.Printf("  - Database: %s", cfg.DatabaseURL)
	log.Printf("  - OAuth Providers: Microsoft, GitHub")
	
	// Initialize database with health check
	log.Println("Initializing database...")
	db, err := database.Initialize(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer func() {
		log.Println("Closing database connection...")
		if err := db.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		} else {
			log.Println("✓ Database connection closed")
		}
	}()
	
	// Perform database health check
	if err := db.Ping(); err != nil {
		log.Fatalf("Database health check failed: %v", err)
	}
	log.Println("✓ Database initialized and health check passed")
	
	// Initialize OAuth2 configuration
	log.Println("Setting up OAuth2 providers...")
	oauthConfig := services.NewOAuth2Config()
	
	// Set Microsoft configuration
	oauthConfig.Microsoft.ClientID = cfg.Microsoft.ClientID
	oauthConfig.Microsoft.ClientSecret = cfg.Microsoft.ClientSecret
	oauthConfig.Microsoft.RedirectURL = cfg.Microsoft.RedirectURL
	oauthConfig.Microsoft.Scopes = cfg.Microsoft.Scopes
	
	// Set GitHub configuration
	oauthConfig.GitHub.ClientID = cfg.GitHub.ClientID
	oauthConfig.GitHub.ClientSecret = cfg.GitHub.ClientSecret
	oauthConfig.GitHub.RedirectURL = cfg.GitHub.RedirectURL
	oauthConfig.GitHub.Scopes = cfg.GitHub.Scopes
	log.Println("✓ OAuth2 providers configured")
	
	// Initialize repositories
	log.Println("Initializing data repositories...")
	userRepo := database.NewUserRepository(db)
	sessionStore := database.NewSessionStore(db)
	log.Println("✓ Data repositories initialized")
	
	// Initialize auth service
	log.Println("Initializing authentication service...")
	authService := services.NewAuthService(
		oauthConfig,
		userRepo,
		sessionStore,
		24*time.Hour, // 24 hour session timeout
	)
	log.Println("✓ Authentication service initialized")
	
	// Initialize web server
	log.Println("Initializing web server...")
	server := handlers.NewServer(cfg, db, authService, userRepo)
	log.Println("✓ Web server initialized")
	
	// Create HTTP server with timeouts
	httpServer := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      server.Router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	// Start session cleanup routine
	log.Println("Starting session cleanup routine...")
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		
		for range ticker.C {
			if err := sessionStore.Cleanup(); err != nil {
				log.Printf("Session cleanup error: %v", err)
			} else {
				log.Println("Session cleanup completed")
			}
		}
	}()
	
	// Set up graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	
	// Start server in a goroutine
	go func() {
		log.Printf("🚀 Server starting on http://localhost:%s", cfg.Port)
		log.Printf("🔐 Login at: %s/login", cfg.BaseURL)
		log.Println("=== SSO Web App Ready ===")
		
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()
	
	// Wait for interrupt signal
	<-quit
	log.Println("\n=== Shutting down SSO Web App ===")
	
	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Shutdown HTTP server
	log.Println("Shutting down HTTP server...")
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	} else {
		log.Println("✓ HTTP server shutdown complete")
	}
	
	log.Println("=== SSO Web App Stopped ===")
}

// printHelp prints configuration help and exits
func printHelp() {
	config.PrintConfigurationHelp()
	os.Exit(0)
}

func init() {
	// Check for help flag
	for _, arg := range os.Args[1:] {
		if arg == "--help" || arg == "-h" {
			printHelp()
		}
	}
}