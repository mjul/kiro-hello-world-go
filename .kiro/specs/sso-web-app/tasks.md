# Implementation Plan

- [x] 1. Set up project structure and dependencies





  - Initialize Go module with required dependencies (Gin, SQLite driver, OAuth2 libraries)
  - Create directory structure for handlers, models, services, templates, and database
  - Set up basic configuration loading from environment variables
  - _Requirements: 4.3, 5.5_

- [ ] 2. Implement database models and repository layer





  - [x] 2.1 Create User model with validation


    - Define User struct with all required fields (ID, Provider, ProviderID, Username, Email, etc.)
    - Implement user validation methods for required fields
    - Write unit tests for User model validation
    - _Requirements: 4.1, 4.2_

  - [x] 2.2 Create Session model


    - Define Session struct with ID, UserID, ExpiresAt, CreatedAt fields
    - Implement session validation and expiration checking methods
    - Write unit tests for Session model
    - _Requirements: 4.4_

  - [x] 2.3 Implement database connection and schema setup


    - Create database connection utilities with SQLite driver
    - Implement schema migration functions to create users and sessions tables
    - Add database initialization with proper indexes
    - Write tests for database connection and schema creation
    - _Requirements: 4.3_

  - [x] 2.4 Implement UserRepository with CRUD operations


    - Create UserRepository interface and SQLite implementation
    - Implement FindByProviderID, Create, and Update methods
    - Add proper error handling for database constraints
    - Write unit tests for all repository methods
    - _Requirements: 4.1, 4.2_

  - [x] 2.5 Implement SessionStore for session management


    - Create SessionStore interface and SQLite implementation
    - Implement Create, Get, Delete, and Cleanup methods for sessions
    - Add session expiration logic and cleanup routines
    - Write unit tests for session store operations
    - _Requirements: 4.4, 3.1, 3.3_

- [x] 3. Create OAuth2 authentication service



  - [x] 3.1 Implement OAuth2 configuration management


    - Create OAuth2Config struct for provider configurations
    - Implement configuration loading for Microsoft 365 and GitHub providers
    - Add validation for required OAuth2 settings
    - Write tests for configuration loading and validation
    - _Requirements: 1.2, 1.3_

  - [x] 3.2 Implement OAuth2 flow initiation



    - Create AuthService interface and implementation
    - Implement InitiateOAuth method to generate authorization URLs with state
    - Add CSRF protection using secure random state generation
    - Write unit tests for OAuth flow initiation
    - _Requirements: 1.1, 1.2, 1.3_

  - [x] 3.3 Implement OAuth2 callback handling


    - Implement HandleCallback method to process authorization codes
    - Add token exchange functionality for both Microsoft and GitHub
    - Implement user profile retrieval from OAuth providers
    - Write unit tests for callback handling and token exchange
    - _Requirements: 1.4, 1.5_

  - [x] 3.4 Implement session creation and validation






    - Add CreateSession method to generate secure session IDs
    - Implement ValidateSession method for session verification
    - Add DestroySession method for logout functionality
    - Write unit tests for session lifecycle management
    - _Requirements: 1.7, 2.4, 3.1_

- [x] 4. Create HTML templates with Go html/template



  - [x] 4.1 Create base template layout


    - Design base.html template with common HTML structure
    - Add CSS styling for responsive design
    - Implement template blocks for title, content, and scripts
    - Test template parsing and rendering
    - _Requirements: 5.2, 5.4_

  - [x] 4.2 Implement login page template


    - Create login.html template extending base layout
    - Add Microsoft 365 and GitHub login buttons with proper styling
    - Implement error message display functionality
    - Test template rendering with different data scenarios
    - _Requirements: 1.1, 5.1, 5.2_

  - [x] 4.3 Create dashboard template for authenticated users


    - Design dashboard.html template with user greeting
    - Display username prominently with "hello {username}" format
    - Add logout button with proper form submission
    - Test template with user data injection
    - _Requirements: 2.1, 2.2, 2.3, 5.3_

  - [x] 4.4 Implement template loading and caching system


    - Create template manager to parse and cache templates at startup
    - Implement template rendering helpers with error handling
    - Add template hot-reloading for development mode
    - Write tests for template loading and rendering
    - _Requirements: 5.4, 5.5_

- [x] 5. Implement Gin web server and routing






  - [x] 5.1 Set up basic Gin server with middleware

    - Initialize Gin router with recovery and logging middleware
    - Configure CORS and security headers middleware
    - Add session middleware for cookie handling
    - Write tests for middleware functionality
    - _Requirements: 5.1_

  - [x] 5.2 Implement authentication handlers


    - Create login page handler (GET /login)
    - Implement OAuth initiation handler (GET /auth/:provider)
    - Add OAuth callback handler (GET /auth/callback/:provider)
    - Write unit tests for authentication route handlers
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7_

  - [x] 5.3 Create protected route handlers


    - Implement dashboard handler with authentication middleware (GET /dashboard)
    - Add root redirect handler (GET /) to login or dashboard based on auth status
    - Create logout handler (POST /logout) with session cleanup
    - Write tests for protected routes and redirects
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.4_

  - [x] 5.4 Implement authentication middleware



    - Create middleware to check session validity on protected routes
    - Add automatic redirect to login for unauthenticated users
    - Implement user context injection for authenticated requests
    - Write tests for authentication middleware behavior
    - _Requirements: 2.4, 3.4_

- [x] 6. Add comprehensive error handling





  - [x] 6.1 Implement error response system


    - Create error types for different failure scenarios
    - Implement error handlers for authentication, database, and validation errors
    - Add user-friendly error pages and messages
    - Write tests for error handling scenarios
    - _Requirements: 5.4_

  - [x] 6.2 Add logging and monitoring



    - Implement structured logging for requests, errors, and authentication events
    - Add health check endpoint for monitoring
    - Create request/response logging middleware
    - Write tests for logging functionality
    - _Requirements: 5.4_

- [x] 7. Create integration tests




  - [x] 7.1 Implement end-to-end authentication flow tests


    - Write integration tests for complete OAuth flow with mock providers
    - Test session creation and validation across requests
    - Add tests for error scenarios and edge cases
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7_

  - [x] 7.2 Test protected route access and redirects


    - Create integration tests for dashboard access with and without authentication
    - Test logout functionality and session cleanup
    - Add tests for proper redirects and error handling
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.4_

- [x] 8. Finalize application configuration and startup





  - [x] 8.1 Implement application configuration validation



    - Add comprehensive configuration validation at startup
    - Create environment variable documentation and examples
    - Implement graceful error handling for missing configuration
    - Write tests for configuration loading and validation
    - _Requirements: 4.3_

  - [x] 8.2 Create main application entry point


    - Implement main.go with proper initialization sequence
    - Add graceful shutdown handling for database connections
    - Create startup logging and health checks
    - Wire all components together with dependency injection
    - _Requirements: 4.3, 5.5_