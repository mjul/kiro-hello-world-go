# SSO Web App

A secure Single Sign-On (SSO) web application built with Go and Gin framework, supporting authentication via Microsoft 365 and GitHub OAuth2 providers.

## Features

- 🔐 **Secure OAuth2 Authentication** with Microsoft 365 and GitHub
- 🎨 **Modern Web Interface** with responsive design and HTML templates
- 🛡️ **Session Management** with secure HTTP-only cookies
- 🗄️ **SQLite Database** with automatic migrations
- 🔒 **CSRF Protection** for OAuth2 flows
- 📱 **Mobile-Friendly** responsive design
- ⚡ **Fast & Lightweight** built with Go and Gin framework
- 🧪 **Comprehensive Testing** with unit and integration tests

## Quick Start

### Prerequisites

- Go 1.24.5 or later
- Git
- GCC compiler (required for CGO and SQLite integration)
  - **Windows**: Install [TDM-GCC](https://jmeubank.github.io/tdm-gcc/) or [MinGW-w64](https://www.mingw-w64.org/)
  - **macOS**: Install Xcode Command Line Tools (`xcode-select --install`)
  - **Linux**: Install build-essential (`sudo apt-get install build-essential` on Ubuntu/Debian)

### 1. Clone the Repository

```bash
git clone <repository-url>
cd sso-web-app
```

### 2. Set Up Environment Variables

Copy the example environment file and configure your OAuth2 credentials:

```bash
cp .env.example .env
```

Edit `.env` with your OAuth2 application credentials:

```env
# Database
DATABASE_URL=sqlite:sso_app.db

# Microsoft OAuth2 (Azure AD)
MICROSOFT_CLIENT_ID=your_microsoft_client_id
MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret

# GitHub OAuth2
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# Session Security
SESSION_SECRET=your_random_session_secret_key_here

# Application
BASE_URL=http://localhost:3000
```

### 3. Initialize Database (Optional)

Run the initialization script to set up your environment:

**On Windows (PowerShell):**
```powershell
.\scripts\init_db.ps1
```

**On Linux/macOS:**
```bash
./scripts/init_db.sh
```

### 4. Run the Application

**Development mode:**
```bash
# CGO is enabled by default for go run
go run .
```

**With debug logging:**
```bash
# Set log level for more verbose output
LOG_LEVEL=debug go run .
```

**Production build:**
```bash
# Build the binary with CGO enabled (required for SQLite)
CGO_ENABLED=1 go build -o sso-web-app .

# Run the binary
./sso-web-app
```

The application will be available at `http://localhost:3000`

## OAuth2 Setup

### Microsoft 365 / Azure AD

1. Go to [Azure Portal](https://portal.azure.com/)
2. Navigate to **Azure Active Directory** > **App registrations**
3. Click **New registration**
4. Configure:
   - **Name**: SSO Web App
   - **Redirect URI**: `http://localhost:3000/auth/callback/microsoft`
   - **Account types**: Accounts in any organizational directory and personal Microsoft accounts
5. Copy the **Application (client) ID** to `MICROSOFT_CLIENT_ID`
6. Go to **Certificates & secrets** > **New client secret**
7. Copy the secret value to `MICROSOFT_CLIENT_SECRET`

### GitHub OAuth App

1. Go to [GitHub Settings](https://github.com/settings/developers)
2. Click **OAuth Apps** > **New OAuth App**
3. Configure:
   - **Application name**: SSO Web App
   - **Homepage URL**: `http://localhost:3000`
   - **Authorization callback URL**: `http://localhost:3000/auth/callback/github`
4. Copy the **Client ID** to `GITHUB_CLIENT_ID`
5. Generate a **Client Secret** and copy to `GITHUB_CLIENT_SECRET`

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `DATABASE_URL` | SQLite database file path | No | `sqlite:sso_app.db` |
| `MICROSOFT_CLIENT_ID` | Microsoft OAuth2 client ID | Yes | - |
| `MICROSOFT_CLIENT_SECRET` | Microsoft OAuth2 client secret | Yes | - |
| `GITHUB_CLIENT_ID` | GitHub OAuth2 client ID | Yes | - |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth2 client secret | Yes | - |
| `SESSION_SECRET` | Secret key for session encryption | Yes | - |
| `BASE_URL` | Application base URL for OAuth2 callbacks | No | `http://localhost:3000` |

### Session Secret Generation

Generate a secure session secret:

```bash
# Using OpenSSL
openssl rand -base64 32

# Using Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Using Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

## Development

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run specific package tests
go test ./handlers
go test ./models
go test ./services

# Run integration tests
go test -tags=integration ./...

# Run tests with coverage
go test -cover ./...
```

### Database Management

The application automatically creates and migrates the SQLite database on startup. To reset the database:

```bash
rm sso_app.db
go run .  # Will recreate and migrate
```

### Logging

The application uses Go's built-in log package. You can control logging by setting environment variables or modifying the log level in the code:

```bash
# Run with debug logging
LOG_LEVEL=debug go run .

# Run with info level logging
LOG_LEVEL=info go run .

# Run with minimal logging
LOG_LEVEL=error go run .
```

## Production Deployment

### Building for Production

```bash
# Build optimized release binary with CGO enabled (required for SQLite)
CGO_ENABLED=1 go build -ldflags="-s -w" -o sso-web-app .

# The binary will be at ./sso-web-app
```

**Note**: CGO is required for SQLite integration. Ensure GCC is installed in your build environment.

### Production Configuration

1. **Use HTTPS**: Update `BASE_URL` to use `https://`
2. **Secure Session Secret**: Use a strong, randomly generated secret
3. **Database**: Consider using a persistent volume for SQLite file
4. **Logging**: Set `LOG_LEVEL=info` or `LOG_LEVEL=warn`
5. **OAuth2 Redirects**: Update OAuth2 app configurations with production URLs

### Docker Deployment

Create a `Dockerfile`:

```dockerfile
FROM golang:1.24-alpine as builder

# Install GCC and other build dependencies required for CGO
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build with CGO enabled (required for SQLite)
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o sso-web-app .

FROM alpine:latest
RUN apk --no-cache add ca-certificates sqlite
WORKDIR /root/
COPY --from=builder /app/sso-web-app .
COPY --from=builder /app/templates ./templates
EXPOSE 3000
CMD ["./sso-web-app"]
```

Build and run:

```bash
docker build -t sso-web-app .
docker run -p 3000:3000 --env-file .env sso-web-app
```

### Reverse Proxy (Nginx)

Example Nginx configuration:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## API Endpoints

| Method | Path | Description | Authentication |
|--------|------|-------------|----------------|
| `GET` | `/` | Root - redirects based on auth status | Optional |
| `GET` | `/login` | Login page with OAuth2 buttons | None |
| `GET` | `/auth/microsoft` | Initiate Microsoft OAuth2 flow | None |
| `GET` | `/auth/github` | Initiate GitHub OAuth2 flow | None |
| `GET` | `/auth/callback/microsoft` | Microsoft OAuth2 callback | None |
| `GET` | `/auth/callback/github` | GitHub OAuth2 callback | None |
| `GET` | `/dashboard` | User dashboard | Required |
| `POST` | `/logout` | Logout and clear session | Required |

## Security Features

- **OAuth2 CSRF Protection**: State parameter validation
- **Secure Session Cookies**: HttpOnly, SameSite=Lax
- **SQL Injection Prevention**: Parameterized queries with database/sql
- **XSS Prevention**: Template escaping with html/template
- **Session Management**: Secure session storage and cleanup
- **Error Handling**: No sensitive information leakage

## Troubleshooting

### Common Issues

**"Configuration error" on startup**
- Check that all required environment variables are set
- Verify OAuth2 credentials are correct

**"Database error" during startup**
- Ensure the application has write permissions to the database directory
- Check disk space availability

**OAuth2 redirect errors**
- Verify redirect URIs match exactly in OAuth2 app configurations
- Check that `BASE_URL` is correctly set

**Session issues**
- Ensure `SESSION_SECRET` is set and consistent across restarts
- Check that cookies are enabled in the browser

**CGO/Build errors**
- Ensure GCC is installed and available in PATH
- On Windows, verify TDM-GCC or MinGW-w64 is properly installed
- For Docker builds, ensure build dependencies are installed in the container
- If getting "CGO_ENABLED=0" errors, explicitly set `CGO_ENABLED=1`

### Debug Mode

Run with debug logging to troubleshoot issues:

```bash
LOG_LEVEL=debug go run .
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Run tests: `go test ./...`
5. Commit your changes: `git commit -am 'Add feature'`
6. Push to the branch: `git push origin feature-name`
7. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Architecture

### Technology Stack

- **Backend**: Go with Gin web framework
- **Database**: SQLite with database/sql and go-sqlite3 driver (CGO-enabled for full SQLite features)
- **Templates**: Go html/template package
- **Authentication**: OAuth2 with Microsoft Graph API and GitHub API
- **Session Management**: Custom session store with SQLite backend
- **Testing**: Built-in Go testing with testify assertions

### SQLite Integration Benefits

This application uses the full SQLite driver (`github.com/mattn/go-sqlite3`) with CGO enabled, providing:

- **Full SQLite Feature Set**: Access to all SQLite functions and extensions
- **Better Performance**: Native C implementation for optimal speed
- **Foreign Key Support**: Proper relational database constraints
- **Advanced SQL Features**: Window functions, CTEs, and full-text search
- **Reliability**: Production-ready SQLite with all safety features enabled

### Project Structure

```
sso-web-app/
├── config/                  # Configuration management
│   ├── config.go           # Configuration loading and validation
│   └── config_test.go      # Configuration tests
├── database/               # Database layer
│   ├── database.go         # Database initialization
│   ├── session_store.go    # Session storage implementation
│   ├── user_repository.go  # User data access layer
│   └── *_test.go          # Database tests
├── handlers/               # HTTP handlers and middleware
│   ├── server.go           # Main server setup and routing
│   ├── errors.go           # Error handling middleware
│   ├── logging.go          # Logging middleware
│   ├── templates.go        # Template rendering
│   └── *_test.go          # Handler tests
├── models/                 # Data models
│   ├── user.go            # User model
│   ├── session.go         # Session model
│   └── *_test.go          # Model tests
├── services/               # Business logic layer
│   ├── auth_service.go     # Authentication service
│   ├── oauth_config.go     # OAuth2 configuration
│   └── *_test.go          # Service tests
├── templates/              # HTML templates
│   ├── base.html          # Base template layout
│   ├── login.html         # Login page
│   ├── dashboard.html     # User dashboard
│   └── error.html         # Error page
├── main.go                # Application entry point
├── go.mod                 # Go module dependencies
├── go.sum                 # Go module checksums
├── .env.example          # Environment variables template
├── integration_test.go   # Integration tests
└── README.md             # This file
```