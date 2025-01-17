# Auth Service
![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)
![Rust Version](https://img.shields.io/badge/rust-1.84.0%2B-orange.svg)
[![CI/CD](https://github.com/RocketArminek/auth-service-rust/actions/workflows/cd.yml/badge.svg)](https://github.com/RocketArminek/auth-service-rust/actions/workflows/cd.yml)
[![Performance Tests](https://github.com/RocketArminek/auth-service-rust/actions/workflows/performance-scheduled.yml/badge.svg)](https://github.com/RocketArminek/auth-service-rust/actions/workflows/performance-scheduled.yml)
[![Security Scan](https://github.com/RocketArminek/auth-service-rust/actions/workflows/security-scheduled.yml/badge.svg?branch=main)](https://github.com/RocketArminek/auth-service-rust/actions/workflows/security-scheduled.yml)

A high-performance, event-driven authentication and authorization service written in Rust. This service provides robust user management and secure authentication flows.

## Important Disclaimers

⚠️ **Please Read Before Using**

- This project is a validation of an idea for a small, low-footprint authentication service
- The future of this project is uncertain and depends on proving its usefulness in real-world scenarios
- This project was primarily created as a learning exercise for writing services in Rust
- **Use at your own risk** - while the code is tested and functional, it hasn't been battle-tested in production environments

## Features

- **Authentication & Authorization**
  - JWT-based authentication with access/refresh token pattern
  - Role-based access control (RBAC)
  - Configurable password hashing (Argon2, Bcrypt)
  - Email verification flow
  - Password reset capabilities

- **Technical Features**
  - Event-driven architecture using RabbitMQ
    - Currently only dispatches events (verification tokens, password reset tokens, etc.)
    - No integrated email delivery system - requires external service to consume events and send emails
  - Multi-database support (MySQL, SQLite)
  - OpenAPI/Swagger documentation
  - Docker & Docker Compose support
  - Comprehensive test suite (unit, integration, performance)

## Performance

The service demonstrates excellent performance characteristics:

- Average response time: 1.77ms
- P95 latency: 4.59ms
- Handles 150+ requests/second under load
- Successfully manages spikes up to 100 concurrent users
- Zero error rate under stress testing

## Prerequisites

- Rust 1.84.0 or higher
- MySQL 8.4+ or SQLite
- RabbitMQ 4.x (optional - for event-driven features)
- Docker & Docker Compose (optional)

## Quick Start

1. Clone the repository:
```bash
git clone git@github.com:RocketArminek/auth-service-rust.git
cd auth-service
```

2. Copy the example environment file:
```bash
cp .env.example .env
```

3. Start with Docker Compose:
```bash
docker-compose up -d
```

Or build and run locally:
```bash
cargo vendor
cargo build --release
./target/release/app start
```

## Configuration

### Environment Variables Reference

#### Server Configuration
```env
# Port for the service to listen on
PORT=8080 

# Host address to bind to
HOST=0.0.0.0

# Logging level (debug, info, warn, error)
LOG_LEVEL=info
```

#### Database Configuration
```env
# Full database connection URL
DATABASE_URL=mysql://root:toor@localhost:3306/auth_service_dev

# Database engine to use (mysql or sqlite)
DATABASE_ENGINE=mysql

# Maximum number of connections in the pool
DATABASE_MAX_CONNECTIONS=5

# Connection timeout in milliseconds
DATABASE_TIMEOUT_MS=500

# Individual database connection parameters (alternative to DATABASE_URL)
DATABASE_USER=root
DATABASE_PASSWORD=toor
DATABASE_HOST=localhost
DATABASE_PORT=3306
DATABASE_NAME=auth_service_dev

# SQLite specific configuration
SQLITE_PATH=./database.sqlite
```

#### Authentication Configuration
```env
# Auth strategy
# stateless -> all actions are performed based on decoded token. No session.
# stateful -> all actions are checking state in DB. There is also a session correlated with token.
AUTH_STRATEGY=stateless

# Password hashing scheme (bcrypt, bcrypt_low, argon2)
PASSWORD_HASHING_SCHEME=bcrypt_low

# JWT secret key for token signing
SECRET=your-secret-key

# Access token duration in seconds (default: 5 minutes)
AT_DURATION_IN_SECONDS=300

# Refresh token duration in seconds (default: 30 days)
# In stateful strategy this is used for duration of session
RT_DURATION_IN_SECONDS=2592000

# Whether email verification is required
VERIFICATION_REQUIRED=true

# Verification token duration in seconds (default: 30 days)
VR_DURATION_IN_SECONDS=2592000

# Reset password token duration in seconds (default: 30 days)
RP_DURATION_IN_SECONDS=2592000
```

#### Role Configuration
```env
# Default role for new users
REGULAR_ROLE_NAME=USER

# Restricted role prefix (roles starting with this are considered admin roles)
RESTRICTED_ROLE_NAME=ADMIN

# Super admin credentials
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=Admin#123*
```

#### RabbitMQ Configuration
```env
# RabbitMQ connection URL
RABBITMQ_URL=amqp://localhost:5672

# Exchange name for events
RABBITMQ_EXCHANGE_NAME=auth.events

# Exchange type (fanout, direct, topic, headers)
RABBITMQ_EXCHANGE_KIND=fanout

# Exchange durability
RABBITMQ_EXCHANGE_DURABLE=true

# Exchange auto-delete setting
RABBITMQ_EXCHANGE_AUTO_DELETE=false

# Enable/disable event-driven features
EVENT_DRIVEN=true
```

## API Documentation

The API documentation is available at `/docs` when the service is running. Key endpoints include:

- `POST /v1/users` - Create new user
- `POST /v1/stateless/login` - User login
- `GET /v1/stateless/authenticate` - Verify authentication
- `POST /v1/stateless/refresh` - Refresh access token
- `GET /v1/restricted/users` - List users (admin only)

## CLI Commands

The service includes several CLI commands for management:

```bash
# Create a new user
app create-user --email user@example.com --password "Pass#word1" --role USER

# Create admin role
app create-role --name ADMIN

# Health check
app health-check

# Start server
app start
```

### Testing Strategy

The project employs a comprehensive testing approach:

1. **Unit Tests**
   - Test individual components in isolation
   - Mock external dependencies
   - Focus on business logic validation

2. **Integration Tests**
   - Test component interactions
   - Use test databases
   - Verify repository implementations

3. **Acceptance Tests**
   - End-to-end scenarios
   - Test complete user workflows
   - Verify business requirements

4. **Performance Tests**
   - Load testing with K6
   - Test different load patterns
   - Measure response times and throughput
   - Verify system behavior under stress

5. **OWASP ZAP Security Scanning**
   - Performing zap full scan (check github action artifacts to read reports)

## Running Tests

```bash
# Run tests
cargo test

# Run performance tests
k6 run tests/performance/auth_flow.js
```

## Production Deployment

For production deployment, consider:

1. Using a reverse proxy (e.g., Traefik, Nginx)
2. Setting up proper SSL/TLS
3. Configuring appropriate database connection pools
4. Setting up monitoring and logging
5. Using proper secrets management

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

This project follows the [Conventional Commits](https://www.conventionalcommits.org/) specification for commit messages

Types:
- `feat`: New feature
- `fix`: Bug fix
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `test`: Adding missing tests or correcting existing tests
- `docs`: Documentation only changes
- `chore`: Changes to the build process or auxiliary tools
- `perf`: Performance improvements
- `style`: Code style changes (formatting, missing semi-colons, etc)


## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Axum](https://github.com/tokio-rs/axum)
- Database support via [SQLx](https://github.com/launchbadge/sqlx)
- Documentation using [Utoipa](https://github.com/juhaku/utoipa)
- Message queue support via [Lapin](https://github.com/CleverCloud/lapin)

## Support

For support, please open an issue in the GitHub repository.
