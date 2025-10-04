# Auth Service
![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)
![Rust Version](https://img.shields.io/badge/rust-1.84.0%2B-orange.svg)
[![CI](https://github.com/RocketArminek/auth-service-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/RocketArminek/auth-service-rust/actions/workflows/ci.yml)

A high-performance, event-driven authentication and authorization middleware for your load balancer written in Rust. This service provides robust user management and secure authentication flows.

## Important Disclaimers

⚠️ **Please Read Before Using**

- This project was primarily created as a learning exercise
- The future of this project is uncertain and depends on proving its usefulness in real-world scenarios
- **Use at your own risk** - while the code is tested and functional, it hasn't been battle-tested in production environments

## Features

- **Authentication & Authorization**
  - JWT-based authentication with access/refresh token pattern
  - Roles management
  - Permission management
  - Configurable password hashing (Argon2, Bcrypt)
  - Password reset capabilities

- **Technical Features**
  - Event-driven architecture using RabbitMQ
    - Currently only dispatches events (verification tokens, password reset tokens, etc.)
    - No integrated email delivery system - requires external service to consume events and send emails
  - Multi-database support (MySQL, SQLite)
  - OpenAPI/Swagger documentation
  - Docker & Docker Compose support
  - Comprehensive test suite (unit, integration, performance)

## Prerequisites

- Rust 1.84.0 or higher
- MySQL 8.4+ or SQLite
- RabbitMQ 4.x (optional - for event-driven features)
- Docker & Docker Compose (optional)

## Examples

### Basic Example
The repository includes a basic example demonstrating integration with a web application using Traefik as a reverse proxy. The example showcases:

- User registration and authentication
- Role-based access control
- Forward authentication with Traefik
- Event-driven architecture

To run the basic example:

1. Navigate to the example directory:

```bash
cd examples/basic
```
2. Start the example with Docker Compose:

```bash
docker compose up -d --build
```

Take a look at the [example README](examples/basic/README.md) for more details.

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

# Maximum number of connections in the pool
DATABASE_MAX_CONNECTIONS=5

# Connection timeout in milliseconds
DATABASE_TIMEOUT_MS=500

# Individual database connection parameters (alternative to DATABASE_URL)

# Database engine to use (mysql or sqlite)
# If not provided the engine will be choosen based on DATABASE_URL
DATABASE_ENGINE=mysql

# Mysql specific configuration
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
# Password hashing scheme (bcrypt, bcrypt_low, argon2)
# Be mindful this hits the performance of the service
PASSWORD_HASHING_SCHEME=bcrypt_low

# JWT secret key for token signing
SECRET=your-secret-key

# Access token duration in seconds (default: 5 minutes)
AT_DURATION_IN_SECONDS=300

# Refresh token duration in seconds (default: 30 days)
# In stateful strategy this is also used for duration of session
RT_DURATION_IN_SECONDS=2592000

# Whether email verification is required
VERIFICATION_REQUIRED=true

# Verification token duration in seconds (default: 30 days)
VR_DURATION_IN_SECONDS=2592000

# Reset password token duration in seconds (default: 30 days)
RP_DURATION_IN_SECONDS=2592000

# Interval in minutes for cleanup tasks (e.g., expired sessions -> default: 5 minutes)
CLEANUP_INTERVAL_IN_MINUTES=5
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
MESSAGE_PUBLISHER_ENGINE=rabbitmq
```

## API Documentation

The API documentation is available at `/docs` when the service is running.
There is also json version of open api schema at `/`

## CLI Commands

The service includes several CLI commands for management:

```bash
# View help with list of all commands
app help
```

## Running Tests

```bash
# Run tests
cargo test

# Run performance tests
k6 run tests/performance/auth_flow.js
```

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Axum](https://github.com/tokio-rs/axum)
- Database support via [SQLx](https://github.com/launchbadge/sqlx)
- Documentation using [Utoipa](https://github.com/juhaku/utoipa)
- Message queue support via [Lapin](https://github.com/CleverCloud/lapin)

## Support

For support, please open an issue in the GitHub repository.
