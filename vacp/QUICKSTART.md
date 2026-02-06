# VACP Quickstart Guide

Get up and running with VACP in 5 minutes.

## Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

## Installation

```bash
# Clone the repository
git clone https://github.com/vacp/vacp.git
cd vacp

# Install in development mode with all dependencies
pip install -e ".[all]"
```

## Quick Start

### 1. Configure Environment

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` with your settings. Minimum required:

```bash
# For development (auto-generates a secret)
JWT_SECRET=

# For production (REQUIRED - generate with command below)
# python -c "import secrets; print(secrets.token_hex(32))"
JWT_SECRET=your-secret-here-at-least-32-chars
```

### 2. Start the Server

```bash
# Development mode (with demo data)
python -m vacp.api.server --demo

# Production mode
ENVIRONMENT=production python -m vacp.api.server
```

The server runs at `http://localhost:8000` by default.

### 3. Use the CLI

```bash
# Check server health
vacp-cli status

# Login (default demo credentials: admin / admin)
vacp-cli auth login --username admin --password admin

# List policies
vacp-cli policy list
```

## Common Pitfalls

### JWT_SECRET Error in Production

**Problem**: Server fails to start with "JWT_SECRET environment variable is required"

**Solution**: Set a strong JWT secret:
```bash
# Generate a secure secret
python -c "import secrets; print(secrets.token_hex(32))"

# Add to .env or environment
export JWT_SECRET=<generated-secret>
```

### Database Connection Issues

**Problem**: "Unable to connect to database" or SQLite errors

**Solution**: Check your DATABASE_URL:
```bash
# SQLite (development)
DATABASE_URL=sqlite:///./vacp.db

# PostgreSQL (production)
DATABASE_URL=postgresql://user:pass@host:5432/vacp
```

### Missing Dependencies

**Problem**: ImportError for FastAPI, uvicorn, or other packages

**Solution**: Install the full package:
```bash
pip install -e ".[all]"

# Or install specific extras
pip install -e ".[server,cli,dev]"
```

### API Authentication Failed

**Problem**: 401 Unauthorized on API requests

**Solutions**:
1. Login first: `vacp-cli auth login`
2. Check token expiry: `vacp-cli auth status`
3. Refresh token: `vacp-cli auth refresh`

### Kill Switch Commands Not Working

**Problem**: `vacp-cli killswitch sign` fails

**Solution**: You need a valid Ed25519 private key file:
```bash
# Generate a keypair
vacp-cli crypto keygen --output my-key

# Sign with the key
vacp-cli killswitch sign --key my-key.priv --key-id your-id
```

### Tests Failing

**Problem**: pytest tests are failing

**Solutions**:
1. Install dev dependencies: `pip install -e ".[dev]"`
2. Run from project root: `cd vacp && pytest`
3. Check for missing .env: `cp .env.example .env`

## Development Workflow

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=vacp --cov-report=html

# Run specific test file
pytest tests/test_gateway.py

# Run tests matching pattern
pytest -k "policy"
```

### Type Checking

```bash
# Run mypy
mypy core/ api/ providers/
```

### Code Quality

```bash
# Security scan
bandit -r vacp/

# Dependency vulnerabilities
safety check
```

## Architecture Overview

```
vacp/
├── api/          # FastAPI HTTP server
├── cli/          # Command-line interface
├── core/         # Core logic (gateway, policy, receipts)
├── providers/    # AI provider integrations (OpenAI, Anthropic)
├── security/     # Input sanitization, injection detection
└── tests/        # Test suite
```

### Key Components

- **Gateway**: Central entry point for tool execution
- **Policy Engine**: Evaluates policies against tool calls
- **Receipt Service**: Creates cryptographic receipts for actions
- **Kill Switch**: Emergency shutdown mechanism
- **Providers**: AI provider integrations with interception

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/v1/auth/login` | POST | Authenticate |
| `/v1/execute` | POST | Execute a tool |
| `/v1/policies` | GET/POST | Manage policies |
| `/v1/receipts/{id}` | GET | Get receipt |
| `/v1/receipts/{id}/verify` | POST | Verify receipt |

## Getting Help

- **Documentation**: Check the `/docs` folder
- **API Docs**: Visit `http://localhost:8000/docs` when server is running
- **Issues**: [GitHub Issues](https://github.com/vacp/vacp/issues)

## Next Steps

1. Read the [full documentation](docs/README.md)
2. Explore the [API reference](http://localhost:8000/docs)
3. Check out [example integrations](examples/)
4. Review [security best practices](docs/security.md)
