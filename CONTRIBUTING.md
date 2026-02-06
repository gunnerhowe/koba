# Contributing to Koba

Thank you for your interest in contributing to Koba! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Bugs

- Use the [Bug Report](https://github.com/gunnerhowe/koba/issues/new?template=bug_report.md) issue template
- Include steps to reproduce, expected behavior, and actual behavior
- Include your environment details (OS, Python version, Node.js version)

### Suggesting Features

- Use the [Feature Request](https://github.com/gunnerhowe/koba/issues/new?template=feature_request.md) issue template
- Describe the problem your feature would solve
- Explain your proposed solution

### Pull Requests

1. Fork the repository
2. Create a feature branch from `main`: `git checkout -b feature/my-feature`
3. Make your changes
4. Write or update tests as needed
5. Ensure all tests pass (see below)
6. Commit with a clear message
7. Push to your fork and open a PR

## Development Setup

### Backend (Python)

```bash
git clone https://github.com/gunnerhowe/koba.git
cd koba

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install backend with dev dependencies
cd vacp
pip install -e ".[all]"

# Copy environment config
cp .env.example .env

# Run tests
pytest

# Run linting
ruff check src/
mypy src/vacp/
```

### Dashboard (Next.js)

```bash
cd vacp-dashboard
npm install
npm run dev
```

### Desktop App (Electron)

```bash
cd desktop-app
npm install
npm start
```

## Testing Requirements

- All new backend code must include tests
- Run `pytest` from the `vacp/` directory before submitting
- Maintain or improve test coverage
- For security-sensitive code, add adversarial tests in `src/vacp/tests/adversarial/`

## Code Style

**Python:**
- [ruff](https://github.com/astral-sh/ruff) for linting
- [mypy](https://mypy-lang.org/) for type checking
- Follow PEP 8 conventions
- Use type hints for function signatures

**TypeScript/JavaScript:**
- Follow existing Next.js/React patterns in the dashboard
- Use TypeScript strict mode for new code

## Commit Messages

- Use clear, descriptive commit messages
- Start with a verb in imperative mood: "Add feature", "Fix bug", "Update docs"
- Reference related issues: "Fix #123"

## Security

If you discover a security vulnerability, **do NOT open a public issue**. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Project Structure

```
koba/
├── vacp/                   # Backend (Python/FastAPI)
│   ├── src/vacp/           # Main package
│   │   ├── api/            # HTTP API endpoints
│   │   ├── auth/           # Authentication
│   │   ├── core/           # Core engine (policy, gateway, receipts, merkle)
│   │   ├── security/       # Security utilities
│   │   ├── storage/        # Database layer
│   │   └── tests/          # Test suite
│   └── pyproject.toml      # Python package config
├── vacp-dashboard/         # Dashboard UI (Next.js/React)
│   └── src/
│       ├── app/            # Next.js app router pages
│       ├── components/     # Reusable React components
│       └── lib/            # Utilities and API client
├── desktop-app/            # Desktop wrapper (Electron)
└── docker-compose.yml      # Docker orchestration
```

## License

By contributing to Koba, you agree that your contributions will be licensed under the [MIT License](LICENSE).
