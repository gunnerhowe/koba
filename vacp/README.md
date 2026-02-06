# Koba - Verified AI Control Protocol

Production-ready AI governance platform with cryptographic audit trails and blockchain anchoring.

## Features

- **Policy Engine** - Default-deny policy enforcement for AI tool access
- **Signed Action Receipts** - Ed25519 signed proof of every AI action
- **Merkle Transparency Log** - Append-only log with cryptographic inclusion proofs
- **Blockchain Anchoring** - Periodic anchoring to Hedera for tamper-evident timestamps
- **Multi-Tenancy** - Complete tenant isolation with API key authentication
- **Multi-Party Kill Switch** - Emergency containment requiring multiple approvals
- **Cognitive Tripwires** - Anomaly detection for unusual AI behavior
- **JIT Token Minting** - Just-in-time capability tokens with fine-grained permissions

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 15+ (or SQLite for development)
- Node.js 18+ (for dashboard)

### Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/koba.git
cd koba/vacp

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration

# Run database migrations
python -m migrations.utils init

# Start the server
python -m api.server
```

### Docker Setup

```bash
cd docker

# Development
docker-compose up -d

# Production
docker-compose -f docker-compose.prod.yml up -d
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `sqlite:///./koba.db` |
| `JWT_SECRET` | Secret key for JWT tokens | Required |
| `SIGNING_KEY_PATH` | Path to Ed25519 private key | Auto-generated |
| `HEDERA_OPERATOR_ID` | Hedera account ID | - |
| `HEDERA_OPERATOR_KEY` | Hedera private key | - |
| `HEDERA_TOPIC_ID` | Hedera Consensus Service topic | - |
| `HEDERA_NETWORK` | `mainnet` or `testnet` | `testnet` |
| `HEDERA_SIMULATE` | Simulate blockchain (dev mode) | `false` |
| `ANCHOR_INTERVAL_MINUTES` | Blockchain anchor frequency | `60` |
| `ANCHOR_MIN_RECEIPTS` | Min receipts before anchoring | `100` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `CORS_ORIGINS` | Allowed CORS origins | `*` |

### Example `.env`

```bash
# Database
DATABASE_URL=postgresql://koba:password@localhost:5432/koba

# Security
JWT_SECRET=your-super-secret-jwt-key-at-least-32-chars

# Hedera (optional for production blockchain anchoring)
HEDERA_OPERATOR_ID=0.0.12345
HEDERA_OPERATOR_KEY=302e020100300506032b6570...
HEDERA_TOPIC_ID=0.0.67890
HEDERA_NETWORK=testnet

# Anchoring
ANCHOR_INTERVAL_MINUTES=60
ANCHOR_MIN_RECEIPTS=100

# Development
HEDERA_SIMULATE=true
LOG_LEVEL=DEBUG
```

## API Overview

### Authentication

```bash
# Login
POST /v1/auth/login
{
  "email": "admin@example.com",
  "password": "password"
}

# Returns JWT tokens
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "user": { ... }
}

# Use token in requests
Authorization: Bearer <access_token>
```

### Tool Execution

```bash
# Execute a tool through the gateway
POST /v1/tools/execute
{
  "tool_id": "file_read",
  "parameters": {
    "path": "/tmp/data.txt"
  },
  "context": {
    "session_id": "sess_123"
  }
}

# Response includes signed receipt
{
  "decision": "allow",
  "receipt": {
    "id": "rcpt_...",
    "signature": "...",
    "log_index": 42
  }
}
```

### Audit Trail

```bash
# Get all receipts
GET /v1/receipts

# Get inclusion proof
GET /v1/receipts/{id}/proof

# Verify a receipt
POST /v1/verify
{
  "receipt": { ... },
  "proof": { ... }
}
```

### Blockchain Anchors

```bash
# List anchors
GET /v1/audit/anchors

# Verify anchor on-chain
GET /v1/audit/anchors/{id}/verify
```

### Tenant Management (System Admin)

```bash
# Create tenant
POST /v1/admin/tenants
{
  "name": "Acme Corp",
  "slug": "acme",
  "plan": "business"
}

# List tenants
GET /v1/admin/tenants

# Suspend tenant
POST /v1/admin/tenants/{id}/suspend
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         AI Application                          │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Koba Gateway                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   Policy    │  │  Tripwires  │  │    JIT Token Minter     │  │
│  │   Engine    │  │             │  │                         │  │
│  └──────┬──────┘  └──────┬──────┘  └────────────┬────────────┘  │
│         │                │                      │               │
│         ▼                ▼                      ▼               │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                   Action Receipt Signer                     ││
│  │                      (Ed25519)                              ││
│  └──────────────────────────┬──────────────────────────────────┘│
└─────────────────────────────┼───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Merkle Transparency Log                      │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐                   │
│  │ R₀   │ │ R₁   │ │ R₂   │ │ R₃   │ │ ...  │  Receipts        │
│  └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └──────┘                   │
│     │        │        │        │                                │
│     └───┬────┘        └───┬────┘                                │
│         ▼                 ▼                                     │
│     ┌──────┐          ┌──────┐                                  │
│     │ H₀₁  │          │ H₂₃  │    Merkle Tree                   │
│     └──┬───┘          └──┬───┘                                  │
│        └───────┬─────────┘                                      │
│                ▼                                                │
│           ┌────────┐                                            │
│           │ Root   │  Signed Tree Head                          │
│           └────────┘                                            │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Blockchain Anchor                            │
│                (Hedera Consensus Service)                       │
│                                                                 │
│    Topic: 0.0.xxxxx  │  Sequence: 123  │  Timestamp: ...        │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
vacp/
├── api/
│   ├── server.py       # FastAPI application
│   └── models.py       # API request/response models
├── core/
│   ├── auth.py         # Authentication & authorization
│   ├── blockchain.py   # Hedera integration
│   ├── containment.py  # Multi-party kill switch
│   ├── database.py     # SQLAlchemy models
│   ├── gateway.py      # Tool execution gateway
│   ├── merkle.py       # Merkle transparency log
│   ├── policy.py       # Policy engine
│   ├── receipts.py     # Signed action receipts
│   ├── tenant.py       # Multi-tenancy service
│   ├── tokens.py       # JIT token minting
│   └── tripwire.py     # Cognitive tripwires
├── monitoring/
│   ├── health.py       # Health checks
│   ├── logging.py      # Structured logging
│   └── metrics.py      # Prometheus metrics
├── migrations/
│   ├── env.py          # Alembic environment
│   └── versions/       # Database migrations
├── tests/
│   ├── unit/           # Unit tests
│   └── integration/    # Integration tests
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── docker-compose.prod.yml
└── requirements.txt
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=vacp --cov-report=html

# Run specific test file
pytest tests/unit/test_tenant.py -v
```

## Dashboard

The Next.js dashboard provides a web UI for:

- Viewing and searching action receipts
- Verifying inclusion proofs
- Managing policies and tools
- Viewing blockchain anchors
- Managing tenants (system admin)
- Emergency containment controls

```bash
cd vacp-dashboard
npm install
npm run dev
```

## Security Considerations

1. **Key Management** - Store signing keys securely (HSM recommended for production)
2. **Database Encryption** - Enable encryption at rest for PostgreSQL
3. **Network Security** - Use TLS for all API traffic
4. **Secrets** - Never commit `.env` files; use secrets management
5. **Audit Logs** - Monitor audit entries for suspicious activity

## License

MIT License - See LICENSE file for details.

## Support

- Documentation: https://docs.koba.ai
- Issues: https://github.com/your-org/koba/issues
- Email: support@koba.ai
