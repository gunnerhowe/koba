# Koba Deployment Guide

This guide covers deploying Koba to production environments.

## Prerequisites

- Docker 24+ and Docker Compose 2.20+
- PostgreSQL 15+ (managed service recommended)
- Hedera testnet/mainnet account (for blockchain anchoring)
- Domain with SSL certificate
- Reverse proxy (nginx, Traefik, or cloud load balancer)

## 1. Infrastructure Setup

### Database

Use a managed PostgreSQL service (AWS RDS, Google Cloud SQL, Azure Database) for production:

```bash
# Create database
CREATE DATABASE koba;
CREATE USER koba WITH ENCRYPTED PASSWORD 'your-strong-password';
GRANT ALL PRIVILEGES ON DATABASE koba TO koba;
```

### Hedera Setup

1. Create a Hedera account at https://portal.hedera.com
2. For testnet: Get free HBAR from faucet
3. For mainnet: Fund account with HBAR
4. Create a Consensus Service topic:

```bash
# Using Hedera SDK or HashScan
# Note the Topic ID (e.g., 0.0.12345)
```

## 2. Environment Configuration

Create production environment file:

```bash
# /opt/koba/.env

# Database
DATABASE_URL=postgresql://koba:password@db.example.com:5432/koba

# Security (generate secure random strings)
JWT_SECRET=$(openssl rand -hex 32)
SIGNING_KEY_PATH=/opt/koba/keys/signing_key.pem

# Hedera
HEDERA_OPERATOR_ID=0.0.12345
HEDERA_OPERATOR_KEY=302e020100300506032b6570...
HEDERA_TOPIC_ID=0.0.67890
HEDERA_NETWORK=mainnet

# Anchoring
ANCHOR_INTERVAL_MINUTES=60
ANCHOR_MIN_RECEIPTS=100

# Production settings
ENVIRONMENT=production
LOG_LEVEL=INFO
CORS_ORIGINS=https://app.yourdomain.com
```

## 3. Generate Signing Key

```bash
# Create keys directory
mkdir -p /opt/koba/keys

# Generate Ed25519 key pair
openssl genpkey -algorithm Ed25519 -out /opt/koba/keys/signing_key.pem

# Secure the key
chmod 600 /opt/koba/keys/signing_key.pem
```

## 4. Docker Deployment

### Production Docker Compose

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  api:
    image: your-registry/koba-api:latest
    restart: always
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - JWT_SECRET=${JWT_SECRET}
      - SIGNING_KEY_PATH=/app/keys/signing_key.pem
      - HEDERA_OPERATOR_ID=${HEDERA_OPERATOR_ID}
      - HEDERA_OPERATOR_KEY=${HEDERA_OPERATOR_KEY}
      - HEDERA_TOPIC_ID=${HEDERA_TOPIC_ID}
      - HEDERA_NETWORK=${HEDERA_NETWORK}
      - LOG_LEVEL=INFO
    volumes:
      - /opt/koba/keys:/app/keys:ro
    ports:
      - "127.0.0.1:8000:8000"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M

  dashboard:
    image: your-registry/koba-dashboard:latest
    restart: always
    environment:
      - NEXT_PUBLIC_API_URL=https://api.yourdomain.com
    ports:
      - "127.0.0.1:3000:3000"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Deploy

```bash
cd /opt/koba
docker-compose -f docker-compose.prod.yml pull
docker-compose -f docker-compose.prod.yml up -d
```

## 5. Database Migration

```bash
# Run migrations
docker-compose exec api python -m migrations.utils upgrade

# Verify
docker-compose exec api python -m migrations.utils health
```

## 6. Reverse Proxy Configuration

### Nginx Example

```nginx
# /etc/nginx/sites-available/koba

upstream koba_api {
    server 127.0.0.1:8000;
    keepalive 32;
}

upstream koba_dashboard {
    server 127.0.0.1:3000;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://koba_api;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_read_timeout 300s;
    }
}

server {
    listen 443 ssl http2;
    server_name app.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://koba_dashboard;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## 7. Create Admin User

```bash
# Connect to API container
docker-compose exec api python

# In Python shell
>>> from core.auth import AuthService, UserRole
>>> import asyncio
>>>
>>> async def create_admin():
...     auth = AuthService()
...     user = await auth.register(
...         email="admin@yourdomain.com",
...         username="admin",
...         password="secure-password-here",
...         role=UserRole.SUPER_ADMIN
...     )
...     print(f"Created admin user: {user.id}")
...
>>> asyncio.run(create_admin())
```

## 8. Monitoring

### Prometheus Metrics

Metrics are exposed at `/metrics`:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'koba'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: /metrics
```

### Key Metrics

- `koba_tool_requests_total` - Tool execution count by decision
- `koba_tool_latency_seconds` - Tool execution latency
- `koba_auth_requests_total` - Authentication requests
- `koba_blockchain_anchors_total` - Blockchain anchor count
- `koba_active_sessions` - Current active sessions

### Health Checks

```bash
# Basic health
curl https://api.yourdomain.com/health

# Detailed health (authenticated)
curl -H "Authorization: Bearer $TOKEN" \
  https://api.yourdomain.com/v1/health/detailed
```

## 9. Backup Strategy

### Database Backup

```bash
# Daily backup script
#!/bin/bash
DATE=$(date +%Y%m%d)
pg_dump -h db.example.com -U koba koba | gzip > /backups/koba_$DATE.sql.gz

# Upload to S3
aws s3 cp /backups/koba_$DATE.sql.gz s3://your-bucket/backups/

# Retain 30 days
find /backups -name "*.sql.gz" -mtime +30 -delete
```

### Key Backup

```bash
# Backup signing key (store securely!)
cp /opt/koba/keys/signing_key.pem /secure-backup/
```

## 10. Scaling

### Horizontal Scaling

Koba API is stateless and can be horizontally scaled:

```yaml
# docker-compose.prod.yml
services:
  api:
    deploy:
      replicas: 3
```

### Load Balancer Health Check

Configure your load balancer to use `/health` endpoint.

## 11. Security Hardening

### Network Security

- Run API on private network, expose only via reverse proxy
- Use VPC/private subnets for database
- Enable firewall rules (ufw, security groups)

### Application Security

- Enable rate limiting (configured in API)
- Use strong JWT secrets (32+ characters)
- Rotate signing keys periodically
- Monitor audit logs for anomalies

### Secrets Management

Use a secrets manager for production:

```bash
# AWS Secrets Manager example
aws secretsmanager create-secret \
  --name koba/production \
  --secret-string '{"JWT_SECRET":"...","HEDERA_OPERATOR_KEY":"..."}'
```

## 12. Troubleshooting

### Check Logs

```bash
# API logs
docker-compose logs -f api

# Database connection
docker-compose exec api python -c "from core.database import check_connection; check_connection()"
```

### Common Issues

1. **Database connection failed**
   - Check DATABASE_URL format
   - Verify network connectivity
   - Check PostgreSQL logs

2. **Blockchain anchoring not working**
   - Verify HEDERA_* environment variables
   - Check Hedera account balance
   - Review anchor scheduler logs

3. **JWT errors**
   - Ensure JWT_SECRET is consistent across restarts
   - Check token expiration settings

## 13. Updates

### Rolling Update

```bash
# Pull new images
docker-compose pull

# Update with zero downtime
docker-compose up -d --no-deps --scale api=2 api
sleep 30
docker-compose up -d --no-deps --scale api=1 api
```

### Database Migrations

Always backup before migrations:

```bash
pg_dump koba > backup_before_migration.sql
docker-compose exec api python -m migrations.utils upgrade
```

## Support

For production support:
- Documentation: https://docs.koba.ai
- Email: support@koba.ai
- Emergency: security@koba.ai
