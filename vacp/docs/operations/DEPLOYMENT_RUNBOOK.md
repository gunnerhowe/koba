# VACP Deployment Runbook

Production deployment guide with real commands for deploying, managing, and troubleshooting VACP (Verified AI Communication Protocol).

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Initial Setup](#initial-setup)
3. [Database Setup](#database-setup)
4. [Secrets Management](#secrets-management)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Monitoring Setup](#monitoring-setup)
7. [Backup Configuration](#backup-configuration)
8. [Health Checks](#health-checks)
9. [Troubleshooting](#troubleshooting)
10. [Emergency Procedures](#emergency-procedures)

---

## Prerequisites

### Required Tools

```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Install PostgreSQL client
sudo apt-get install postgresql-client

# Install Vault CLI
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install vault
```

### Environment Setup

```bash
# Set environment variables
export VACP_NAMESPACE="vacp"
export VACP_RELEASE="vacp-prod"
export KUBECONFIG="/path/to/kubeconfig"

# Verify cluster access
kubectl cluster-info
kubectl get nodes
```

---

## Initial Setup

### 1. Create Namespace

```bash
# Create namespace with labels
kubectl create namespace ${VACP_NAMESPACE}

# Add labels for network policies
kubectl label namespace ${VACP_NAMESPACE} \
  app.kubernetes.io/name=vacp \
  environment=production

# Enable pod security standards
kubectl label namespace ${VACP_NAMESPACE} \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

### 2. Generate Encryption Keys

```bash
# Generate master encryption key (32 bytes)
MASTER_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "Master Key: $MASTER_KEY"

# Generate API key
API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
echo "API Key: $API_KEY"

# Generate backup encryption key
BACKUP_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "Backup Key: $BACKUP_KEY"

# IMPORTANT: Store these keys securely in your secrets manager
```

### 3. Create TLS Certificates

```bash
# Option 1: Using cert-manager (recommended)
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: vacp-tls
  namespace: ${VACP_NAMESPACE}
spec:
  secretName: vacp-tls-cert
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - vacp.example.com
    - api.vacp.example.com
EOF

# Option 2: Manual certificate creation
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout tls.key -out tls.crt \
  -subj "/CN=vacp.example.com"

kubectl create secret tls vacp-tls \
  --cert=tls.crt --key=tls.key \
  -n ${VACP_NAMESPACE}
```

---

## Database Setup

### 1. Deploy PostgreSQL (Using Helm)

```bash
# Add Bitnami repo
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Create database values file
cat > postgres-values.yaml <<EOF
auth:
  database: vacp
  username: vacp
  password: "$(openssl rand -base64 24)"
  postgresPassword: "$(openssl rand -base64 24)"

primary:
  persistence:
    enabled: true
    size: 50Gi
    storageClass: "standard"

  resources:
    requests:
      memory: 1Gi
      cpu: 500m
    limits:
      memory: 4Gi
      cpu: 2000m

  extraEnvVars:
    - name: POSTGRES_MAX_CONNECTIONS
      value: "200"

metrics:
  enabled: true
  serviceMonitor:
    enabled: true

backup:
  enabled: true
  cronjob:
    schedule: "0 2 * * *"
    storage:
      size: 10Gi
EOF

# Install PostgreSQL
helm install vacp-postgresql bitnami/postgresql \
  -n ${VACP_NAMESPACE} \
  -f postgres-values.yaml

# Wait for PostgreSQL to be ready
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=postgresql \
  -n ${VACP_NAMESPACE} \
  --timeout=300s
```

### 2. Initialize Database Schema

```bash
# Get PostgreSQL password
export POSTGRES_PASSWORD=$(kubectl get secret vacp-postgresql \
  -n ${VACP_NAMESPACE} \
  -o jsonpath="{.data.password}" | base64 -d)

# Port-forward to PostgreSQL
kubectl port-forward svc/vacp-postgresql 5432:5432 -n ${VACP_NAMESPACE} &

# Run migrations
PGPASSWORD=$POSTGRES_PASSWORD psql -h localhost -U vacp -d vacp <<EOF
-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create audit log table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action VARCHAR(255) NOT NULL,
    actor_id VARCHAR(255) NOT NULL,
    actor_type VARCHAR(50) NOT NULL,
    resource_type VARCHAR(255) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    correlation_id UUID,
    request_id UUID,
    status VARCHAR(50) DEFAULT 'success',
    details JSONB,
    signature TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_tenant_id ON audit_logs(tenant_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_correlation_id ON audit_logs(correlation_id);

-- Create blockchain anchors table
CREATE TABLE IF NOT EXISTS blockchain_anchors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    merkle_root VARCHAR(64) NOT NULL,
    tree_size INTEGER NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    backend VARCHAR(50) NOT NULL,
    transaction_id VARCHAR(255),
    consensus_timestamp TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confirmed_at TIMESTAMPTZ,
    metadata JSONB
);

CREATE INDEX idx_blockchain_anchors_merkle_root ON blockchain_anchors(merkle_root);
CREATE INDEX idx_blockchain_anchors_status ON blockchain_anchors(status);

-- Create tokens table
CREATE TABLE IF NOT EXISTS tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    secret_hash VARCHAR(255) NOT NULL,
    permissions JSONB NOT NULL DEFAULT '[]',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    tenant_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    metadata JSONB
);

CREATE INDEX idx_tokens_agent_id ON tokens(agent_id);
CREATE INDEX idx_tokens_tenant_id ON tokens(tenant_id);
CREATE INDEX idx_tokens_status ON tokens(status);

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO vacp;
EOF

# Kill port-forward
pkill -f "port-forward.*5432"
```

---

## Secrets Management

### 1. Deploy HashiCorp Vault (Optional but Recommended)

```bash
# Add HashiCorp repo
helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update

# Create Vault values
cat > vault-values.yaml <<EOF
server:
  ha:
    enabled: true
    replicas: 3
    raft:
      enabled: true

  resources:
    requests:
      memory: 256Mi
      cpu: 250m
    limits:
      memory: 512Mi
      cpu: 1000m

  auditStorage:
    enabled: true
    size: 10Gi

ui:
  enabled: true
EOF

# Install Vault
helm install vault hashicorp/vault \
  -n vault --create-namespace \
  -f vault-values.yaml

# Initialize Vault (first time only)
kubectl exec -n vault vault-0 -- vault operator init \
  -key-shares=5 -key-threshold=3 \
  -format=json > vault-init.json

# Unseal Vault (use 3 of 5 keys)
UNSEAL_KEY_1=$(jq -r '.unseal_keys_b64[0]' vault-init.json)
UNSEAL_KEY_2=$(jq -r '.unseal_keys_b64[1]' vault-init.json)
UNSEAL_KEY_3=$(jq -r '.unseal_keys_b64[2]' vault-init.json)

kubectl exec -n vault vault-0 -- vault operator unseal $UNSEAL_KEY_1
kubectl exec -n vault vault-0 -- vault operator unseal $UNSEAL_KEY_2
kubectl exec -n vault vault-0 -- vault operator unseal $UNSEAL_KEY_3
```

### 2. Store Secrets in Vault

```bash
# Get root token
ROOT_TOKEN=$(jq -r '.root_token' vault-init.json)

# Port-forward to Vault
kubectl port-forward -n vault svc/vault 8200:8200 &

# Configure Vault
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN=$ROOT_TOKEN

# Enable KV secrets engine
vault secrets enable -path=vacp kv-v2

# Store VACP secrets
vault kv put vacp/config \
  master_key="$MASTER_KEY" \
  api_key="$API_KEY" \
  backup_key="$BACKUP_KEY" \
  database_url="postgresql://vacp:${POSTGRES_PASSWORD}@vacp-postgresql:5432/vacp"

# Store Hedera credentials (if using)
vault kv put vacp/hedera \
  account_id="0.0.XXXXXX" \
  private_key="YOUR_HEDERA_PRIVATE_KEY"

# Store AI provider keys
vault kv put vacp/providers \
  openai_api_key="sk-..." \
  anthropic_api_key="sk-ant-..."

# Enable Kubernetes auth
vault auth enable kubernetes

vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc"

# Create policy for VACP
vault policy write vacp - <<EOF
path "vacp/data/*" {
  capabilities = ["read"]
}
path "vacp/metadata/*" {
  capabilities = ["list"]
}
EOF

# Create role for VACP
vault write auth/kubernetes/role/vacp \
  bound_service_account_names=vacp \
  bound_service_account_namespaces=${VACP_NAMESPACE} \
  policies=vacp \
  ttl=24h

pkill -f "port-forward.*8200"
```

### 3. Create Kubernetes Secrets (Alternative to Vault)

```bash
# Create secrets directly in Kubernetes
kubectl create secret generic vacp-secrets \
  -n ${VACP_NAMESPACE} \
  --from-literal=VACP_MASTER_KEY="$MASTER_KEY" \
  --from-literal=VACP_API_KEY="$API_KEY" \
  --from-literal=VACP_DATABASE_URL="postgresql://vacp:${POSTGRES_PASSWORD}@vacp-postgresql:5432/vacp" \
  --from-literal=VACP_BACKUP_ENCRYPTION_KEY="$BACKUP_KEY" \
  --from-literal=OPENAI_API_KEY="sk-..." \
  --from-literal=ANTHROPIC_API_KEY="sk-ant-..."
```

---

## Kubernetes Deployment

### 1. Deploy Using Helm

```bash
# Create values file for production
cat > vacp-values.yaml <<EOF
replicaCount: 3

image:
  repository: vacp/api-server
  tag: "1.0.0"
  pullPolicy: IfNotPresent

resources:
  requests:
    cpu: 500m
    memory: 1Gi
  limits:
    cpu: 2000m
    memory: 4Gi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70

ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/limit-rps: "50"
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: vacp.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: vacp-tls-cert
      hosts:
        - vacp.example.com

config:
  logLevel: "INFO"
  logFormat: "json"
  blockchain:
    enabled: true
    backend: "hedera"
    hederaNetwork: "mainnet"
  vault:
    address: "http://vault.vault:8200"
    authMethod: "kubernetes"
    authRole: "vacp"

secrets:
  create: false  # Using Vault instead

networkPolicy:
  enabled: true

podDisruptionBudget:
  enabled: true
  minAvailable: 2
EOF

# Deploy VACP
helm upgrade --install ${VACP_RELEASE} ./deploy/helm/vacp \
  -n ${VACP_NAMESPACE} \
  -f vacp-values.yaml \
  --wait --timeout=10m

# Verify deployment
kubectl get pods -n ${VACP_NAMESPACE} -l app.kubernetes.io/name=vacp
kubectl get svc -n ${VACP_NAMESPACE}
kubectl get ingress -n ${VACP_NAMESPACE}
```

### 2. Verify Deployment

```bash
# Check pod status
kubectl get pods -n ${VACP_NAMESPACE} -o wide

# Check logs
kubectl logs -n ${VACP_NAMESPACE} -l app.kubernetes.io/name=vacp --tail=100

# Check health endpoints
kubectl port-forward svc/vacp 8080:80 -n ${VACP_NAMESPACE} &
curl http://localhost:8080/health/live
curl http://localhost:8080/health/ready
pkill -f "port-forward.*8080"

# Check HPA status
kubectl get hpa -n ${VACP_NAMESPACE}

# Check network policies
kubectl get networkpolicy -n ${VACP_NAMESPACE}
```

---

## Monitoring Setup

### 1. Deploy Prometheus and Grafana

```bash
# Add Prometheus community repo
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Create monitoring namespace
kubectl create namespace monitoring

# Install Prometheus stack
helm install prometheus prometheus-community/kube-prometheus-stack \
  -n monitoring \
  --set grafana.adminPassword="$(openssl rand -base64 16)" \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false

# Create ServiceMonitor for VACP
kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: vacp
  namespace: monitoring
  labels:
    release: prometheus
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: vacp
  namespaceSelector:
    matchNames:
      - ${VACP_NAMESPACE}
  endpoints:
    - port: http
      path: /metrics
      interval: 30s
EOF
```

### 2. Create Alerting Rules

```bash
kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: vacp-alerts
  namespace: monitoring
  labels:
    release: prometheus
spec:
  groups:
    - name: vacp.rules
      rules:
        - alert: VACPHighErrorRate
          expr: |
            sum(rate(vacp_requests_total{status=~"5.."}[5m])) /
            sum(rate(vacp_requests_total[5m])) > 0.05
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "VACP high error rate"
            description: "Error rate is above 5%"

        - alert: VACPHighLatency
          expr: |
            histogram_quantile(0.95, rate(vacp_request_duration_seconds_bucket[5m])) > 2
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "VACP high latency"
            description: "P95 latency is above 2 seconds"

        - alert: VACPPodNotReady
          expr: |
            kube_pod_status_ready{namespace="${VACP_NAMESPACE}",condition="true"} == 0
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "VACP pod not ready"
            description: "Pod {{ \$labels.pod }} is not ready"
EOF
```

---

## Backup Configuration

### 1. Configure Automated Backups

```bash
# Create backup CronJob
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: CronJob
metadata:
  name: vacp-backup
  namespace: ${VACP_NAMESPACE}
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: vacp
          containers:
            - name: backup
              image: postgres:15
              env:
                - name: PGPASSWORD
                  valueFrom:
                    secretKeyRef:
                      name: vacp-postgresql
                      key: password
                - name: BACKUP_S3_BUCKET
                  value: "vacp-backups"
              command:
                - /bin/bash
                - -c
                - |
                  BACKUP_FILE="/tmp/vacp_\$(date +%Y%m%d_%H%M%S).sql.gz"
                  pg_dump -h vacp-postgresql -U vacp -d vacp | gzip > \$BACKUP_FILE
                  # Upload to S3 (requires aws-cli in image)
                  # aws s3 cp \$BACKUP_FILE s3://\$BACKUP_S3_BUCKET/
                  echo "Backup completed: \$BACKUP_FILE"
          restartPolicy: OnFailure
EOF
```

### 2. Manual Backup Commands

```bash
# Create manual backup
kubectl exec -n ${VACP_NAMESPACE} vacp-postgresql-0 -- \
  pg_dump -U vacp -d vacp | gzip > vacp_backup_$(date +%Y%m%d).sql.gz

# Restore from backup
gunzip -c vacp_backup_20240115.sql.gz | \
  kubectl exec -i -n ${VACP_NAMESPACE} vacp-postgresql-0 -- \
  psql -U vacp -d vacp
```

---

## Health Checks

### Daily Health Check Procedure

```bash
#!/bin/bash
# Save as: health_check.sh

echo "=== VACP Health Check ==="
echo "Time: $(date)"
echo ""

# 1. Check pod status
echo "1. Pod Status:"
kubectl get pods -n ${VACP_NAMESPACE} -l app.kubernetes.io/name=vacp

# 2. Check service health
echo -e "\n2. Service Health:"
kubectl port-forward svc/vacp 8080:80 -n ${VACP_NAMESPACE} &
PF_PID=$!
sleep 2

LIVE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health/live)
READY=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health/ready)
kill $PF_PID 2>/dev/null

echo "  Liveness: $LIVE"
echo "  Readiness: $READY"

# 3. Check database
echo -e "\n3. Database Status:"
kubectl get pods -n ${VACP_NAMESPACE} -l app.kubernetes.io/name=postgresql

# 4. Check HPA
echo -e "\n4. Autoscaling Status:"
kubectl get hpa -n ${VACP_NAMESPACE}

# 5. Check recent errors
echo -e "\n5. Recent Errors (last 5 min):"
kubectl logs -n ${VACP_NAMESPACE} -l app.kubernetes.io/name=vacp \
  --since=5m | grep -i error | tail -5

# 6. Check resource usage
echo -e "\n6. Resource Usage:"
kubectl top pods -n ${VACP_NAMESPACE}

echo -e "\n=== Health Check Complete ==="
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Pods Not Starting

```bash
# Check pod events
kubectl describe pod -n ${VACP_NAMESPACE} -l app.kubernetes.io/name=vacp

# Check for resource constraints
kubectl get events -n ${VACP_NAMESPACE} --sort-by='.lastTimestamp'

# Check node resources
kubectl describe nodes | grep -A 5 "Allocated resources"
```

#### 2. Database Connection Issues

```bash
# Test database connectivity
kubectl run -it --rm db-test \
  --image=postgres:15 \
  --restart=Never \
  -n ${VACP_NAMESPACE} \
  -- psql -h vacp-postgresql -U vacp -d vacp -c "SELECT 1"

# Check database logs
kubectl logs -n ${VACP_NAMESPACE} -l app.kubernetes.io/name=postgresql --tail=50

# Check connection limits
kubectl exec -n ${VACP_NAMESPACE} vacp-postgresql-0 -- \
  psql -U vacp -d vacp -c "SELECT count(*) FROM pg_stat_activity"
```

#### 3. High Latency

```bash
# Check pod resource usage
kubectl top pods -n ${VACP_NAMESPACE}

# Check for throttling
kubectl describe pod -n ${VACP_NAMESPACE} -l app.kubernetes.io/name=vacp | grep -A 3 "Resources"

# Check network policies
kubectl get networkpolicy -n ${VACP_NAMESPACE} -o yaml

# Scale up if needed
kubectl scale deployment vacp -n ${VACP_NAMESPACE} --replicas=5
```

#### 4. Certificate Issues

```bash
# Check certificate status
kubectl get certificate -n ${VACP_NAMESPACE}

# Check certificate secret
kubectl describe secret vacp-tls-cert -n ${VACP_NAMESPACE}

# Force certificate renewal
kubectl delete certificate vacp-tls -n ${VACP_NAMESPACE}
# cert-manager will recreate it
```

---

## Emergency Procedures

### 1. Emergency Kill Switch Activation

```bash
# Activate kill switch via API
curl -X POST https://vacp.example.com/api/v1/security/kill-switch \
  -H "X-API-Key: $VACP_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Emergency shutdown - Security incident",
    "scope": "global",
    "duration_minutes": 0
  }'

# Or scale to zero
kubectl scale deployment vacp -n ${VACP_NAMESPACE} --replicas=0
```

### 2. Emergency Rollback

```bash
# Check deployment history
kubectl rollout history deployment/vacp -n ${VACP_NAMESPACE}

# Rollback to previous version
kubectl rollout undo deployment/vacp -n ${VACP_NAMESPACE}

# Rollback to specific revision
kubectl rollout undo deployment/vacp -n ${VACP_NAMESPACE} --to-revision=2

# Monitor rollback
kubectl rollout status deployment/vacp -n ${VACP_NAMESPACE}
```

### 3. Database Emergency Recovery

```bash
# Create emergency backup
kubectl exec -n ${VACP_NAMESPACE} vacp-postgresql-0 -- \
  pg_dump -U vacp -d vacp > emergency_backup_$(date +%Y%m%d_%H%M%S).sql

# Restore from backup
cat emergency_backup.sql | \
  kubectl exec -i -n ${VACP_NAMESPACE} vacp-postgresql-0 -- \
  psql -U vacp -d vacp

# Reset database connections
kubectl exec -n ${VACP_NAMESPACE} vacp-postgresql-0 -- \
  psql -U vacp -d vacp -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='vacp' AND pid <> pg_backend_pid()"
```

### 4. Security Incident Response

```bash
# 1. Isolate affected pods
kubectl label pods -n ${VACP_NAMESPACE} -l app.kubernetes.io/name=vacp quarantine=true

# 2. Apply restrictive network policy
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-lockdown
  namespace: ${VACP_NAMESPACE}
spec:
  podSelector:
    matchLabels:
      quarantine: "true"
  policyTypes:
    - Ingress
    - Egress
  ingress: []  # Block all ingress
  egress: []   # Block all egress
EOF

# 3. Export audit logs
kubectl exec -n ${VACP_NAMESPACE} vacp-0 -- \
  python -c "from vacp.core.audit_export import *; ..."

# 4. Collect pod logs
kubectl logs -n ${VACP_NAMESPACE} -l app.kubernetes.io/name=vacp --all-containers --timestamps > incident_logs.txt
```

---

## Maintenance Procedures

### Scheduled Maintenance Window

```bash
#!/bin/bash
# Save as: maintenance.sh

echo "Starting maintenance window..."

# 1. Enable maintenance mode (optional application feature)
# curl -X POST https://vacp.example.com/admin/maintenance/enable

# 2. Scale down to reduce traffic
kubectl scale deployment vacp -n ${VACP_NAMESPACE} --replicas=1

# 3. Create pre-maintenance backup
kubectl exec -n ${VACP_NAMESPACE} vacp-postgresql-0 -- \
  pg_dump -U vacp -d vacp > pre_maintenance_$(date +%Y%m%d).sql

# 4. Perform maintenance (example: apply database migrations)
# kubectl apply -f migrations.yaml

# 5. Scale back up
kubectl scale deployment vacp -n ${VACP_NAMESPACE} --replicas=3

# 6. Verify health
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=vacp \
  -n ${VACP_NAMESPACE} \
  --timeout=300s

# 7. Disable maintenance mode
# curl -X POST https://vacp.example.com/admin/maintenance/disable

echo "Maintenance window complete."
```

---

## Contact Information

| Role | Contact | Escalation |
|------|---------|------------|
| On-call Engineer | [pagerduty/opsgenie] | Primary |
| Security Team | security@example.com | Security incidents |
| Platform Team | platform@example.com | Infrastructure issues |
| Database Admin | dba@example.com | Database issues |

---

*Document Version: 1.0*
*Last Updated: [DATE]*
*Next Review: Quarterly*
