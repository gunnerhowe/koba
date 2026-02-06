# Koba Governance Plugin for ClawdBot

This plugin integrates ClawdBot with Koba (VACP) to provide:

- **Policy Enforcement**: Every AI tool call is evaluated against Koba's policy engine
- **Signed Receipts**: Cryptographically signed proof of every action
- **Audit Logging**: Tamper-evident transparency log of all AI actions
- **Approval Workflows**: High-risk actions require human approval

## Quick Start

### 1. Start Koba

```bash
cd vacp
docker-compose up -d
```

Koba API will be available at `http://localhost:8000`

### 2. Install the Plugin

Copy the plugin to your ClawdBot workspace:

```bash
# Option A: Copy to workspace plugins directory
cp -r integrations/clawdbot ~/.clawdbot/plugins/koba-governance

# Option B: Install from npm (when published)
# npm install -g koba-governance
```

### 3. Configure ClawdBot

Add to your `~/.clawdbot/config.yaml`:

```yaml
plugins:
  koba-governance:
    enabled: true
    config:
      apiUrl: http://localhost:8000
      tenantId: default
      verbose: true
      # Optional: skip certain tools
      skipTools:
        - read_file
        - list_files
```

Or use environment variables:

```bash
export KOBA_API_URL=http://localhost:8000
export KOBA_TENANT_ID=default
# export KOBA_API_KEY=your-api-key  # If authentication is enabled
```

### 4. Restart ClawdBot

```bash
clawdbot gateway --restart
```

## How It Works

```
ClawdBot AI Agent
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│                    Koba Plugin                               │
│  ┌──────────────────┐        ┌──────────────────────────┐   │
│  │ before_tool_call │───────▶│ POST /v1/tools/evaluate  │   │
│  │      hook        │◀───────│     (policy check)       │   │
│  └──────────────────┘        └──────────────────────────┘   │
│           │                                                  │
│           │ allow/deny/require_approval                      │
│           ▼                                                  │
│  ┌──────────────────┐                                       │
│  │   Tool Executes  │ (if allowed)                          │
│  └──────────────────┘                                       │
│           │                                                  │
│           ▼                                                  │
│  ┌──────────────────┐        ┌──────────────────────────┐   │
│  │ after_tool_call  │───────▶│ POST /v1/audit/record    │   │
│  │      hook        │◀───────│   (signed receipt)       │   │
│  └──────────────────┘        └──────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
       │
       ▼
  Response to User
```

### Policy Evaluation Flow

1. **before_tool_call**: When ClawdBot's AI wants to use a tool, this hook fires
2. **Koba Evaluate**: The plugin sends the tool call to Koba's `/v1/tools/evaluate`
3. **Policy Decision**: Koba returns `allow`, `deny`, or `require_approval`
4. **Execution**: If allowed, ClawdBot executes the tool
5. **Record**: After execution, the plugin records the result via `/v1/audit/record`
6. **Receipt**: Koba returns a cryptographically signed receipt

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiUrl` | string | `http://localhost:8000` | Koba API URL |
| `apiKey` | string | - | API key for authentication (optional) |
| `tenantId` | string | `default` | Tenant ID for multi-tenant setups |
| `blockOnError` | boolean | `false` | Block tool calls if Koba is unavailable |
| `skipTools` | string[] | `[]` | Tools to skip governance for |
| `verbose` | boolean | `false` | Enable verbose logging |

## Viewing Audit Logs

### Via Koba Dashboard

Open `http://localhost:3000` in your browser to see:
- Real-time tool call activity
- Policy decisions
- Signed receipts
- Approval queue

### Via API

```bash
# Get recent audit entries
curl http://localhost:8000/v1/audit/entries

# Get a specific receipt
curl http://localhost:8000/v1/receipts/{receipt_id}

# Verify a receipt signature
curl -X POST http://localhost:8000/v1/receipts/verify \
  -H "Content-Type: application/json" \
  -d '{"receipt_id": "rcpt_xxx"}'
```

## Creating Policies

### Example: Block Dangerous Tools

```bash
curl -X POST http://localhost:8000/v1/policy/bundles \
  -H "Content-Type: application/json" \
  -d '{
    "name": "clawdbot-safety",
    "rules": [
      {
        "name": "block-shell-commands",
        "action": "deny",
        "conditions": {
          "tool_name": {"pattern": "shell_*"}
        },
        "reason": "Shell commands are not allowed"
      },
      {
        "name": "require-approval-for-writes",
        "action": "require_approval",
        "conditions": {
          "tool_name": {"pattern": "write_*"}
        },
        "reason": "Write operations require human approval"
      },
      {
        "name": "allow-reads",
        "action": "allow",
        "conditions": {
          "tool_name": {"pattern": "read_*"}
        }
      }
    ]
  }'
```

### Example: Rate Limiting

```bash
curl -X POST http://localhost:8000/v1/policy/bundles \
  -H "Content-Type: application/json" \
  -d '{
    "name": "rate-limits",
    "rules": [
      {
        "name": "browser-rate-limit",
        "action": "allow",
        "conditions": {
          "tool_name": {"exact": "browser_action"}
        },
        "constraints": {
          "rate_limit": {
            "max_calls": 10,
            "window_seconds": 60
          }
        }
      }
    ]
  }'
```

## Troubleshooting

### Plugin not loading

Check ClawdBot logs:
```bash
clawdbot gateway --verbose
```

Look for:
```
[plugins] koba-governance loaded
Koba governance plugin activated
```

### Tool calls not being evaluated

1. Make sure Koba is running: `curl http://localhost:8000/health`
2. Check if the tool is in `skipTools`
3. Enable verbose logging in plugin config

### Koba connection errors

1. Verify `apiUrl` is correct
2. Check network connectivity
3. Set `blockOnError: false` to allow tool calls when Koba is down

## Development

### Building from source

```bash
cd integrations/clawdbot
npm install
npm run build
```

### Testing

```bash
# Start Koba
docker-compose up -d

# Start ClawdBot with plugin
clawdbot gateway --verbose

# Send a test message that uses tools
clawdbot agent --message "What's the weather like?"
```

## License

MIT
