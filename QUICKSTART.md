# 🚀 Quickstart Guide

Get Guardix running in 5 minutes.

## Prerequisites

1. **Ollama** installed and running on your host machine:
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Download a model
ollama pull gpt-oss:20b

# Verify Ollama is running
ollama list
```

2. **VS Code** with "Dev Containers" extension

## Step 1: Open the Project

```bash
# Clone the repo (or open the folder)
code .

# VS Code automatically detects the dev container
# Click "Reopen in Container"
```

The container will:
- Install Rust, SQLx, Redis
- Create SQLite database
- Initialize empty rulebook
- Generate config.yaml

## Step 2: Start the Test Backend

In a VS Code terminal:

```bash
make backend
# Or: cargo run --example test_backend
```

The backend listens on `http://localhost:3000` (intentionally vulnerable for testing).

## Step 3: Configure the WAF

The `config.yaml` file is already created. Verify that:

```yaml
waf:
  upstream_url: "http://localhost:3000"  # ← Test backend

llm:
  base_url: "http://host.docker.internal:11434"  # ← Ollama on host
```

## Step 4: Start the WAF

In another terminal:

```bash
make run
# Or: cargo run
```

You should see:

```
🛡️ Guardix - AI-Powered WAF that learns
✓ Log store initialized
✓ Rulebook store initialized
✓ Redis cache initialized
✓ LLM provider connected
✓ Judge service initialized
✓ Learner service initialized
🚀 WAF listening on 0.0.0.0:5000
```

## Step 5: Test

In a third terminal:

```bash
# Quick health check
curl http://localhost:5000/health
```

Test manually:

```bash
# Normal request (should pass)
curl http://localhost:5000/api/users

# SQL injection attempt (should be blocked/flagged)
curl "http://localhost:5000/users?id=1' OR '1'='1"

# XSS attempt
curl "http://localhost:5000/search?q=<script>alert('xss')</script>"
```

## Step 6: Observe Results

### Real-time Logs

In the WAF terminal, you'll see:

```
INFO guardix: Request evaluated method=GET path=/users decision=block confidence=0.92
```

### SQLite Database

```bash
make logs
# Or: sqlite3 data/logs.db "SELECT * FROM events ORDER BY timestamp DESC LIMIT 10;"
```

### Rulebook

```bash
make rulebook
# Or: cat data/rulebook.json | jq
```

The Learner analyzes flagged requests every hour and updates the rulebook automatically.

## Useful Commands

```bash
make help              # List all commands

make build             # Compile
make test              # Run tests
make fmt               # Format code
make clippy            # Lint

make logs              # View recent logs
make rulebook          # View current rules
make stats             # Event statistics

make test-e2e          # End-to-end tests
```

## Force Immediate Learning

By default, the Learner runs every 60 minutes. To test immediately:

1. Modify `config.yaml`:
```yaml
learner:
  batch_interval_minutes: 1  # ← 1 minute instead of 60
  min_flagged_requests: 3    # ← Lower threshold
```

2. Restart the WAF

3. Generate several similar attacks

4. Wait 1 minute

5. Observe updated rulebook

## Troubleshooting

### "LLM health check failed"

```bash
# Verify Ollama is running on host
curl http://host.docker.internal:11434/api/tags

# If error, start Ollama:
ollama serve
```

### "Redis ping failed"

```bash
# Redis should start automatically with container
# Check:
docker compose ps

# Restart if needed:
docker compose restart cache
```

### "Failed to connect to upstream"

```bash
# Verify test backend is running:
curl http://localhost:3000/health

# If not, start it:
make backend
```

### Database Locked

```bash
# Stop WAF and clean:
make clean
# Then restart
```

## Next Steps

1. 📖 Read the full [README.md](README.md)
2. 🏗️ Check [ARCHITECTURE.md](docs/ARCHITECTURE.md)
3. 🔧 Modify prompts in `src/llm/prompts.rs`
4. 📊 Add your own metrics
5. 🎯 Test with your own backend

## Support

If you encounter issues:
1. Check WAF logs (very verbose)
2. Check `data/logs.db`
3. Check config `config.yaml`
4. Run with `RUST_LOG=debug cargo run`

Happy testing! 🛡️🔒
