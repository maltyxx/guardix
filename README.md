# 🛡️ Guardix - AI-Powered WAF that learns

An **autonomous Web Application Firewall (WAF)** that uses a **Large Language Model (LLM)** to learn and adapt its security rules automatically based on observed traffic.

## 🎯 Concept

Unlike traditional WAFs that require tedious manual configuration, Guardix:

- **Real-time judgment**: Evaluates each HTTP request via LLM (Judge)
- **Automatic learning**: Periodically analyzes suspicious requests and generates new rules (Learner)
- **Traffic adaptation**: Continuously improves detection without manual intervention
- **Fail-open**: In case of errors or timeouts, allows traffic through (high availability)

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│  HTTP Request                           │
├─────────────────────────────────────────┤
│  WAF Middleware                         │  ← Normalization, timeout
├─────────────────────────────────────────┤
│  Judge Service                          │  ← Real-time decision
│    ├─ Redis Cache (lookup)             │
│    ├─ LLM Ollama (on cache miss)       │
│    └─ Fail-open (on timeout/error)     │
├─────────────────────────────────────────┤
│  Decision: Allow / Flag / Block         │
├─────────────────────────────────────────┤
│  SQLite Log (async)                     │
├─────────────────────────────────────────┤
│  Forward → Upstream or 403              │
└─────────────────────────────────────────┘

        Parallel process (batch):
┌─────────────────────────────────────────┐
│  Learner Service (every 60 min)        │
│    ├─ Read flagged logs                │
│    ├─ Call LLM for analysis            │
│    ├─ Generate new rules               │
│    └─ Save rulebook.json               │
├─────────────────────────────────────────┤
│  Hot-reload rulebook                    │  ← No restart needed
└─────────────────────────────────────────┘
```

### Key Components

- **Judge**: Real-time service that evaluates requests
- **Learner**: Batch service that generates rules
- **Redis**: Verdict cache (~70% reduction in LLM calls)
- **SQLite**: Event log storage
- **Ollama**: Local LLM provider

## 🚀 Quick Start

### Prerequisites

1. **Ollama** on the host machine:
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Download a model
ollama pull gpt-oss:20b
```

2. **Dev Container** (recommended) or Rust + Redis locally

### Launch with Dev Container

```bash
# Open in VS Code with Dev Containers extension
# Container starts automatically with Redis

# Build the project
cargo build

# Start the WAF
cargo run

# WAF listens on http://localhost:5000
```

### Configuration

Edit `config.yaml`:

```yaml
waf:
  listen_addr: "0.0.0.0:5000"        # WAF port
  upstream_url: "http://backend:3000" # Protected backend
  request_timeout_ms: 30000

llm:
  base_url: "http://host.docker.internal:11434"  # Ollama
  model: "gpt-oss:20b"
  judge_timeout_ms: 30000             # Decision timeout
  judge_max_tokens: 150
  judge_temperature: 0.0              # Deterministic

cache:
  redis_url: "redis://cache:6379"
  ttl_seconds: 900                    # Cache 15 min
  enabled: true

learner:
  batch_interval_minutes: 60          # Learn every hour
  min_flagged_requests: 10            # Minimum threshold
  enabled: true
```

## 📊 Usage

### Testing the WAF

```bash
# Health check
curl http://localhost:5000/health

# Normal request (should be allowed)
curl http://localhost:5000/api/users

# SQL injection attempt (should be flagged/blocked)
curl "http://localhost:5000/users?id=1' OR '1'='1"

# XSS attempt
curl "http://localhost:5000/search?q=<script>alert('xss')</script>"
```

### View logs

```bash
# Events are stored in data/logs.db
sqlite3 data/logs.db "SELECT * FROM events ORDER BY timestamp DESC LIMIT 10;"
```

### View rulebook

```bash
# Rulebook evolves automatically
cat data/rulebook.json | jq
```

## 🧪 Testing

```bash
# Unit tests
cargo test --lib

# Integration tests
cargo test --test integration_tests

# End-to-end tests (requires ports 3000 & 5000 free)
make test-e2e

# All tests with detailed logs
RUST_LOG=debug cargo test -- --nocapture
```

See [tests/README.md](tests/README.md) for detailed testing documentation.

## 🔧 Development

### Project Structure

```
src/
├── main.rs              # Entry point
├── config.rs            # YAML configuration
├── core/
│   ├── judge.rs         # Real-time decision service
│   ├── learner.rs       # Batch learning service
│   └── rulebook.rs      # Rule management
├── http/
│   ├── proxy.rs         # Reverse proxy
│   └── middleware.rs    # HTTP pipeline
├── llm/
│   ├── client.rs        # LLM abstraction trait
│   ├── ollama.rs        # Ollama implementation
│   └── prompts.rs       # Prompt templates
├── storage/
│   ├── cache.rs         # Redis
│   ├── logs.rs          # SQLite
│   └── rules.rs         # Rulebook JSON + hot-reload
└── models/
    ├── decision.rs      # JudgeDecision, ThreatLevel
    └── request.rs       # RequestPayload, LogEntry
```

### Architectural Principles

✅ **SOLID**: Each module has a single responsibility  
✅ **Type-safe**: No magic strings, only enums  
✅ **Dependency Injection**: Traits for LLM abstraction  
✅ **Fail-open**: High availability on errors  
✅ **Observable**: Structured tracing everywhere  

### Useful Commands

```bash
# Format code
cargo fmt

# Linter
cargo clippy

# Watch mode (recompile on changes)
cargo watch -x run

# Optimized build for production
cargo build --release
```

## 📈 Metrics

The Judge exposes internal metrics:

- `total_requests`: Total evaluated requests
- `cache_hits`: Verdicts served from cache
- `cache_misses`: LLM calls made
- `llm_timeouts`: LLM timeouts
- `llm_errors`: LLM errors
- `fail_open_count`: Fail-open occurrences

## 🔒 Security

### Detected Attack Types

- ✅ SQL Injection (SQLi)
- ✅ Cross-Site Scripting (XSS)
- ✅ Path Traversal
- ✅ Command Injection
- ✅ Authentication Bypass
- ✅ API Abuse

### Possible Decisions

- **Allow**: Legitimate request (confidence > 0.7)
- **Flag**: Suspicious but uncertain (confidence 0.4-0.7) → logged for analysis
- **Block**: Confirmed attack (confidence > 0.7) → 403 Forbidden

## 🛣️ Roadmap

### V1 (MVP) - ✅ Current
- [x] Real-time Judge with Redis cache
- [x] Batch Learner every hour
- [x] Hot-reload rulebook
- [x] Fail-open on errors
- [x] Local Ollama support

### V2 (Future improvements)
- [ ] Circuit breaker for LLM
- [ ] Prometheus metrics (endpoint `/metrics`)
- [ ] Admin dashboard
- [ ] Multi-LLM support (small for Judge, large for Learner)
- [ ] Rate limiting per IP

### V3 (Advanced)
- [ ] Vector store (Qdrant) for attack clustering
- [ ] Dynamic few-shot learning
- [ ] Learning-only mode (flag everything, block nothing)
- [ ] ModSecurity rule export

## 🤝 Contributing

Contributions are welcome! Please follow SOLID principles and add tests.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - Copyright (c) 2025 Yoann Vanitou

## 👤 Author

**Yoann Vanitou** ([@maltyxx](https://github.com/maltyxx))
- GitHub: [github.com/maltyxx](https://github.com/maltyxx)
- Project: [Guardix](https://github.com/maltyxx/guardix)
- LinkedIn: [linkedin.com/in/yvanitou](https://linkedin.com/in/yvanitou)

## 🙏 Credits

Built with:
- 🦀 Rust
- 🔥 Axum (HTTP framework)
- 🧠 Ollama (Local LLM)
- 🗄️ Redis + SQLite

---

**Guardix** - AI-Powered security that learns. Zero configuration.
