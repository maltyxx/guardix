# Guardix Architecture

## Overview

Guardix is built on a layered architecture following SOLID principles and the **Judge-Learner** pattern.

## Flow Diagrams

### Request Lifecycle (Judge)

```
┌──────────────┐
│  Client      │
└──────┬───────┘
       │ HTTP Request
       ▼
┌──────────────────────────────────┐
│  Axum Router                     │
│  - Middleware (tracing, timeout) │
└──────┬───────────────────────────┘
       │
       ▼
┌──────────────────────────────────┐
│  proxy_handler                   │
│  1. Extract & normalize payload  │
└──────┬───────────────────────────┘
       │
       ▼
┌──────────────────────────────────┐
│  Judge::evaluate()               │
│  ┌─────────────────────────────┐ │
│  │ 1. Check Redis cache        │ │
│  │    ├─ HIT  → return cached  │ │
│  │    └─ MISS → continue       │ │
│  └─────────────────────────────┘ │
│  ┌─────────────────────────────┐ │
│  │ 2. Call LLM with timeout    │ │
│  │    ├─ Read rulebook         │ │
│  │    ├─ Generate prompt       │ │
│  │    └─ Ollama API call       │ │
│  └─────────────────────────────┘ │
│  ┌─────────────────────────────┐ │
│  │ 3. Handle response          │ │
│  │    ├─ Success → cache       │ │
│  │    ├─ Timeout → fail-open   │ │
│  │    └─ Error   → fail-open   │ │
│  └─────────────────────────────┘ │
└──────┬───────────────────────────┘
       │
       │ JudgeDecision
       ▼
┌──────────────────────────────────┐
│  Log event (async)               │
│  - SQLite insertion              │
└──────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────┐
│  Act on decision                 │
│  ├─ Block → 403 Forbidden        │
│  ├─ Flag  → forward + log        │
│  └─ Allow → forward              │
└──────┬───────────────────────────┘
       │
       ▼
┌──────────────────────────────────┐
│  Forward to upstream             │
│  (if not blocked)                │
└──────┬───────────────────────────┘
       │
       ▼
┌──────────────┐
│  Response    │
└──────────────┘
```

### Learning Cycle (Learner)

```
┌─────────────────────────────────────┐
│  Learner Scheduler (tokio interval) │
│  Tick every 60 minutes             │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│  Learner::run_batch()               │
│  ┌────────────────────────────────┐ │
│  │ 1. Get last_run timestamp      │ │
│  └────────────────────────────────┘ │
│  ┌────────────────────────────────┐ │
│  │ 2. Fetch flagged events        │ │
│  │    SELECT * FROM events        │ │
│  │    WHERE decision='flag'       │ │
│  │    AND timestamp >= last_run   │ │
│  └────────────────────────────────┘ │
│  ┌────────────────────────────────┐ │
│  │ 3. Check threshold             │ │
│  │    if count < 10 → skip        │ │
│  └────────────────────────────────┘ │
│  ┌────────────────────────────────┐ │
│  │ 4. Load current rulebook       │ │
│  └────────────────────────────────┘ │
│  ┌────────────────────────────────┐ │
│  │ 5. Call LLM learner            │ │
│  │    - Generate learner prompt   │ │
│  │    - Analyze patterns          │ │
│  │    - Suggest rule changes      │ │
│  └────────────────────────────────┘ │
│  ┌────────────────────────────────┐ │
│  │ 6. Apply changes               │ │
│  │    - Add new rules             │ │
│  │    - Weaken rules (×0.8 conf)  │ │
│  │    - Remove rules              │ │
│  └────────────────────────────────┘ │
│  ┌────────────────────────────────┐ │
│  │ 7. Save rulebook.json          │ │
│  └────────────────────────────────┘ │
│  ┌────────────────────────────────┐ │
│  │ 8. Update last_run             │ │
│  └────────────────────────────────┘ │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│  notify watcher detects change      │
│  → hot-reload rulebook in Judge     │
└─────────────────────────────────────┘
```

## Modules and Responsibilities

### Core (Business Logic)

#### `judge.rs`
**Responsibility**: Real-time request decisions

- **Dependencies**: `LlmProvider`, `RedisCache`, `Rulebook`
- **Pattern**: Cache-aside
- **Error Policy**: Fail-open
- **Metrics**: total_requests, cache_hits, timeouts, etc.

#### `learner.rs`
**Responsibility**: Batch learning and rule generation

- **Dependencies**: `LlmProvider`, `LogStore`, `RulebookStore`
- **Pattern**: Tokio interval scheduler
- **Trigger**: Configurable interval (default: 60 min)
- **Threshold**: Minimum 10 flagged requests

#### `rulebook.rs`
**Responsibility**: Rule structure and management

- **Operations**: add_rule, remove_rule, get_rule
- **Versioning**: Incremented on each modification
- **Timestamp**: updated_at for traceability

### HTTP (Transport Layer)

#### `proxy.rs`
**Responsibility**: Reverse proxy and orchestration

- **Extraction**: HTTP request normalization
- **Decision**: Judge invocation
- **Logging**: Async non-blocking
- **Forwarding**: To upstream with hyper-util

#### `middleware.rs`
**Responsibility**: Processing pipeline

- **Tracing**: Structured logging per request
- **Timeout**: Global timeout via Tower
- **Headers**: Case-insensitive normalization

### LLM (AI Abstraction)

#### `client.rs`
**Responsibility**: LLM abstraction trait

- **Pattern**: Dependency Inversion
- **Methods**: judge_request, learn_rules, health_check
- **Mock**: MockLlmProvider for tests

#### `ollama.rs`
**Responsibility**: Ollama implementation

- **HTTP Client**: reqwest with timeout
- **Retry**: 1 retry with 100ms backoff
- **JSON parsing**: Robust extraction even with surrounding text
- **Format**: JSON enforced via Ollama parameter

#### `prompts.rs`
**Responsibility**: Prompt templates

- **Judge prompt**: Optimized for latency (temp=0, max_tokens=150)
- **Learner prompt**: Pattern analysis (temp=0.3, max_tokens=2048)
- **Structured output**: Strict JSON format requested

### Storage (Persistence)

#### `cache.rs`
**Responsibility**: Redis verdict cache

- **Pattern**: Set with TTL (default: 15 min)
- **Key format**: `verdict:{hash}`
- **Serialization**: JSON via serde

#### `logs.rs`
**Responsibility**: SQLite event logs

- **Schema**: events table with indices
- **Queries**: get_flagged_since, get_blocked_since
- **Migrations**: sqlx migrate

#### `rules.rs`
**Responsibility**: Rulebook persistence

- **Format**: Pretty-printed JSON
- **Hot-reload**: notify watcher on file
- **Channel**: mpsc to communicate changes

### Models (Data Structures)

#### `decision.rs`
**Structures**:
- `JudgeDecision`: Allow | Flag | Block
- `ThreatLevel`: Low | Medium | High | Critical
- `LearnerOutput`: new_rules, weaken_rules, remove_rules

#### `request.rs`
**Structures**:
- `RequestPayload`: Normalized request with SHA256 hash
- `LogEntry`: Event logged in SQLite

## Design Principles

### 1. Type Safety
❌ No magic strings  
✅ Enums everywhere (ThreatLevel, RuleAction, etc.)

### 2. Dependency Injection
❌ Direct coupling to Ollama  
✅ Inject `LlmProvider` trait

### 3. Fail-open
❌ Block all on error  
✅ Allow with confidence=0 on timeout/error

### 4. Cache-aside
❌ Call LLM every time  
✅ Redis lookup → cache miss → LLM → cache set

### 5. Async non-blocking
❌ Synchronous log slowing down  
✅ tokio::spawn for logs

### 6. Hot-reload
❌ Restart to apply rules  
✅ notify watcher + Arc<RwLock<Rulebook>>

## Architectural Decision Records (ADR)

### ADR-001: Single LLM for MVP
**Context**: Simplicity vs performance  
**Decision**: Same model for Judge and Learner, different prompts  
**Rationale**: Avoid complexity, simple deployment

### ADR-002: Redis optional but recommended
**Context**: High LLM latency  
**Decision**: Cache enabled by default, can be disabled  
**Rationale**: 70%+ reduction in LLM calls

### ADR-003: SQLite for logs
**Context**: Simple persistence  
**Decision**: Embedded SQLite, no external server  
**Rationale**: Zero configuration, sufficient for MVP

### ADR-004: Fail-open by default
**Context**: High availability vs security  
**Decision**: Allow on errors  
**Rationale**: WAF must not break the service

### ADR-005: Forced JSON format
**Context**: LLM may add text around response  
**Decision**: Parse with JSON extraction  
**Rationale**: Robustness even if LLM is verbose

## Data Schema

### SQLite events table
```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,           -- Unix timestamp
    method TEXT NOT NULL,                 -- GET, POST, etc.
    path TEXT NOT NULL,                   -- /api/users
    payload_hash TEXT NOT NULL,           -- SHA256
    decision TEXT NOT NULL,               -- allow, flag, block
    confidence REAL NOT NULL,             -- 0.0 - 1.0
    reason TEXT,                          -- Explanation
    ip_addr TEXT,                         -- Client IP
    user_agent TEXT                       -- User-Agent header
);

CREATE INDEX idx_decision_timestamp ON events(decision, timestamp);
CREATE INDEX idx_payload_hash ON events(payload_hash);
CREATE INDEX idx_timestamp ON events(timestamp DESC);
```

### Redis keys
```
verdict:{hash} → JSON(JudgeDecision)
TTL: 900 seconds (15 min)
```

### rulebook.json
```json
{
  "version": 1,
  "updated_at": "2025-11-06T12:00:00Z",
  "rules": [
    {
      "id": "uuid-v4",
      "pattern": "SELECT.*FROM",
      "threat_type": "sqli",
      "confidence": 0.85,
      "action": "block",
      "created_by": "llm",
      "created_at": "2025-11-06T12:00:00Z",
      "description": "SQL injection pattern"
    }
  ]
}
```

## Performance

### Target Latencies
- **Judge (cache hit)**: < 5ms
- **Judge (cache miss)**: < 300ms (p95)
- **Learner batch**: < 30s for 100 logs

### Success Metrics
- **Cache hit ratio**: > 70%
- **False positives**: < 5%
- **Fail-open rate**: < 1%

## Extensibility

### Adding a New LLM Provider
1. Implement `LlmProvider` trait
2. Add config to `LlmConfig`
3. Factory pattern in main.rs

### Adding a New Storage Backend
1. Create `CacheProvider` or `LogProvider` trait
2. Refactor storage modules
3. Dependency injection

### Adding New Metrics
1. Add fields to `JudgeMetrics`
2. Expose via `/metrics` endpoint (TODO: Prometheus)
