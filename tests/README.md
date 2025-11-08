# Testing Guardix

## Test Types

### 1. Unit Tests (14 tests)
Tests for individual functions and modules.

```bash
# Run all unit tests
cargo test --lib

# Run tests for a specific module
cargo test --lib judge
```

**What's tested:**
- LLM response parsing
- Prompt generation
- Rule validation
- Request hashing
- Threat level logic
- Component integration (Judge, LogStore, etc.)

### 2. End-to-End Tests (18 tests)
Real-world tests with actual HTTP requests, backend, and LLM.

```bash
# Run E2E tests (requires ports 3000 & 5000 free)
make test-e2e

# Run a specific E2E test
cargo test --test e2e_tests test_sqli_classic_tautology -- --ignored --nocapture
```

**Architecture:**
```
Test Client → WAF (port 5000) → Backend (port 3000)
                ↓
              Ollama LLM
```

**What's tested:**

#### 🔴 Attacks (must be blocked - 403)
- **SQL Injection** (4 tests): `' OR '1'='1`, `UNION SELECT`, `DROP TABLE`
- **XSS** (3 tests): `<script>`, `onerror`, `javascript:`
- **Path Traversal** (2 tests): `../../etc/passwd`
- **Command Injection** (3 tests): `;`, `|`, `` ` ``

#### 🟢 Legitimate Requests (must pass - 200)
- Normal GET requests
- GET with query params
- POST with JSON
- Search queries

#### 🔵 Edge Cases
- Health endpoint
- Empty requests

## Running All Tests

```bash
# Quick: unit tests only (< 1 second)
cargo test

# Full: including E2E (~4 minutes with LLM)
make test && make test-e2e
```

## Writing Tests

### Unit Test Example

```rust
#[tokio::test]
async fn test_parse_judge_response() {
    let json = r#"{"decision":"block","confidence":0.95,"reason":"SQL injection"}"#;
    let result = parse_response(json).unwrap();
    
    assert!(matches!(result, JudgeDecision::Block { .. }));
    assert_eq!(result.confidence(), 0.95);
}
```

### E2E Test Example

```rust
#[tokio::test]
#[ignore]  // Always mark E2E tests with #[ignore]
async fn test_xss_is_blocked() {
    let env = TestEnvironment::setup().await.unwrap();
    
    let response = env.get("/search?q=<script>alert('xss')</script>")
        .await
        .unwrap();
    
    assert_eq!(response.status(), 403);
}
```

## Test Configuration

**E2E Test Settings** (`tests/e2e_tests.rs`):
- `WAF_PORT`: 5000
- `BACKEND_PORT`: 3000
- `STARTUP_WAIT`: 5 seconds
- `REQUEST_TIMEOUT`: 35 seconds (must be > `judge_timeout_ms`)

**Important:**
- E2E tests run sequentially (`--test-threads=1`) to avoid port conflicts
- All E2E tests are marked `#[ignore]` and run explicitly
- Tests automatically start/stop backend and WAF processes

## Debugging Tests

### Enable Logging

```bash
# Debug level
RUST_LOG=debug cargo test -- --nocapture

# Trace level (includes LLM prompts/responses)
RUST_LOG=trace cargo test -- --nocapture
```

### Run Single Test

```bash
# Unit test
cargo test --lib test_parse_judge_response -- --nocapture

# E2E test
cargo test --test e2e_tests test_sqli_classic_tautology -- --ignored --nocapture
```

### Manual E2E Testing

```bash
# Terminal 1: Start backend
make backend

# Terminal 2: Start WAF
make dev-trace

# Terminal 3: Test manually
curl "http://localhost:5000/users?id=1' OR '1'='1"
```

## CI/CD

Tests are run automatically on:
- Every push (unit tests)
- Pull requests (unit tests)
- Release tags (all tests including E2E)

## Test Metrics

Current status:
- **Unit tests**: 14 passing ✅
- **E2E tests**: 18 passing ✅
- **Total**: 32 tests

Coverage goals:
- Overall: > 80%
- Business logic: > 90%
- Security code: 100%

## Troubleshooting

### "Address already in use"
```bash
# Kill existing processes on ports 3000 and 5000
lsof -ti:3000 | xargs kill -9
lsof -ti:5000 | xargs kill -9
```

### "Connection refused" in E2E tests
- Increase `STARTUP_WAIT` in `tests/e2e_tests.rs`
- Check Ollama is running: `curl http://localhost:11434/api/tags`

### E2E tests timing out
- Increase `judge_timeout_ms` in `config.yaml`
- Use a smaller/faster LLM model

## Best Practices

✅ **DO:**
- Write tests for every new feature
- Use descriptive test names
- Test both success and error cases
- Keep tests independent and isolated

❌ **DON'T:**
- Skip failing tests
- Test implementation details
- Create interdependent tests
- Commit commented-out tests

---

For more details, see [CONTRIBUTING.md](../CONTRIBUTING.md).

