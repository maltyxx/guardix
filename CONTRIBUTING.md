# Contributing to Guardix

Thank you for your interest in contributing to Guardix! 🛡️

**Project Author**: Yoann Vanitou ([@maltyxx](https://github.com/maltyxx))

## 📋 Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## 🚀 Getting Started

### 1. Fork and Clone

```bash
git clone https://github.com/maltyxx/guardix.git
cd guardix
```

### 2. Setup Development Environment

**Option A: Dev Container (Recommended)**
- Open in VS Code with Dev Containers extension
- Environment is automatically configured

**Option B: Local Setup**
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install tools
cargo install cargo-watch sqlx-cli --no-default-features --features sqlite

# Install Redis
# macOS: brew install redis
# Linux: apt-get install redis-server

# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull gpt-oss:20b
```

### 3. Build and Test

```bash
# Build
cargo build

# Run tests
cargo test

# Run linter
cargo clippy -- -D warnings

# Format code
cargo fmt
```

## 💻 Development Workflow

### Creating a Feature

```bash
# Create a feature branch
git checkout -b feature/my-awesome-feature

# Make changes
# ... code ...

# Run tests
cargo test

# Lint and format
cargo clippy -- -D warnings
cargo fmt

# Commit
git add .
git commit -m "feat: add awesome feature"

# Push
git push origin feature/my-awesome-feature
```

### Commit Message Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new feature
fix: bug fix
docs: documentation changes
test: add or update tests
refactor: code refactoring
perf: performance improvements
chore: maintenance tasks
```

## 📐 Code Quality Standards

### 1. No Warnings

Code must compile without warnings:

```bash
cargo clippy -- -D warnings
```

**Do NOT use** `#[allow(dead_code)]` or similar to suppress warnings. If code is unused, delete it.

### 2. SOLID Principles

**Single Responsibility**: Each module/struct does one thing well

```rust
// ✅ Good: Judge only evaluates requests
pub struct Judge {
    llm: Arc<dyn LlmProvider>,
    cache: Option<Arc<RedisCache>>,
}

// ❌ Bad: Judge shouldn't manage storage
pub struct Judge {
    llm: Arc<dyn LlmProvider>,
    database: SqliteConnection,  // ❌ Storage responsibility
}
```

**Open/Closed**: Extend via traits, not modification

```rust
// ✅ Good: Abstract via trait
pub trait LlmProvider: Send + Sync {
    async fn judge_request(&self, ...) -> Result<JudgeDecision>;
}

// Easy to add new providers without changing Judge
```

**Dependency Inversion**: Depend on abstractions, not concretions

```rust
// ✅ Good: Depend on trait
pub struct Judge {
    llm: Arc<dyn LlmProvider>,  // Abstract
}

// ❌ Bad: Depend on concrete type
pub struct Judge {
    ollama: Arc<OllamaProvider>,  // Concrete
}
```

### 3. Type Safety

Use enums instead of strings:

```rust
// ✅ Good
pub enum JudgeDecision {
    Allow { confidence: f32 },
    Flag { confidence: f32, reason: String },
    Block { confidence: f32, reason: String },
}

// ❌ Bad
pub struct Decision {
    action: String,  // "allow", "flag", "block" - stringly typed!
}
```

### 4. Error Handling

Use `Result` and `anyhow` for error propagation:

```rust
// ✅ Good
pub async fn judge_request(&self, payload: &RequestPayload) -> Result<JudgeDecision> {
    let response = self.llm.generate(prompt)
        .await
        .context("Failed to call LLM")?;  // Adds context
    // ...
}

// ❌ Bad
pub async fn judge_request(&self, payload: &RequestPayload) -> JudgeDecision {
    match self.llm.generate(prompt).await {
        Ok(resp) => resp,
        Err(_) => JudgeDecision::Allow { confidence: 0.0 },  // Silent failure!
    }
}
```

### 5. Testing

Every feature must have tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sql_injection_detection() {
        let payload = RequestPayload::new(
            "GET".to_string(),
            "/users?id=1' OR '1'='1".to_string(),
            // ...
        );
        
        let decision = judge.evaluate(payload).await;
        
        assert!(matches!(decision, JudgeDecision::Block { .. }));
    }
}
```

### 6. Documentation

Public APIs must have doc comments:

```rust
/// Evaluates an HTTP request for security threats.
///
/// # Arguments
/// * `payload` - The normalized HTTP request
///
/// # Returns
/// * `JudgeDecision::Allow` - Safe request
/// * `JudgeDecision::Flag` - Suspicious, needs review
/// * `JudgeDecision::Block` - Confirmed attack
///
/// # Errors
/// Returns `Err` if LLM call fails and fail-open applies
pub async fn evaluate(&self, payload: RequestPayload) -> JudgeDecision {
    // ...
}
```

### 7. Performance

- Use `Arc` for shared ownership
- Use `async/await` for I/O operations
- Avoid blocking operations in async contexts
- Cache expensive computations

```rust
// ✅ Good: Non-blocking
let decision = tokio::time::timeout(
    self.timeout_duration,
    self.llm.judge_request(payload)
).await??;

// ❌ Bad: Blocking in async
std::thread::sleep(Duration::from_secs(1));  // Blocks entire runtime!
```

## 🧪 Testing Guidelines

### Test Types

1. **Unit Tests**: Test individual functions
   ```bash
   cargo test --lib
   ```

2. **Integration Tests**: Test component interactions
   ```bash
   cargo test --test integration_tests
   ```

3. **E2E Tests**: Test full system with real LLM
   ```bash
   make test-e2e
   ```

### Writing Good Tests

```rust
// ✅ Good: Descriptive name, clear assertions
#[tokio::test]
async fn test_sql_injection_is_blocked_with_high_confidence() {
    let judge = setup_judge_with_ollama().await;
    let payload = create_sqli_payload("' OR '1'='1");
    
    let decision = judge.evaluate(payload).await;
    
    assert!(matches!(decision, JudgeDecision::Block { .. }));
    assert!(decision.confidence() > 0.8);
}

// ❌ Bad: Vague name, no clear purpose
#[tokio::test]
async fn test_request() {
    let j = Judge::new(llm, None, rb, Duration::from_secs(1));
    let p = RequestPayload::new("GET".to_string(), "/test".to_string(), HashMap::new(), None, HashMap::new(), None);
    let d = j.evaluate(p).await;
    assert!(true);  // What are we testing??
}
```

## 📝 Pull Request Process

1. **Update documentation** if needed
2. **Add tests** for new features
3. **Run full test suite**: `cargo test`
4. **Run linter**: `cargo clippy -- -D warnings`
5. **Format code**: `cargo fmt`
6. **Update CHANGELOG** if applicable
7. **Create PR** with clear description

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] E2E tests pass
- [ ] Manual testing performed

## Checklist
- [ ] Code follows project style
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No new warnings
```

## 🐛 Reporting Bugs

### Before Reporting

1. Check existing issues
2. Update to latest version
3. Try to reproduce consistently

### Bug Report Template

```markdown
## Bug Description
Clear description of the bug

## Steps to Reproduce
1. Step 1
2. Step 2
3. ...

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- OS: [e.g., Ubuntu 22.04]
- Rust version: [e.g., 1.75]
- Guardix version: [e.g., 0.1.0]
- LLM model: [e.g., gpt-oss:20b]

## Logs
```
Relevant logs here
```
```

## 💡 Feature Requests

We welcome feature requests! Please:

1. Search existing requests first
2. Explain the use case
3. Describe proposed solution
4. Consider implementation complexity

## 🏗️ Architecture Decisions

When making significant architectural changes:

1. **Discuss first** in an issue
2. **Document rationale** in code comments
3. **Update** `docs/ARCHITECTURE.md`
4. **Add migration guide** if breaking

## 📚 Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Async Rust](https://rust-lang.github.io/async-book/)
- [Axum Documentation](https://docs.rs/axum/)
- [SOLID Principles](https://en.wikipedia.org/wiki/SOLID)

## 🙏 Thank You!

Every contribution, no matter how small, is valuable. Thank you for helping make Guardix better!
