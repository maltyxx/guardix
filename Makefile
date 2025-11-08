.PHONY: help build run test check fmt clippy clean dev backend test-e2e

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the project
	cargo build

build-release: ## Build in optimized release mode
	cargo build --release

run: ## Run the WAF
	cargo run

test: ## Run all tests
	cargo test

test-verbose: ## Run tests with detailed logs
	RUST_LOG=debug cargo test -- --nocapture

test-cov: ## Show test coverage percentage
	cargo llvm-cov --lib --summary-only

check: ## Check compilation without building binaries
	cargo check

sqlx-prepare: ## Regenerate SQLx cache for offline mode
	@echo "Creating temporary database for SQLx..."
	@sqlite3 /tmp/guardix_sqlx.db < migrations/001_initial.sql
	@DATABASE_URL="sqlite:///tmp/guardix_sqlx.db" cargo sqlx prepare
	@rm -f /tmp/guardix_sqlx.db
	@echo "✓ SQLx cache updated in .sqlx/ (commit to git)"

fmt: ## Format code
	cargo fmt

clippy: ## Run linter
	cargo clippy -- -D warnings -A dead_code

clean: ## Clean build artifacts
	cargo clean
	rm -rf data/*.db data/*.db-*

dev: ## Development mode with auto-reload
	cargo watch -x run

dev-debug: ## Dev mode with DEBUG logs for LLM (prompt + Ollama response)
	RUST_LOG=guardix::llm::debug=debug,guardix=info cargo watch -x run

dev-trace: ## Dev mode with TRACE logs for LLM (full exchange content)
	RUST_LOG=guardix::llm::debug=trace,guardix=debug cargo watch -x run

backend: ## Start test backend (displays all request info)
	@echo "🎯 Starting test backend on http://localhost:3000"
	@echo "📋 Displays all received request information"
	@echo ""
	cargo run --example test_backend

test-e2e: ## End-to-End tests (WAF + Backend in real conditions)
	@echo "🚀 Launching E2E tests..."
	@echo "⚠️  Make sure no service is running on ports 3000 and 5000"
	@echo ""
	cargo test --test e2e_tests -- --ignored --test-threads=1 --nocapture

logs: ## Display recent SQLite logs
	@sqlite3 data/logs.db "SELECT datetime(timestamp, 'unixepoch', 'localtime') as time, method, path, decision, confidence, reason FROM events ORDER BY timestamp DESC LIMIT 20;" 2>/dev/null || echo "No logs yet (run WAF first)"

rulebook: ## Display current rulebook
	@cat data/rulebook.json 2>/dev/null | jq . || echo "No rulebook yet (run WAF first)"

stats: ## Event statistics
	@sqlite3 data/logs.db "SELECT decision, COUNT(*) as count FROM events GROUP BY decision;" 2>/dev/null || echo "No stats yet"

ollama-models: ## List available Ollama models
	@echo "📋 Available Ollama models:"
	@curl -s http://host.docker.internal:11434/api/tags | jq -r '.models[].name' 2>/dev/null || echo "❌ Ollama not accessible"

setup: ## Initial project setup
	@bash .devcontainer/setup.sh || echo "Run from dev container"

