#!/bin/bash
set -e

echo "🦀 Setting up Guardix
 development environment..."

# Ensure we're in the workspace directory
cd /workspace

# Create data directories
echo "📁 Creating data directories..."
mkdir -p data
chmod 755 data

# Create initial empty rulebook if it doesn't exist
if [ ! -f data/rulebook.json ]; then
    echo "📋 Creating initial rulebook..."
    cat > data/rulebook.json <<EOF
{
  "version": 1,
  "updated_at": "$(date -Iseconds)",
  "rules": []
}
EOF
fi

# Create default config if not exists
if [ ! -f config.yaml ]; then
    echo "⚙️  Creating default config..."
    if [ -f config.yaml.example ]; then
        cp config.yaml.example config.yaml
        echo "✓ Config created from config.yaml.example"
    else
        echo "❌ Error: config.yaml.example not found"
        exit 1
    fi
fi

# Wait for Redis to be available
echo "⏳ Waiting for Redis..."
timeout 30 sh -c 'until redis-cli -h cache ping 2>/dev/null | grep -q PONG; do sleep 1; done' && echo "✅ Redis is ready" || echo "⚠️  Redis not available (will start with project)"

# Check Ollama availability
echo "🤖 Checking Ollama..."
if curl -s http://host.docker.internal:11434/api/tags >/dev/null 2>&1; then
    echo "✅ Ollama is available"
else
    echo "⚠️  Ollama not detected on host.docker.internal:11434"
    echo "   Please ensure Ollama is running on your host machine with:"
    echo "   $ ollama pull llama3.2"
fi

# Install/update Rust dependencies
if [ -f Cargo.toml ]; then
    echo "📦 Fetching Rust dependencies..."
    cargo fetch || true
    echo "✅ Dependencies cached"
fi

# Run database migrations if they exist
if [ -d migrations ]; then
    echo "🗄️  Running database migrations..."
    sqlx database create --database-url sqlite:./data/logs.db 2>/dev/null || true
    sqlx migrate run --database-url sqlite:./data/logs.db || true
    echo "✅ Database initialized"
fi

echo ""
echo "✅ Development environment ready!"
echo ""
echo "🚀 Quick start (using Make):"
echo "  make dev            # Dev mode with hot-reload (recommended)"
echo "  make build          # Build project"
echo "  make run            # Start WAF"
echo "  make test           # Run tests"
echo "  make clippy         # Lint code"
echo "  make fmt            # Format code"
echo "  make help           # See all available commands"
echo ""
echo "📚 Or use Cargo directly:"
echo "  cargo build         # Build project"
echo "  cargo run           # Start WAF"
echo "  cargo test          # Run tests"
echo ""
echo "🌐 WAF will be available at: http://localhost:5000"
echo "💚 Health check: http://localhost:5000/health"

