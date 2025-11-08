// Guardix - AI-Powered WAF that learns
// Copyright (c) 2025 Yoann Vanitou
// Licensed under the MIT License

mod config;
mod core;
mod http;
mod llm;
mod models;
mod storage;

use anyhow::{Context, Result};
use axum::{middleware, routing::get, Router};
use config::Config;
use core::{judge::Judge, learner::Learner, rulebook::Rulebook};
use http::{
    middleware::tracing_middleware,
    proxy::{health_handler, proxy_handler, AppState},
};
use llm::{client::LlmProvider, ollama::OllamaProvider};
use std::sync::Arc;
use storage::{cache::RedisCache, logs::LogStore, rules::RulebookStore};
use tokio::sync::RwLock;
use tower_http::timeout::TimeoutLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "guardix=info,tower_http=debug,axum::rejection=trace".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("🛡️ Guardix - AI-Powered WAF that learns");

    // Load configuration
    let config = Config::from_file("config.yaml").with_context(|| "Failed to load config.yaml")?;

    tracing::info!("Configuration loaded");

    // Initialize storage components
    tracing::info!("Initializing storage...");

    let logs = Arc::new(
        LogStore::new(&config.storage.logs_db_path)
            .await
            .with_context(|| "Failed to initialize log store")?,
    );
    tracing::info!("✓ Log store initialized");

    let rules_store = Arc::new(
        RulebookStore::new(&config.storage.rulebook_path)
            .with_context(|| "Failed to initialize rulebook store")?,
    );
    tracing::info!("✓ Rulebook store initialized");

    let cache = if config.cache.enabled {
        let cache = RedisCache::new(&config.cache.redis_url, config.cache.ttl())
            .await
            .with_context(|| "Failed to connect to Redis")?;

        // Test connection
        cache.ping().await.with_context(|| "Redis ping failed")?;

        tracing::info!("✓ Redis cache initialized");
        Some(Arc::new(cache))
    } else {
        tracing::info!("Cache disabled");
        None
    };

    // Initialize LLM provider
    tracing::info!("Initializing LLM provider...");
    let llm = Arc::new(
        OllamaProvider::new(&config.llm).with_context(|| "Failed to create Ollama provider")?,
    );

    // Health check LLM
    match llm.health_check().await {
        Ok(_) => tracing::info!("✓ LLM provider connected"),
        Err(e) => {
            tracing::warn!("LLM health check failed: {}. Continuing anyway...", e);
        }
    }

    // Load or create initial rulebook
    let rulebook = rules_store.load().await.unwrap_or_else(|_| {
        tracing::warn!("Failed to load rulebook, creating new one");
        Rulebook::default()
    });
    tracing::info!("Loaded rulebook with {} rules", rulebook.rules.len());

    let rulebook = Arc::new(RwLock::new(rulebook));

    // Initialize Judge
    let judge = Arc::new(Judge::new(
        llm.clone(),
        cache,
        Arc::clone(&rulebook),
        config.llm.judge_timeout(),
        config.waf.fail_mode.clone(),
    ));
    tracing::info!("✓ Judge service initialized");

    // Initialize Learner
    if config.learner.enabled {
        let learner = Arc::new(Learner::new(
            llm.clone(),
            Arc::clone(&logs),
            Arc::clone(&rules_store),
            config.learner.batch_interval(),
            config.learner.min_flagged_requests,
        ));
        tracing::info!("✓ Learner service initialized");

        // Start learner scheduler
        tokio::spawn(learner.start_scheduler());
        tracing::info!(
            "✓ Learner scheduler started (interval: {:?})",
            config.learner.batch_interval()
        );
    } else {
        tracing::info!("Learner disabled");
    }

    // Setup hot-reload watcher
    let rulebook_for_watcher = Arc::clone(&rulebook);
    let rules_store_for_watcher = Arc::clone(&rules_store);
    tokio::spawn(async move {
        match rules_store_for_watcher.watch() {
            Ok(mut rx) => {
                tracing::info!("✓ Rulebook hot-reload watcher started");
                while let Some(result) = rx.recv().await {
                    match result {
                        Ok(new_rulebook) => {
                            let mut rb = rulebook_for_watcher.write().await;
                            *rb = new_rulebook.clone();
                            tracing::info!(
                                "🔄 Rulebook hot-reloaded: {} rules (version {})",
                                new_rulebook.rules.len(),
                                new_rulebook.version
                            );
                        }
                        Err(e) => {
                            tracing::error!("Failed to reload rulebook: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to start rulebook watcher: {}", e);
            }
        }
    });

    // Build application state
    let app_state = AppState::new(
        Arc::clone(&judge),
        Arc::clone(&logs),
        config.waf.upstream_url.clone(),
    );

    // Build Axum router
    let app = Router::new()
        .route("/health", get(health_handler))
        .fallback(proxy_handler)
        .layer(middleware::from_fn(tracing_middleware))
        .layer(TimeoutLayer::new(config.waf.request_timeout()))
        .with_state(app_state);

    // Start server
    let listener = tokio::net::TcpListener::bind(&config.waf.listen_addr)
        .await
        .with_context(|| format!("Failed to bind to {}", config.waf.listen_addr))?;

    tracing::info!("🚀 WAF listening on {}", config.waf.listen_addr);
    tracing::info!("   Upstream: {}", config.waf.upstream_url);
    tracing::info!("   Health check: http://{}/health", config.waf.listen_addr);

    axum::serve(listener, app)
        .await
        .with_context(|| "Server error")?;

    Ok(())
}
