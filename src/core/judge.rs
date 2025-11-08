use crate::config::FailMode;
use crate::core::rulebook::Rulebook;
use crate::llm::client::LlmProvider;
use crate::models::decision::{JudgeDecision, ThreatLevel};
use crate::models::request::RequestPayload;
use crate::storage::cache::RedisCache;
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::timeout;

/// The Judge service is responsible for real-time request evaluation.
/// It uses a cache-aside pattern with Redis and falls back to LLM evaluation.
/// In case of errors or timeouts, behavior depends on the configured fail_mode (open or closed).
pub struct Judge {
    llm: Arc<dyn LlmProvider>,
    cache: Option<Arc<RedisCache>>,
    rulebook: Arc<RwLock<Rulebook>>,
    timeout_duration: Duration,
    fail_mode: FailMode,
    metrics: JudgeMetrics,
}

#[derive(Default, Clone)]
pub struct JudgeMetrics {
    pub total_requests: Arc<std::sync::atomic::AtomicU64>,
    pub cache_hits: Arc<std::sync::atomic::AtomicU64>,
    pub cache_misses: Arc<std::sync::atomic::AtomicU64>,
    pub llm_timeouts: Arc<std::sync::atomic::AtomicU64>,
    pub llm_errors: Arc<std::sync::atomic::AtomicU64>,
    pub fail_open_count: Arc<std::sync::atomic::AtomicU64>,
    pub fail_closed_count: Arc<std::sync::atomic::AtomicU64>,
}

impl Judge {
    pub fn new(
        llm: Arc<dyn LlmProvider>,
        cache: Option<Arc<RedisCache>>,
        rulebook: Arc<RwLock<Rulebook>>,
        timeout_duration: Duration,
        fail_mode: FailMode,
    ) -> Self {
        Self {
            llm,
            cache,
            rulebook,
            timeout_duration,
            fail_mode,
            metrics: JudgeMetrics::default(),
        }
    }

    /// Evaluate a request and return a decision.
    /// This is the main entry point for request evaluation.
    ///
    /// Flow:
    /// 1. Check cache for existing verdict
    /// 2. If cache miss, call LLM with timeout
    /// 3. Cache the result (if cache enabled)
    /// 4. On error/timeout: behavior depends on fail_mode (open: allow, closed: block)
    pub async fn evaluate(&self, payload: RequestPayload) -> JudgeDecision {
        use std::sync::atomic::Ordering;

        self.metrics.total_requests.fetch_add(1, Ordering::Relaxed);

        // Step 1: Check cache
        if let Some(ref cache) = self.cache {
            match cache.get_verdict(&payload.normalized_hash).await {
                Ok(Some(cached_decision)) => {
                    self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        hash = %payload.normalized_hash,
                        decision = ?cached_decision.decision_type(),
                        "Cache hit"
                    );
                    return cached_decision;
                }
                Ok(None) => {
                    self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Cache lookup failed");
                }
            }
        }

        // Step 2: Call LLM with timeout
        let decision = self.call_llm_with_timeout(&payload).await;

        // Step 3: Cache the result
        if let Some(ref cache) = self.cache {
            if let Ok(ref dec) = decision {
                if let Err(e) = cache.set_verdict(&payload.normalized_hash, dec).await {
                    tracing::warn!(error = %e, "Failed to cache verdict");
                }
            }
        }

        // Step 4: Handle result or apply fail mode
        match decision {
            Ok(dec) => {
                tracing::info!(
                    method = %payload.method,
                    path = %payload.path,
                    decision = ?dec.decision_type(),
                    confidence = dec.confidence(),
                    "Request evaluated"
                );
                dec
            }
            Err(e) => {
                match self.fail_mode {
                    FailMode::Open => {
                        tracing::warn!(
                            error = %e,
                            method = %payload.method,
                            path = %payload.path,
                            "LLM evaluation failed, failing open (allowing request)"
                        );
                        self.metrics.fail_open_count.fetch_add(1, Ordering::Relaxed);
                        JudgeDecision::Allow { confidence: 0.0 }
                    }
                    FailMode::Closed => {
                        tracing::warn!(
                            error = %e,
                            method = %payload.method,
                            path = %payload.path,
                            "LLM evaluation failed, failing closed (blocking request)"
                        );
                        self.metrics.fail_closed_count.fetch_add(1, Ordering::Relaxed);
                        JudgeDecision::Block {
                            confidence: 0.0,
                            reason: "LLM evaluation failed".to_string(),
                            threat_level: ThreatLevel::Medium,
                        }
                    }
                }
            }
        }
    }

    async fn call_llm_with_timeout(&self, payload: &RequestPayload) -> Result<JudgeDecision> {
        use std::sync::atomic::Ordering;

        let rulebook = self.rulebook.read().await;

        let result = timeout(self.timeout_duration, async {
            self.llm.judge_request(payload, &rulebook).await
        })
        .await;

        match result {
            Ok(Ok(decision)) => Ok(decision),
            Ok(Err(e)) => {
                self.metrics.llm_errors.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
            Err(_) => {
                self.metrics.llm_timeouts.fetch_add(1, Ordering::Relaxed);
                anyhow::bail!("LLM timeout after {:?}", self.timeout_duration)
            }
        }
    }

    /// Returns metrics for monitoring and observability endpoints
    #[allow(dead_code)]
    pub fn metrics(&self) -> &JudgeMetrics {
        &self.metrics
    }

    /// Update the rulebook reference (used by hot-reload)
    #[allow(dead_code)]
    pub fn update_rulebook(&self, new_rulebook: Rulebook) -> tokio::task::JoinHandle<()> {
        let rulebook = Arc::clone(&self.rulebook);
        tokio::spawn(async move {
            let mut rb = rulebook.write().await;
            *rb = new_rulebook;
            tracing::info!("Rulebook updated with {} rules", rb.rules.len());
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::client::mock::MockLlmProvider;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_judge_with_mock_llm() {
        let llm = Arc::new(MockLlmProvider::new());
        let rulebook = Arc::new(RwLock::new(Rulebook::new()));
        let judge = Judge::new(llm, None, rulebook, Duration::from_secs(1), FailMode::Open);

        let payload = RequestPayload::new(
            "GET".to_string(),
            "/test".to_string(),
            HashMap::new(),
            None,
            HashMap::new(),
            Some("127.0.0.1".to_string()),
        );

        let decision = judge.evaluate(payload).await;
        assert!(matches!(decision, JudgeDecision::Allow { .. }));
    }

    #[tokio::test]
    async fn test_judge_block_decision() {
        let llm = Arc::new(MockLlmProvider::new().with_block());
        let rulebook = Arc::new(RwLock::new(Rulebook::new()));
        let judge = Judge::new(llm, None, rulebook, Duration::from_secs(1), FailMode::Open);

        let payload = RequestPayload::new(
            "GET".to_string(),
            "/admin".to_string(),
            HashMap::new(),
            Some("'; DROP TABLE users--".to_string()),
            HashMap::new(),
            None,
        );

        let decision = judge.evaluate(payload).await;
        assert!(decision.is_block());
    }

    #[tokio::test]
    async fn test_metrics_tracking() {
        use std::sync::atomic::Ordering;

        let llm = Arc::new(MockLlmProvider::new());
        let rulebook = Arc::new(RwLock::new(Rulebook::new()));
        let judge = Judge::new(llm, None, rulebook, Duration::from_secs(1), FailMode::Open);

        let payload = RequestPayload::new(
            "GET".to_string(),
            "/test".to_string(),
            HashMap::new(),
            None,
            HashMap::new(),
            None,
        );

        judge.evaluate(payload).await;

        assert_eq!(judge.metrics().total_requests.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_fail_mode_open() {
        use std::sync::atomic::Ordering;

        // Mock LLM that always fails
        let llm = Arc::new(MockLlmProvider::new().with_error());
        let rulebook = Arc::new(RwLock::new(Rulebook::new()));
        let judge = Judge::new(llm, None, rulebook, Duration::from_secs(1), FailMode::Open);

        let payload = RequestPayload::new(
            "GET".to_string(),
            "/test".to_string(),
            HashMap::new(),
            None,
            HashMap::new(),
            None,
        );

        let decision = judge.evaluate(payload).await;
        assert!(matches!(decision, JudgeDecision::Allow { confidence: 0.0 }));
        assert_eq!(judge.metrics().fail_open_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_fail_mode_closed() {
        use std::sync::atomic::Ordering;

        // Mock LLM that always fails
        let llm = Arc::new(MockLlmProvider::new().with_error());
        let rulebook = Arc::new(RwLock::new(Rulebook::new()));
        let judge = Judge::new(llm, None, rulebook, Duration::from_secs(1), FailMode::Closed);

        let payload = RequestPayload::new(
            "GET".to_string(),
            "/test".to_string(),
            HashMap::new(),
            None,
            HashMap::new(),
            None,
        );

        let decision = judge.evaluate(payload).await;
        assert!(decision.is_block());
        assert_eq!(judge.metrics().fail_closed_count.load(Ordering::Relaxed), 1);
    }
}
