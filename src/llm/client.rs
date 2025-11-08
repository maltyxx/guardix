use crate::core::rulebook::Rulebook;
use crate::models::decision::{JudgeDecision, LearnerOutput};
use crate::models::request::{LogEntry, RequestPayload};
use anyhow::Result;
use async_trait::async_trait;

/// Trait for LLM providers that can judge requests and learn rules.
/// This abstraction allows swapping between different LLM providers (Ollama, OpenAI, etc.)
/// and makes testing easier with mock implementations.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Evaluate a single request and return a decision.
    /// Used by the Judge service for real-time request evaluation.
    ///
    /// # Arguments
    /// * `payload` - The normalized request payload
    /// * `rules` - The current rulebook
    ///
    /// # Returns
    /// A `JudgeDecision` (Allow, Flag, or Block)
    async fn judge_request(
        &self,
        payload: &RequestPayload,
        rules: &Rulebook,
    ) -> Result<JudgeDecision>;

    /// Analyze flagged requests and generate new rules or modify existing ones.
    /// Used by the Learner service in batch mode.
    ///
    /// # Arguments
    /// * `flagged_logs` - Recent flagged events
    /// * `current_rules` - The current rulebook
    ///
    /// # Returns
    /// A `LearnerOutput` with suggested rule changes
    async fn learn_rules(
        &self,
        flagged_logs: Vec<LogEntry>,
        current_rules: &Rulebook,
    ) -> Result<LearnerOutput>;

    /// Health check for the LLM provider
    async fn health_check(&self) -> Result<()>;
}

/// Mock LLM provider for testing (unit tests + integration tests)
/// Compiled in all builds for simplicity, but only used in tests.
#[allow(dead_code)] // Used in unit and integration tests
pub mod mock {
    use super::*;
    use crate::models::decision::ThreatLevel;

    /// Mock LLM provider for testing
    #[allow(dead_code)] // Used in tests
    pub struct MockLlmProvider {
        should_block: bool,
    }

    #[allow(dead_code)] // Used in tests
    impl Default for MockLlmProvider {
        fn default() -> Self {
            Self::new()
        }
    }

    #[allow(dead_code)] // Used in tests
    impl MockLlmProvider {
        pub fn new() -> Self {
            Self {
                should_block: false,
            }
        }

        pub fn with_block(mut self) -> Self {
            self.should_block = true;
            self
        }
    }

    #[async_trait]
    impl LlmProvider for MockLlmProvider {
        async fn judge_request(
            &self,
            _payload: &RequestPayload,
            _rules: &Rulebook,
        ) -> Result<JudgeDecision> {
            if self.should_block {
                Ok(JudgeDecision::Block {
                    confidence: 0.9,
                    reason: "Mock block".to_string(),
                    threat_level: ThreatLevel::High,
                })
            } else {
                Ok(JudgeDecision::Allow { confidence: 0.5 })
            }
        }

        async fn learn_rules(
            &self,
            _flagged_logs: Vec<LogEntry>,
            _current_rules: &Rulebook,
        ) -> Result<LearnerOutput> {
            Ok(LearnerOutput {
                new_rules: vec![],
                weaken_rules: vec![],
                remove_rules: vec![],
                rationales: vec!["Mock learner output".to_string()],
            })
        }

        async fn health_check(&self) -> Result<()> {
            Ok(())
        }
    }
}
