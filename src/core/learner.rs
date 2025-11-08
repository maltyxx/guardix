use crate::core::rulebook::{Rule, Rulebook};
use crate::llm::client::LlmProvider;
use crate::models::decision::LearnerOutput;
use crate::storage::logs::LogStore;
use crate::storage::rules::RulebookStore;
use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::interval;

/// The Learner service runs periodically in batch mode to analyze flagged requests
/// and generate new rules or modify existing ones based on observed patterns.
pub struct Learner {
    llm: Arc<dyn LlmProvider>,
    logs: Arc<LogStore>,
    rules_store: Arc<RulebookStore>,
    batch_interval: Duration,
    min_flagged_requests: usize,
    last_run_timestamp: std::sync::Arc<std::sync::RwLock<i64>>,
}

impl Learner {
    pub fn new(
        llm: Arc<dyn LlmProvider>,
        logs: Arc<LogStore>,
        rules_store: Arc<RulebookStore>,
        batch_interval: Duration,
        min_flagged_requests: usize,
    ) -> Self {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Self {
            llm,
            logs,
            rules_store,
            batch_interval,
            min_flagged_requests,
            last_run_timestamp: Arc::new(std::sync::RwLock::new(current_time)),
        }
    }

    /// Run a single batch learning cycle
    pub async fn run_batch(&self) -> Result<()> {
        tracing::info!("Starting learner batch");

        // Step 1: Get the timestamp of last run
        let last_run = {
            let timestamp = self.last_run_timestamp.read().unwrap();
            *timestamp
        };

        // Step 2: Fetch flagged events since last run
        let flagged = self
            .logs
            .get_flagged_since(last_run)
            .await
            .with_context(|| "Failed to fetch flagged events")?;

        tracing::info!("Found {} flagged requests since last run", flagged.len());

        // Step 3: Check if we have enough data
        if flagged.len() < self.min_flagged_requests {
            tracing::info!(
                "Not enough flagged requests ({} < {}), skipping batch",
                flagged.len(),
                self.min_flagged_requests
            );
            return Ok(());
        }

        // Step 4: Load current rulebook
        let current_rules = self
            .rules_store
            .load()
            .await
            .with_context(|| "Failed to load rulebook")?;

        tracing::info!("Current rulebook has {} rules", current_rules.rules.len());

        // Step 5: Call LLM learner
        let output = self
            .llm
            .learn_rules(flagged, &current_rules)
            .await
            .with_context(|| "Failed to learn rules from LLM")?;

        tracing::info!(
            "LLM suggested {} new rules, {} rules to weaken, {} rules to remove",
            output.new_rules.len(),
            output.weaken_rules.len(),
            output.remove_rules.len()
        );

        // Step 6: Apply changes to rulebook
        let new_rulebook = self.apply_changes(&current_rules, &output)?;

        // Step 7: Save updated rulebook
        self.rules_store
            .save(&new_rulebook)
            .await
            .with_context(|| "Failed to save rulebook")?;

        tracing::info!(
            "Rulebook updated: {} rules (was {})",
            new_rulebook.rules.len(),
            current_rules.rules.len()
        );

        // Log rationales
        for rationale in &output.rationales {
            tracing::info!("Learner rationale: {}", rationale);
        }

        // Step 8: Update last run timestamp
        {
            let mut timestamp = self.last_run_timestamp.write().unwrap();
            *timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
        }

        Ok(())
    }

    /// Apply learner output to current rulebook
    fn apply_changes(&self, current_rules: &Rulebook, output: &LearnerOutput) -> Result<Rulebook> {
        let mut new_rulebook = current_rules.clone();

        // Remove rules
        for rule_id in &output.remove_rules {
            if new_rulebook.remove_rule(rule_id) {
                tracing::info!("Removed rule: {}", rule_id);
            }
        }

        // Weaken rules (reduce confidence)
        for rule_id in &output.weaken_rules {
            if let Some(rule) = new_rulebook.rules.iter_mut().find(|r| r.id == *rule_id) {
                let old_confidence = rule.confidence;
                rule.confidence = (rule.confidence * 0.8).max(0.3); // Reduce by 20%, min 0.3
                tracing::info!(
                    "Weakened rule {}: confidence {} -> {}",
                    rule_id,
                    old_confidence,
                    rule.confidence
                );
            }
        }

        // Add new rules
        for suggestion in &output.new_rules {
            let rule = Rule::new(
                suggestion.pattern.clone(),
                suggestion.threat_type.clone(),
                suggestion.confidence,
                suggestion.action,
                "llm".to_string(),
            )
            .with_description(suggestion.description.clone());

            tracing::info!(
                "Adding new rule: {} ({}) - action: {}",
                rule.threat_type,
                rule.pattern,
                rule.action.as_str()
            );

            new_rulebook.add_rule(rule);
        }

        Ok(new_rulebook)
    }

    /// Start the scheduler that runs batch learning at regular intervals
    pub async fn start_scheduler(self: Arc<Self>) {
        let mut ticker = interval(self.batch_interval);

        tracing::info!(
            "Learner scheduler started with interval: {:?}",
            self.batch_interval
        );

        loop {
            ticker.tick().await;

            tracing::debug!("Learner tick");

            if let Err(e) = self.run_batch().await {
                tracing::error!(error = %e, "Learner batch failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::client::mock::MockLlmProvider;
    use crate::models::decision::{RuleAction, RuleSuggestion};

    #[tokio::test]
    async fn test_learner_applies_changes() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("logs.db");
        let rulebook_path = temp_dir.path().join("rulebook.json");

        let logs = Arc::new(LogStore::new(&db_path).await.unwrap());
        let rules_store = Arc::new(RulebookStore::new(&rulebook_path).unwrap());
        let llm = Arc::new(MockLlmProvider::new());

        let learner = Learner::new(llm, logs, rules_store.clone(), Duration::from_secs(60), 1);

        // Create initial rulebook
        let mut initial_rulebook = Rulebook::new();
        initial_rulebook.add_rule(Rule::new(
            "test".to_string(),
            "xss".to_string(),
            0.9,
            RuleAction::Block,
            "manual".to_string(),
        ));

        // Create output with changes
        let output = LearnerOutput {
            new_rules: vec![RuleSuggestion {
                pattern: "SELECT.*FROM".to_string(),
                threat_type: "sqli".to_string(),
                description: "SQL injection pattern".to_string(),
                confidence: 0.85,
                action: RuleAction::Block,
            }],
            weaken_rules: vec![],
            remove_rules: vec![],
            rationales: vec!["Added SQLi rule".to_string()],
        };

        let new_rulebook = learner.apply_changes(&initial_rulebook, &output).unwrap();

        assert_eq!(new_rulebook.rules.len(), 2);
        assert!(new_rulebook.rules.iter().any(|r| r.threat_type == "sqli"));
    }
}
