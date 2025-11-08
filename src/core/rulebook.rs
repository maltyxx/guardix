use crate::models::decision::RuleAction;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rulebook {
    pub version: u64,
    pub updated_at: DateTime<Utc>,
    pub rules: Vec<Rule>,
}

impl Default for Rulebook {
    fn default() -> Self {
        Self {
            version: 1,
            updated_at: Utc::now(),
            rules: Vec::new(),
        }
    }
}

impl Rulebook {
    /// Creates a new empty rulebook
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
        self.version += 1;
        self.updated_at = Utc::now();
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let initial_len = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);
        let removed = self.rules.len() < initial_len;
        if removed {
            self.version += 1;
            self.updated_at = Utc::now();
        }
        removed
    }

    /// Retrieves a specific rule by ID - used for rule inspection/debugging
    #[allow(dead_code)]
    pub fn get_rule(&self, rule_id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == rule_id)
    }

    /// Filters rules by threat type - used for analytics and reporting
    #[allow(dead_code)]
    pub fn get_rules_by_type(&self, threat_type: &str) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| r.threat_type == threat_type)
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub pattern: String,
    pub threat_type: String,
    pub confidence: f32,
    pub action: RuleAction,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Rule {
    pub fn new(
        pattern: String,
        threat_type: String,
        confidence: f32,
        action: RuleAction,
        created_by: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            pattern,
            threat_type,
            confidence,
            action,
            created_by,
            created_at: Utc::now(),
            description: None,
        }
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }
}
