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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rulebook_new() {
        let rulebook = Rulebook::new();
        assert_eq!(rulebook.version, 1);
        assert_eq!(rulebook.rules.len(), 0);
    }

    #[test]
    fn test_rulebook_default() {
        let rulebook = Rulebook::default();
        assert_eq!(rulebook.version, 1);
        assert_eq!(rulebook.rules.len(), 0);
    }

    #[test]
    fn test_add_rule() {
        let mut rulebook = Rulebook::new();
        let initial_version = rulebook.version;

        let rule = Rule::new(
            "SELECT.*FROM".to_string(),
            "sqli".to_string(),
            0.9,
            RuleAction::Block,
            "admin".to_string(),
        );

        rulebook.add_rule(rule);

        assert_eq!(rulebook.rules.len(), 1);
        assert_eq!(rulebook.version, initial_version + 1);
        assert_eq!(rulebook.rules[0].threat_type, "sqli");
    }

    #[test]
    fn test_add_multiple_rules() {
        let mut rulebook = Rulebook::new();

        for i in 0..3 {
            let rule = Rule::new(
                format!("pattern_{}", i),
                format!("type_{}", i),
                0.8,
                RuleAction::Flag,
                "system".to_string(),
            );
            rulebook.add_rule(rule);
        }

        assert_eq!(rulebook.rules.len(), 3);
        assert_eq!(rulebook.version, 4); // Initial 1 + 3 additions
    }

    #[test]
    fn test_remove_rule() {
        let mut rulebook = Rulebook::new();

        let rule = Rule::new(
            "test".to_string(),
            "xss".to_string(),
            0.7,
            RuleAction::Block,
            "admin".to_string(),
        );
        let rule_id = rule.id.clone();
        rulebook.add_rule(rule);

        assert_eq!(rulebook.rules.len(), 1);

        let removed = rulebook.remove_rule(&rule_id);
        assert!(removed);
        assert_eq!(rulebook.rules.len(), 0);
    }

    #[test]
    fn test_remove_nonexistent_rule() {
        let mut rulebook = Rulebook::new();

        let rule = Rule::new(
            "test".to_string(),
            "xss".to_string(),
            0.7,
            RuleAction::Block,
            "admin".to_string(),
        );
        rulebook.add_rule(rule);

        let removed = rulebook.remove_rule("nonexistent-id");
        assert!(!removed);
        assert_eq!(rulebook.rules.len(), 1);
    }

    #[test]
    fn test_get_rule() {
        let mut rulebook = Rulebook::new();

        let rule = Rule::new(
            "pattern1".to_string(),
            "sqli".to_string(),
            0.95,
            RuleAction::Block,
            "system".to_string(),
        );
        let rule_id = rule.id.clone();
        rulebook.add_rule(rule);

        let found = rulebook.get_rule(&rule_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().pattern, "pattern1");
    }

    #[test]
    fn test_get_nonexistent_rule() {
        let rulebook = Rulebook::new();
        let found = rulebook.get_rule("nonexistent-id");
        assert!(found.is_none());
    }

    #[test]
    fn test_get_rules_by_type() {
        let mut rulebook = Rulebook::new();

        for i in 0..3 {
            let rule = Rule::new(
                format!("sqli_pattern_{}", i),
                "sqli".to_string(),
                0.8,
                RuleAction::Block,
                "system".to_string(),
            );
            rulebook.add_rule(rule);
        }

        let rule = Rule::new(
            "xss_pattern".to_string(),
            "xss".to_string(),
            0.9,
            RuleAction::Flag,
            "system".to_string(),
        );
        rulebook.add_rule(rule);

        let sqli_rules = rulebook.get_rules_by_type("sqli");
        assert_eq!(sqli_rules.len(), 3);

        let xss_rules = rulebook.get_rules_by_type("xss");
        assert_eq!(xss_rules.len(), 1);

        let nonexistent_rules = rulebook.get_rules_by_type("nonexistent");
        assert_eq!(nonexistent_rules.len(), 0);
    }

    #[test]
    fn test_rule_new() {
        let rule = Rule::new(
            "test_pattern".to_string(),
            "test_type".to_string(),
            0.85,
            RuleAction::Flag,
            "tester".to_string(),
        );

        assert!(!rule.id.is_empty());
        assert_eq!(rule.pattern, "test_pattern");
        assert_eq!(rule.threat_type, "test_type");
        assert_eq!(rule.confidence, 0.85);
        assert_eq!(rule.action, RuleAction::Flag);
        assert_eq!(rule.created_by, "tester");
        assert!(rule.description.is_none());
    }

    #[test]
    fn test_rule_with_description() {
        let rule = Rule::new(
            "pattern".to_string(),
            "type".to_string(),
            0.9,
            RuleAction::Block,
            "admin".to_string(),
        )
        .with_description("This is a test rule".to_string());

        assert_eq!(
            rule.description,
            Some("This is a test rule".to_string())
        );
    }

    #[test]
    fn test_rulebook_version_increments() {
        let mut rulebook = Rulebook::new();
        let initial_version = rulebook.version;

        let rule1 = Rule::new(
            "p1".to_string(),
            "t1".to_string(),
            0.8,
            RuleAction::Block,
            "system".to_string(),
        );
        rulebook.add_rule(rule1);
        assert_eq!(rulebook.version, initial_version + 1);

        let rule2 = Rule::new(
            "p2".to_string(),
            "t2".to_string(),
            0.7,
            RuleAction::Flag,
            "system".to_string(),
        );
        let rule2_id = rule2.id.clone();
        rulebook.add_rule(rule2);
        assert_eq!(rulebook.version, initial_version + 2);

        rulebook.remove_rule(&rule2_id);
        assert_eq!(rulebook.version, initial_version + 3);
    }

    #[test]
    fn test_rulebook_serialization() {
        let mut rulebook = Rulebook::new();
        let rule = Rule::new(
            "SELECT.*".to_string(),
            "sqli".to_string(),
            0.95,
            RuleAction::Block,
            "admin".to_string(),
        );
        rulebook.add_rule(rule);

        let json = serde_json::to_string(&rulebook).unwrap();
        let deserialized: Rulebook = serde_json::from_str(&json).unwrap();

        assert_eq!(rulebook.version, deserialized.version);
        assert_eq!(rulebook.rules.len(), deserialized.rules.len());
        assert_eq!(
            rulebook.rules[0].pattern,
            deserialized.rules[0].pattern
        );
    }

    #[test]
    fn test_rule_unique_ids() {
        let rule1 = Rule::new(
            "pattern".to_string(),
            "type".to_string(),
            0.8,
            RuleAction::Block,
            "system".to_string(),
        );

        let rule2 = Rule::new(
            "pattern".to_string(),
            "type".to_string(),
            0.8,
            RuleAction::Block,
            "system".to_string(),
        );

        assert_ne!(rule1.id, rule2.id);
    }
}
