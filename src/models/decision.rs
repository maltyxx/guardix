use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum JudgeDecision {
    Allow {
        confidence: f32,
    },
    Flag {
        confidence: f32,
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        suggested_rule: Option<String>,
    },
    Block {
        confidence: f32,
        reason: String,
        threat_level: ThreatLevel,
    },
}

impl JudgeDecision {
    pub fn confidence(&self) -> f32 {
        match self {
            JudgeDecision::Allow { confidence } => *confidence,
            JudgeDecision::Flag { confidence, .. } => *confidence,
            JudgeDecision::Block { confidence, .. } => *confidence,
        }
    }

    /// Checks if decision is a block - useful for metrics and filtering
    #[allow(dead_code)]
    pub fn is_block(&self) -> bool {
        matches!(self, JudgeDecision::Block { .. })
    }

    /// Checks if decision is a flag - useful for metrics and filtering
    #[allow(dead_code)]
    pub fn is_flag(&self) -> bool {
        matches!(self, JudgeDecision::Flag { .. })
    }

    pub fn decision_type(&self) -> &str {
        match self {
            JudgeDecision::Allow { .. } => "allow",
            JudgeDecision::Flag { .. } => "flag",
            JudgeDecision::Block { .. } => "block",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatLevel {
    /// Converts threat level to string representation for serialization
    #[allow(dead_code)]
    pub fn as_str(&self) -> &str {
        match self {
            ThreatLevel::Low => "low",
            ThreatLevel::Medium => "medium",
            ThreatLevel::High => "high",
            ThreatLevel::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnerOutput {
    pub new_rules: Vec<RuleSuggestion>,
    pub weaken_rules: Vec<String>, // Rule IDs
    pub remove_rules: Vec<String>, // Rule IDs
    pub rationales: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSuggestion {
    pub pattern: String,
    pub threat_type: String,
    pub description: String,
    pub confidence: f32,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Block,
    Flag,
}

impl RuleAction {
    pub fn as_str(&self) -> &str {
        match self {
            RuleAction::Block => "block",
            RuleAction::Flag => "flag",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_judge_decision_confidence() {
        let allow = JudgeDecision::Allow { confidence: 0.95 };
        assert_eq!(allow.confidence(), 0.95);

        let flag = JudgeDecision::Flag {
            confidence: 0.65,
            reason: "Suspicious".to_string(),
            suggested_rule: None,
        };
        assert_eq!(flag.confidence(), 0.65);

        let block = JudgeDecision::Block {
            confidence: 0.9,
            reason: "Attack detected".to_string(),
            threat_level: ThreatLevel::High,
        };
        assert_eq!(block.confidence(), 0.9);
    }

    #[test]
    fn test_judge_decision_is_block() {
        let allow = JudgeDecision::Allow { confidence: 0.9 };
        assert!(!allow.is_block());

        let flag = JudgeDecision::Flag {
            confidence: 0.6,
            reason: "Suspicious".to_string(),
            suggested_rule: None,
        };
        assert!(!flag.is_block());

        let block = JudgeDecision::Block {
            confidence: 0.95,
            reason: "SQL injection".to_string(),
            threat_level: ThreatLevel::Critical,
        };
        assert!(block.is_block());
    }

    #[test]
    fn test_judge_decision_is_flag() {
        let allow = JudgeDecision::Allow { confidence: 0.9 };
        assert!(!allow.is_flag());

        let flag = JudgeDecision::Flag {
            confidence: 0.6,
            reason: "Suspicious".to_string(),
            suggested_rule: Some("rule-123".to_string()),
        };
        assert!(flag.is_flag());

        let block = JudgeDecision::Block {
            confidence: 0.95,
            reason: "XSS".to_string(),
            threat_level: ThreatLevel::High,
        };
        assert!(!block.is_flag());
    }

    #[test]
    fn test_judge_decision_type() {
        let allow = JudgeDecision::Allow { confidence: 0.9 };
        assert_eq!(allow.decision_type(), "allow");

        let flag = JudgeDecision::Flag {
            confidence: 0.6,
            reason: "Suspicious".to_string(),
            suggested_rule: None,
        };
        assert_eq!(flag.decision_type(), "flag");

        let block = JudgeDecision::Block {
            confidence: 0.95,
            reason: "Attack".to_string(),
            threat_level: ThreatLevel::Medium,
        };
        assert_eq!(block.decision_type(), "block");
    }

    #[test]
    fn test_threat_level_as_str() {
        assert_eq!(ThreatLevel::Low.as_str(), "low");
        assert_eq!(ThreatLevel::Medium.as_str(), "medium");
        assert_eq!(ThreatLevel::High.as_str(), "high");
        assert_eq!(ThreatLevel::Critical.as_str(), "critical");
    }

    #[test]
    fn test_threat_level_serialization() {
        let level = ThreatLevel::High;
        let json = serde_json::to_string(&level).unwrap();
        assert_eq!(json, r#""high""#);

        let deserialized: ThreatLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ThreatLevel::High);
    }

    #[test]
    fn test_rule_action_as_str() {
        assert_eq!(RuleAction::Block.as_str(), "block");
        assert_eq!(RuleAction::Flag.as_str(), "flag");
    }

    #[test]
    fn test_rule_action_serialization() {
        let action = RuleAction::Block;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, r#""block""#);

        let deserialized: RuleAction = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, RuleAction::Block);
    }

    #[test]
    fn test_judge_decision_serialization() {
        let decision = JudgeDecision::Block {
            confidence: 0.95,
            reason: "SQL injection detected".to_string(),
            threat_level: ThreatLevel::Critical,
        };

        let json = serde_json::to_string(&decision).unwrap();
        let deserialized: JudgeDecision = serde_json::from_str(&json).unwrap();

        assert_eq!(decision.confidence(), deserialized.confidence());
        assert!(deserialized.is_block());
    }

    #[test]
    fn test_learner_output_structure() {
        let output = LearnerOutput {
            new_rules: vec![RuleSuggestion {
                pattern: "SELECT.*FROM".to_string(),
                threat_type: "sqli".to_string(),
                description: "SQL injection pattern".to_string(),
                confidence: 0.9,
                action: RuleAction::Block,
            }],
            weaken_rules: vec!["rule-1".to_string()],
            remove_rules: vec!["rule-2".to_string()],
            rationales: vec!["Added SQLi protection".to_string()],
        };

        assert_eq!(output.new_rules.len(), 1);
        assert_eq!(output.weaken_rules.len(), 1);
        assert_eq!(output.remove_rules.len(), 1);
        assert_eq!(output.rationales.len(), 1);
        assert_eq!(output.new_rules[0].threat_type, "sqli");
    }
}
