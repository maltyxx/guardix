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
