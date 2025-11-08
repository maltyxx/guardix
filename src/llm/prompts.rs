use crate::core::rulebook::Rulebook;
use crate::models::request::{LogEntry, RequestPayload};

/// Generate the judge prompt for request evaluation.
/// This prompt is optimized for low latency with temperature=0 and max_tokens=128.
pub fn judge_prompt(payload: &RequestPayload, rules: &Rulebook) -> String {
    let rules_summary = if rules.rules.is_empty() {
        "No existing rules yet.".to_string()
    } else {
        rules
            .rules
            .iter()
            .map(|r| {
                format!(
                    "- {} ({}): {} [action: {}]",
                    r.threat_type,
                    r.id,
                    r.pattern,
                    r.action.as_str()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let body_info = payload
        .body
        .as_ref()
        .map(|b| format!("Body: {}", truncate(b, 500)))
        .unwrap_or_else(|| "Body: none".to_string());

    let query_info = if payload.query_params.is_empty() {
        "Query params: none".to_string()
    } else {
        format!("Query params: {:?}", payload.query_params)
    };

    format!(
        r#"WAF security expert: evaluate this request for threats.

REQUEST:
{} {} | {} | {} | Headers: {:?}

RULES: {}

Analyze: injection attacks (SQL/code/command), XSS, path manipulation, auth bypass, API abuse.

DECIDE:
- block (confidence > 0.8): definitive attack
- flag (0.5-0.8): suspicious
- allow (> 0.8): legitimate

Output: decision, confidence, reason, threat_level"#,
        payload.method, payload.path, body_info, query_info, payload.headers, rules_summary
    )
}

/// Generate the learner prompt for rule generation.
/// This prompt analyzes flagged requests and suggests new rules or modifications.
pub fn learner_prompt(logs: &[LogEntry], rules: &Rulebook) -> String {
    let logs_summary = logs
        .iter()
        .take(50) // Limit to prevent context overflow
        .map(|log| {
            format!(
                "- {} {} | Hash: {} | Reason: {}",
                log.method,
                log.path,
                &log.payload_hash[..12],
                log.reason.as_deref().unwrap_or("none")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let rules_summary = if rules.rules.is_empty() {
        "No existing rules.".to_string()
    } else {
        rules
            .rules
            .iter()
            .map(|r| {
                format!(
                    "- ID: {} | Type: {} | Pattern: {} | Action: {} | Confidence: {}",
                    r.id,
                    r.threat_type,
                    r.pattern,
                    r.action.as_str(),
                    r.confidence
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r#"WAF rule learning system. Analyze flagged requests and suggest rule improvements.

FLAGGED REQUESTS ({} total):
{}

CURRENT RULES ({} total):
{}

Tasks:
1. Find patterns in flagged requests (3+ similar = new rule)
2. Suggest new rules for recurring threats
3. Weaken rules with consistent low confidence
4. Remove unused rules

Guidelines:
- Prefer "flag" over "block" initially
- High confidence (>0.8) for OWASP Top 10 patterns
- Low confidence (0.5-0.7) for emerging patterns"#,
        logs.len(),
        logs_summary,
        rules.rules.len(),
        rules_summary
    )
}

/// Truncate a string to a maximum length with ellipsis
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_judge_prompt_generation() {
        let payload = RequestPayload::new(
            "GET".to_string(),
            "/api/users".to_string(),
            HashMap::new(),
            None,
            HashMap::new(),
            Some("127.0.0.1".to_string()),
        );

        let rules = Rulebook::new();
        let prompt = judge_prompt(&payload, &rules);

        assert!(prompt.contains("GET"));
        assert!(prompt.contains("/api/users"));
        assert!(prompt.contains("WAF security expert"));
    }

    #[test]
    fn test_learner_prompt_generation() {
        let logs = vec![LogEntry {
            id: 1,
            timestamp: 0,
            method: "GET".to_string(),
            path: "/admin".to_string(),
            payload_hash: "abc123def456".to_string(),
            decision: "flag".to_string(),
            confidence: 0.6,
            reason: Some("Suspicious".to_string()),
            ip_addr: None,
            user_agent: None,
        }];

        let rules = Rulebook::new();
        let prompt = learner_prompt(&logs, &rules);

        assert!(prompt.contains("abc123def456"));
        assert!(prompt.contains("Suspicious"));
        assert!(prompt.contains("rule learning"));
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 5), "hello...");
    }
}
