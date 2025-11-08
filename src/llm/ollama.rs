use crate::config::LlmConfig;
use crate::core::rulebook::Rulebook;
use crate::llm::client::LlmProvider;
use crate::llm::prompts::{judge_prompt, learner_prompt};
use crate::models::decision::{JudgeDecision, LearnerOutput, ThreatLevel};
use crate::models::request::{LogEntry, RequestPayload};
use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub struct OllamaProvider {
    client: Client,
    base_url: String,
    model: String,
    judge_timeout: Duration,
    judge_max_tokens: u32,
    judge_temperature: f32,
    learner_max_tokens: u32,
    learner_temperature: f32,
}

impl OllamaProvider {
    pub fn new(config: &LlmConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60)) // Overall timeout
            .build()
            .with_context(|| "Failed to create HTTP client")?;

        Ok(Self {
            client,
            base_url: config.base_url.clone(),
            model: config.model.clone(),
            judge_timeout: config.judge_timeout(),
            judge_max_tokens: config.judge_max_tokens,
            judge_temperature: config.judge_temperature,
            learner_max_tokens: config.learner_max_tokens,
            learner_temperature: config.learner_temperature,
        })
    }

    async fn generate(
        &self,
        prompt: String,
        max_tokens: u32,
        temperature: f32,
        timeout: Duration,
    ) -> Result<String> {
        tracing::debug!(
            target: "guardix::llm::debug",
            prompt_length = prompt.len(),
            model = %self.model,
            max_tokens = max_tokens,
            temperature = temperature,
            "📤 SENDING PROMPT TO LLM"
        );
        tracing::trace!(
            target: "guardix::llm::debug",
            "📝 PROMPT:\n{}\n---END PROMPT---",
            prompt
        );

        // Create JSON schema for structured output
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "decision": {
                    "type": "string",
                    "enum": ["allow", "flag", "block"]
                },
                "confidence": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0
                },
                "reason": {
                    "type": "string"
                },
                "threat_level": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"]
                },
                "suggested_rule": {
                    "type": "string"
                }
            },
            "required": ["decision", "confidence", "reason", "threat_level"]
        });

        let request = ChatRequest {
            model: self.model.clone(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: prompt,
            }],
            stream: false,
            format: schema,
            options: ChatOptions {
                temperature,
                num_predict: max_tokens as i32,
                num_ctx: 2048,  // Context window (smaller = faster)
            },
        };

        let url = format!("{}/api/chat", self.base_url);

        // First attempt
        match self.call_ollama_chat(&url, &request, timeout).await {
            Ok(response) => Ok(response),
            Err(e) => {
                tracing::warn!("First Ollama call failed: {}. Retrying...", e);

                // Retry once with backoff
                tokio::time::sleep(Duration::from_millis(100)).await;

                self.call_ollama_chat(&url, &request, timeout)
                    .await
                    .with_context(|| "Ollama retry failed")
            }
        }
    }

    async fn call_ollama_chat(
        &self,
        url: &str,
        request: &ChatRequest,
        timeout: Duration,
    ) -> Result<String> {
        let response = tokio::time::timeout(timeout, self.client.post(url).json(request).send())
            .await
            .with_context(|| format!("Ollama request timeout after {:?}", timeout))?
            .with_context(|| "Failed to send request to Ollama")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Ollama returned error {}: {}", status, body);
        }

        // Get the raw response text BEFORE parsing to debug what Ollama actually returns
        let raw_body = response
            .text()
            .await
            .with_context(|| "Failed to read Ollama response body")?;

        tracing::debug!(
            target: "guardix::llm::debug",
            raw_body_length = raw_body.len(),
            "📥 RAW OLLAMA RESPONSE"
        );
        tracing::trace!(
            target: "guardix::llm::debug",
            "📋 RAW BODY:\n{}\n---END RAW BODY---",
            raw_body
        );

        // Parse the chat response
        let chat_response: ChatResponse = serde_json::from_str(&raw_body)
            .with_context(|| format!("Failed to parse Ollama chat response. Raw body: {}", raw_body))?;

        // Support both standard models (content) and reasoning models (thinking)
        let response_text = if !chat_response.message.content.is_empty() {
            chat_response.message.content
        } else if let Some(thinking) = chat_response.message.thinking {
            tracing::debug!(
                target: "guardix::llm::debug",
                "Model returned 'thinking' field instead of 'content' (reasoning model)"
            );
            thinking
        } else {
            String::new()
        };

        tracing::debug!(
            target: "guardix::llm::debug",
            response_length = response_text.len(),
            done = chat_response.done,
            "📦 PARSED CHAT RESPONSE"
        );
        tracing::trace!(
            target: "guardix::llm::debug",
            "📝 MESSAGE CONTENT:\n{}\n---END CONTENT---",
            response_text
        );

        Ok(response_text)
    }

    fn parse_judge_response(&self, response: &str) -> Result<JudgeDecision> {
        // With structured outputs, response is already pure JSON
        let parsed: JudgeResponseJson = serde_json::from_str(response)
            .with_context(|| format!("Failed to parse judge JSON: {}", response))?;

        let decision = match parsed.decision.to_lowercase().as_str() {
            "allow" => JudgeDecision::Allow {
                confidence: parsed.confidence,
            },
            "flag" => JudgeDecision::Flag {
                confidence: parsed.confidence,
                reason: parsed.reason.unwrap_or_else(|| "Flagged".to_string()),
                suggested_rule: parsed.suggested_rule,
            },
            "block" => {
                let threat_level = parsed
                    .threat_level
                    .as_deref()
                    .and_then(Self::parse_threat_level)
                    .unwrap_or(ThreatLevel::Medium);

                JudgeDecision::Block {
                    confidence: parsed.confidence,
                    reason: parsed.reason.unwrap_or_else(|| "Blocked".to_string()),
                    threat_level,
                }
            }
            _ => anyhow::bail!("Unknown decision type: {}", parsed.decision),
        };

        Ok(decision)
    }

    fn parse_learner_response(&self, response: &str) -> Result<LearnerOutput> {
        // With structured outputs, response is already pure JSON
        let parsed: LearnerOutput = serde_json::from_str(response)
            .with_context(|| format!("Failed to parse learner JSON: {}", response))?;

        Ok(parsed)
    }

    fn parse_threat_level(level: &str) -> Option<ThreatLevel> {
        match level.to_lowercase().as_str() {
            "low" => Some(ThreatLevel::Low),
            "medium" => Some(ThreatLevel::Medium),
            "high" => Some(ThreatLevel::High),
            "critical" => Some(ThreatLevel::Critical),
            _ => None,
        }
    }
}

#[async_trait]
impl LlmProvider for OllamaProvider {
    async fn judge_request(
        &self,
        payload: &RequestPayload,
        rules: &Rulebook,
    ) -> Result<JudgeDecision> {
        let prompt = judge_prompt(payload, rules);

        let response = self
            .generate(
                prompt,
                self.judge_max_tokens,
                self.judge_temperature,
                self.judge_timeout,
            )
            .await?;

        self.parse_judge_response(&response)
    }

    async fn learn_rules(
        &self,
        flagged_logs: Vec<LogEntry>,
        current_rules: &Rulebook,
    ) -> Result<LearnerOutput> {
        let prompt = learner_prompt(&flagged_logs, current_rules);

        let response = self
            .generate(
                prompt,
                self.learner_max_tokens,
                self.learner_temperature,
                Duration::from_secs(30), // Longer timeout for learner
            )
            .await?;

        self.parse_learner_response(&response)
    }

    async fn health_check(&self) -> Result<()> {
        let url = format!("{}/api/tags", self.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| "Failed to connect to Ollama")?;

        if !response.status().is_success() {
            anyhow::bail!("Ollama health check failed: {}", response.status());
        }

        Ok(())
    }
}

// Chat API structures (for structured outputs with JSON schema)
#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
    format: serde_json::Value, // JSON schema
    options: ChatOptions,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct ChatOptions {
    temperature: f32,
    num_predict: i32,    // Max tokens to generate
    num_ctx: i32,        // Context window size (smaller = faster)
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    message: ChatMessageResponse,
    #[allow(dead_code)]
    done: bool,
}

#[derive(Debug, Deserialize)]
struct ChatMessageResponse {
    content: String,
    /// Some models (like qwen3) use a "thinking" field for reasoning instead of "content"
    #[serde(default)]
    thinking: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JudgeResponseJson {
    decision: String,
    confidence: f32,
    reason: Option<String>,
    threat_level: Option<String>,
    suggested_rule: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LlmConfig;

    fn create_test_config() -> LlmConfig {
        LlmConfig {
            provider: "ollama".to_string(),
            base_url: "http://localhost:11434".to_string(),
            model: "test-model".to_string(),
            judge_timeout_ms: 1000,
            judge_max_tokens: 128,
            judge_temperature: 0.0,
            learner_max_tokens: 2048,
            learner_temperature: 0.3,
        }
    }

    #[test]
    fn test_parse_threat_level() {
        assert_eq!(
            OllamaProvider::parse_threat_level("high"),
            Some(ThreatLevel::High)
        );
        assert_eq!(
            OllamaProvider::parse_threat_level("CRITICAL"),
            Some(ThreatLevel::Critical)
        );
        assert_eq!(
            OllamaProvider::parse_threat_level("low"),
            Some(ThreatLevel::Low)
        );
        assert_eq!(
            OllamaProvider::parse_threat_level("medium"),
            Some(ThreatLevel::Medium)
        );
        assert_eq!(OllamaProvider::parse_threat_level("unknown"), None);
    }

    #[test]
    fn test_parse_judge_response_allow() {
        let config = create_test_config();
        let provider = OllamaProvider::new(&config).unwrap();

        let json_response = r#"{
            "decision": "allow",
            "confidence": 0.95,
            "reason": "Legitimate request",
            "threat_level": "low"
        }"#;

        let result = provider.parse_judge_response(json_response);
        assert!(result.is_ok());

        let decision = result.unwrap();
        assert!(matches!(decision, JudgeDecision::Allow { .. }));
        assert_eq!(decision.confidence(), 0.95);
    }

    #[test]
    fn test_parse_judge_response_flag() {
        let config = create_test_config();
        let provider = OllamaProvider::new(&config).unwrap();

        let json_response = r#"{
            "decision": "flag",
            "confidence": 0.65,
            "reason": "Suspicious pattern detected",
            "threat_level": "medium",
            "suggested_rule": "Check for SQL keywords"
        }"#;

        let result = provider.parse_judge_response(json_response);
        assert!(result.is_ok());

        let decision = result.unwrap();
        assert!(decision.is_flag());
        assert_eq!(decision.confidence(), 0.65);
    }

    #[test]
    fn test_parse_judge_response_block() {
        let config = create_test_config();
        let provider = OllamaProvider::new(&config).unwrap();

        let json_response = r#"{
            "decision": "block",
            "confidence": 0.98,
            "reason": "SQL injection detected",
            "threat_level": "critical"
        }"#;

        let result = provider.parse_judge_response(json_response);
        assert!(result.is_ok());

        let decision = result.unwrap();
        assert!(decision.is_block());
        assert_eq!(decision.confidence(), 0.98);

        if let JudgeDecision::Block { threat_level, .. } = decision {
            assert_eq!(threat_level, ThreatLevel::Critical);
        } else {
            panic!("Expected Block decision");
        }
    }

    #[test]
    fn test_parse_judge_response_block_without_threat_level() {
        let config = create_test_config();
        let provider = OllamaProvider::new(&config).unwrap();

        let json_response = r#"{
            "decision": "block",
            "confidence": 0.85,
            "reason": "Malicious request"
        }"#;

        let result = provider.parse_judge_response(json_response);
        assert!(result.is_ok());

        let decision = result.unwrap();
        if let JudgeDecision::Block { threat_level, .. } = decision {
            // Should default to Medium
            assert_eq!(threat_level, ThreatLevel::Medium);
        } else {
            panic!("Expected Block decision");
        }
    }

    #[test]
    fn test_parse_judge_response_invalid_decision() {
        let config = create_test_config();
        let provider = OllamaProvider::new(&config).unwrap();

        let json_response = r#"{
            "decision": "unknown",
            "confidence": 0.5,
            "reason": "Test"
        }"#;

        let result = provider.parse_judge_response(json_response);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_judge_response_invalid_json() {
        let config = create_test_config();
        let provider = OllamaProvider::new(&config).unwrap();

        let json_response = r#"{ invalid json }"#;

        let result = provider.parse_judge_response(json_response);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_learner_response() {
        let config = create_test_config();
        let provider = OllamaProvider::new(&config).unwrap();

        let json_response = r#"{
            "new_rules": [
                {
                    "pattern": "SELECT.*FROM",
                    "threat_type": "sqli",
                    "description": "SQL injection pattern",
                    "confidence": 0.9,
                    "action": "block"
                }
            ],
            "weaken_rules": ["rule-1"],
            "remove_rules": ["rule-2"],
            "rationales": ["Added SQLi detection"]
        }"#;

        let result = provider.parse_learner_response(json_response);
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.new_rules.len(), 1);
        assert_eq!(output.weaken_rules.len(), 1);
        assert_eq!(output.remove_rules.len(), 1);
        assert_eq!(output.rationales.len(), 1);
        assert_eq!(output.new_rules[0].pattern, "SELECT.*FROM");
    }

    #[test]
    fn test_parse_learner_response_empty() {
        let config = create_test_config();
        let provider = OllamaProvider::new(&config).unwrap();

        let json_response = r#"{
            "new_rules": [],
            "weaken_rules": [],
            "remove_rules": [],
            "rationales": ["No changes needed"]
        }"#;

        let result = provider.parse_learner_response(json_response);
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.new_rules.len(), 0);
        assert_eq!(output.rationales.len(), 1);
    }

    #[test]
    fn test_parse_learner_response_invalid_json() {
        let config = create_test_config();
        let provider = OllamaProvider::new(&config).unwrap();

        let json_response = r#"{ invalid json }"#;

        let result = provider.parse_learner_response(json_response);
        assert!(result.is_err());
    }

    #[test]
    fn test_ollama_provider_creation() {
        let config = create_test_config();
        let provider = OllamaProvider::new(&config);

        assert!(provider.is_ok());

        let provider = provider.unwrap();
        assert_eq!(provider.model, "test-model");
        assert_eq!(provider.base_url, "http://localhost:11434");
    }

    #[test]
    fn test_chat_request_structure() {
        let request = ChatRequest {
            model: "test-model".to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: "test content".to_string(),
            }],
            stream: false,
            format: serde_json::json!({"type": "object"}),
            options: ChatOptions {
                temperature: 0.0,
                num_predict: 128,
                num_ctx: 2048,
            },
        };

        assert_eq!(request.model, "test-model");
        assert_eq!(request.messages.len(), 1);
        assert_eq!(request.stream, false);
        assert_eq!(request.options.temperature, 0.0);
    }
}
