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

        tracing::debug!(
            target: "guardix::llm::debug",
            content_length = chat_response.message.content.len(),
            done = chat_response.done,
            "📦 PARSED CHAT RESPONSE"
        );
        tracing::trace!(
            target: "guardix::llm::debug",
            "📝 MESSAGE CONTENT:\n{}\n---END CONTENT---",
            chat_response.message.content
        );

        Ok(chat_response.message.content)
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
        assert_eq!(OllamaProvider::parse_threat_level("unknown"), None);
    }
}
