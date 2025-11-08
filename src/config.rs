use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub waf: WafConfig,
    pub llm: LlmConfig,
    pub cache: CacheConfig,
    pub storage: StorageConfig,
    pub learner: LearnerConfig,
    pub observability: ObservabilityConfig,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;

        let config: Config =
            serde_yaml_ng::from_str(&content).with_context(|| "Failed to parse config YAML")?;

        config.validate()?;

        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        // Validate listen address
        if self.waf.listen_addr.is_empty() {
            anyhow::bail!("waf.listen_addr cannot be empty");
        }

        // Validate upstream URL
        if self.waf.upstream_url.is_empty() {
            anyhow::bail!("waf.upstream_url cannot be empty");
        }

        // Validate timeouts
        if self.waf.request_timeout_ms == 0 {
            anyhow::bail!("waf.request_timeout_ms must be greater than 0");
        }

        if self.llm.judge_timeout_ms == 0 {
            anyhow::bail!("llm.judge_timeout_ms must be greater than 0");
        }

        // Validate LLM config
        if self.llm.base_url.is_empty() {
            anyhow::bail!("llm.base_url cannot be empty");
        }

        if self.llm.model.is_empty() {
            anyhow::bail!("llm.model cannot be empty");
        }

        // Validate cache
        if self.cache.enabled && self.cache.redis_url.is_empty() {
            anyhow::bail!("cache.redis_url cannot be empty when cache is enabled");
        }

        // Validate storage paths
        if self.storage.logs_db_path.is_empty() {
            anyhow::bail!("storage.logs_db_path cannot be empty");
        }

        if self.storage.rulebook_path.is_empty() {
            anyhow::bail!("storage.rulebook_path cannot be empty");
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    pub listen_addr: String,
    pub upstream_url: String,
    pub request_timeout_ms: u64,
}

impl WafConfig {
    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    pub provider: String,
    pub base_url: String,
    pub model: String,
    pub judge_timeout_ms: u64,
    pub judge_max_tokens: u32,
    pub judge_temperature: f32,
    pub learner_max_tokens: u32,
    pub learner_temperature: f32,
}

impl LlmConfig {
    pub fn judge_timeout(&self) -> Duration {
        Duration::from_millis(self.judge_timeout_ms)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub redis_url: String,
    pub ttl_seconds: u64,
    pub enabled: bool,
}

impl CacheConfig {
    pub fn ttl(&self) -> Duration {
        Duration::from_secs(self.ttl_seconds)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub logs_db_path: String,
    pub rulebook_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnerConfig {
    pub batch_interval_minutes: u64,
    pub min_flagged_requests: usize,
    pub enabled: bool,
}

impl LearnerConfig {
    pub fn batch_interval(&self) -> Duration {
        Duration::from_secs(self.batch_interval_minutes * 60)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    pub log_level: String,
    pub metrics_enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = Config {
            waf: WafConfig {
                listen_addr: "0.0.0.0:8080".to_string(),
                upstream_url: "http://backend:3000".to_string(),
                request_timeout_ms: 30000,
            },
            llm: LlmConfig {
                provider: "ollama".to_string(),
                base_url: "http://localhost:11434".to_string(),
                model: "llama3.2".to_string(),
                judge_timeout_ms: 200,
                judge_max_tokens: 128,
                judge_temperature: 0.0,
                learner_max_tokens: 2048,
                learner_temperature: 0.3,
            },
            cache: CacheConfig {
                redis_url: "redis://localhost:6379".to_string(),
                ttl_seconds: 900,
                enabled: true,
            },
            storage: StorageConfig {
                logs_db_path: "./data/logs.db".to_string(),
                rulebook_path: "./data/rulebook.json".to_string(),
            },
            learner: LearnerConfig {
                batch_interval_minutes: 60,
                min_flagged_requests: 10,
                enabled: true,
            },
            observability: ObservabilityConfig {
                log_level: "info".to_string(),
                metrics_enabled: true,
            },
        };

        assert!(config.validate().is_ok());
    }
}
