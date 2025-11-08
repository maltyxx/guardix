use crate::models::decision::JudgeDecision;
use anyhow::{Context, Result};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::time::Duration;

pub struct RedisCache {
    client: ConnectionManager,
    ttl: Duration,
}

impl RedisCache {
    pub async fn new(redis_url: &str, ttl: Duration) -> Result<Self> {
        let client = redis::Client::open(redis_url)
            .with_context(|| format!("Failed to create Redis client: {}", redis_url))?;

        let connection = ConnectionManager::new(client)
            .await
            .with_context(|| "Failed to connect to Redis")?;

        Ok(Self {
            client: connection,
            ttl,
        })
    }

    pub async fn get_verdict(&self, hash: &str) -> Result<Option<JudgeDecision>> {
        let key = Self::verdict_key(hash);
        let mut conn = self.client.clone();

        let value: Option<String> = conn
            .get(&key)
            .await
            .with_context(|| format!("Failed to get verdict from Redis: {}", key))?;

        match value {
            Some(json) => {
                let decision = serde_json::from_str(&json)
                    .with_context(|| "Failed to deserialize verdict from Redis")?;
                Ok(Some(decision))
            }
            None => Ok(None),
        }
    }

    pub async fn set_verdict(&self, hash: &str, decision: &JudgeDecision) -> Result<()> {
        let key = Self::verdict_key(hash);
        let mut conn = self.client.clone();

        let json = serde_json::to_string(decision)
            .with_context(|| "Failed to serialize verdict for Redis")?;

        conn.set_ex::<_, _, ()>(&key, json, self.ttl.as_secs())
            .await
            .with_context(|| format!("Failed to set verdict in Redis: {}", key))?;

        Ok(())
    }

    /// Invalidates a cached verdict - used for cache warming/invalidation strategies
    #[allow(dead_code)]
    pub async fn invalidate(&self, hash: &str) -> Result<()> {
        let key = Self::verdict_key(hash);
        let mut conn = self.client.clone();

        conn.del::<_, ()>(&key)
            .await
            .with_context(|| format!("Failed to delete verdict from Redis: {}", key))?;

        Ok(())
    }

    pub async fn ping(&self) -> Result<()> {
        let mut conn = self.client.clone();
        redis::cmd("PING")
            .query_async::<()>(&mut conn)
            .await
            .with_context(|| "Redis ping failed")?;
        Ok(())
    }

    fn verdict_key(hash: &str) -> String {
        format!("verdict:{}", hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::decision::ThreatLevel;

    // These tests require a running Redis instance
    // Run with: docker run -d -p 6379:6379 redis:alpine

    #[tokio::test]
    #[ignore] // Ignored by default, run with --ignored flag
    async fn test_set_and_get_verdict() {
        let cache = RedisCache::new("redis://localhost:6379", Duration::from_secs(60))
            .await
            .expect("Failed to create cache");

        let decision = JudgeDecision::Block {
            confidence: 0.95,
            reason: "SQL injection detected".to_string(),
            threat_level: ThreatLevel::High,
        };

        let hash = "test_hash_123";

        cache
            .set_verdict(hash, &decision)
            .await
            .expect("Failed to set verdict");

        let retrieved = cache
            .get_verdict(hash)
            .await
            .expect("Failed to get verdict")
            .expect("Verdict not found");

        assert_eq!(decision, retrieved);
    }
}
