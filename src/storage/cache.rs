use crate::models::decision::JudgeDecision;
use anyhow::{Context, Result};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::time::Duration;

#[derive(Clone)]
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

    #[test]
    fn test_verdict_key_format() {
        let hash = "abc123def456";
        let key = RedisCache::verdict_key(hash);
        assert_eq!(key, "verdict:abc123def456");
        assert!(key.starts_with("verdict:"));
    }

    #[test]
    fn test_verdict_key_with_special_chars() {
        let hash = "test-hash_123.456";
        let key = RedisCache::verdict_key(hash);
        assert_eq!(key, "verdict:test-hash_123.456");
    }

    #[test]
    fn test_verdict_key_empty_hash() {
        let key = RedisCache::verdict_key("");
        assert_eq!(key, "verdict:");
    }

    #[tokio::test]
    #[ignore] // Requires actual network connection attempt - run with integration tests
    async fn test_redis_connection_failure() {
        // Try to connect to non-existent Redis
        let result = RedisCache::new("redis://localhost:9999", Duration::from_secs(60)).await;
        assert!(result.is_err());
        
        if let Err(err) = result {
            let msg = err.to_string();
            assert!(msg.contains("Failed to connect to Redis") || msg.contains("Connection refused"));
        }
    }

    #[tokio::test]
    async fn test_redis_invalid_url() {
        // Invalid Redis URL format
        let result = RedisCache::new("invalid://url", Duration::from_secs(60)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redis_empty_url() {
        // Empty URL should fail
        let result = RedisCache::new("", Duration::from_secs(60)).await;
        assert!(result.is_err());
    }

    // Integration test with real Redis (ignored by default)
    #[tokio::test]
    #[ignore]
    async fn test_set_and_get_verdict_with_redis() {
        let cache = RedisCache::new("redis://localhost:6379", Duration::from_secs(60))
            .await
            .expect("Failed to create cache - Redis not running?");

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

    #[tokio::test]
    #[ignore]
    async fn test_get_nonexistent_verdict_with_redis() {
        let cache = RedisCache::new("redis://localhost:6379", Duration::from_secs(60))
            .await
            .expect("Redis not running");

        let result = cache.get_verdict("nonexistent_hash").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    #[ignore]
    async fn test_invalidate_verdict_with_redis() {
        let cache = RedisCache::new("redis://localhost:6379", Duration::from_secs(60))
            .await
            .expect("Redis not running");

        let decision = JudgeDecision::Allow { confidence: 0.9 };
        let hash = "test_invalidate";

        // Set then invalidate
        cache.set_verdict(hash, &decision).await.unwrap();
        cache.invalidate(hash).await.unwrap();

        // Should be gone
        let result = cache.get_verdict(hash).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    #[ignore]
    async fn test_ping_with_redis() {
        let cache = RedisCache::new("redis://localhost:6379", Duration::from_secs(60))
            .await
            .expect("Redis not running");

        let result = cache.ping().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[ignore]
    async fn test_cache_ttl_with_redis() {
        let cache = RedisCache::new("redis://localhost:6379", Duration::from_secs(1))
            .await
            .expect("Redis not running");

        let decision = JudgeDecision::Flag {
            confidence: 0.6,
            reason: "Test".to_string(),
            suggested_rule: None,
        };
        let hash = "test_ttl";

        cache.set_verdict(hash, &decision).await.unwrap();

        // Should exist immediately
        let result1 = cache.get_verdict(hash).await.unwrap();
        assert!(result1.is_some());

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should be gone
        let result2 = cache.get_verdict(hash).await.unwrap();
        assert!(result2.is_none());
    }
}
