use crate::models::decision::JudgeDecision;
use crate::models::request::{LogEntry, RequestPayload};
use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct LogStore {
    pool: SqlitePool,
}

impl LogStore {
    pub async fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let path_str = db_path.as_ref().to_string_lossy().to_string();

        // Ensure parent directory exists
        if let Some(parent) = db_path.as_ref().parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create database directory: {:?}", parent))?;
        }

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path_str))?
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .with_context(|| format!("Failed to connect to SQLite database: {}", path_str))?;

        // Run migrations
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .with_context(|| "Failed to run database migrations")?;

        Ok(Self { pool })
    }

    pub async fn log_event(
        &self,
        payload: &RequestPayload,
        decision: &JudgeDecision,
    ) -> Result<i64> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let decision_type = decision.decision_type();
        let confidence = decision.confidence();
        let reason = match decision {
            JudgeDecision::Flag { reason, .. } | JudgeDecision::Block { reason, .. } => {
                Some(reason.as_str())
            }
            JudgeDecision::Allow { .. } => None,
        };

        let user_agent = payload.get_user_agent().map(|s| s.as_str());

        let result = sqlx::query!(
            r#"
            INSERT INTO events (timestamp, method, path, payload_hash, decision, confidence, reason, ip_addr, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            timestamp,
            payload.method,
            payload.path,
            payload.normalized_hash,
            decision_type,
            confidence,
            reason,
            payload.ip_addr,
            user_agent,
        )
        .execute(&self.pool)
        .await
        .with_context(|| "Failed to insert event into database")?;

        Ok(result.last_insert_rowid())
    }

    pub async fn get_flagged_since(&self, since_timestamp: i64) -> Result<Vec<LogEntry>> {
        let entries = sqlx::query_as!(
            LogEntry,
            r#"
            SELECT id as "id!", timestamp as "timestamp!", method, path, payload_hash, decision, confidence as "confidence: f32", reason, ip_addr, user_agent
            FROM events
            WHERE decision = 'flag' AND timestamp >= ?
            ORDER BY timestamp DESC
            "#,
            since_timestamp
        )
        .fetch_all(&self.pool)
        .await
        .with_context(|| "Failed to fetch flagged events")?;

        Ok(entries)
    }

    /// Retrieves blocked requests since timestamp - used for analytics dashboards
    #[allow(dead_code)]
    pub async fn get_blocked_since(&self, since_timestamp: i64) -> Result<Vec<LogEntry>> {
        let entries = sqlx::query_as!(
            LogEntry,
            r#"
            SELECT id as "id!", timestamp as "timestamp!", method, path, payload_hash, decision, confidence as "confidence: f32", reason, ip_addr, user_agent
            FROM events
            WHERE decision = 'block' AND timestamp >= ?
            ORDER BY timestamp DESC
            "#,
            since_timestamp
        )
        .fetch_all(&self.pool)
        .await
        .with_context(|| "Failed to fetch blocked events")?;

        Ok(entries)
    }

    /// Retrieves all events since timestamp with limit - used for general log viewing
    #[allow(dead_code)]
    pub async fn get_events_since(
        &self,
        since_timestamp: i64,
        limit: i64,
    ) -> Result<Vec<LogEntry>> {
        let entries = sqlx::query_as!(
            LogEntry,
            r#"
            SELECT id as "id!", timestamp as "timestamp!", method, path, payload_hash, decision, confidence as "confidence: f32", reason, ip_addr, user_agent
            FROM events
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT ?
            "#,
            since_timestamp,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .with_context(|| "Failed to fetch events")?;

        Ok(entries)
    }

    /// Aggregates event counts by decision type - used for metrics and reporting
    #[allow(dead_code)]
    pub async fn count_events_by_decision(
        &self,
        since_timestamp: i64,
    ) -> Result<Vec<(String, i64)>> {
        let counts = sqlx::query!(
            r#"
            SELECT decision, COUNT(*) as count
            FROM events
            WHERE timestamp >= ?
            GROUP BY decision
            "#,
            since_timestamp
        )
        .fetch_all(&self.pool)
        .await
        .with_context(|| "Failed to count events by decision")?;

        Ok(counts
            .into_iter()
            .map(|row| (row.decision, row.count))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::decision::ThreatLevel;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_log_event() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let store = LogStore::new(&db_path).await.unwrap();

        let payload = RequestPayload::new(
            "GET".to_string(),
            "/test".to_string(),
            HashMap::new(),
            None,
            HashMap::new(),
            Some("127.0.0.1".to_string()),
        );

        let decision = JudgeDecision::Block {
            confidence: 0.9,
            reason: "Test block".to_string(),
            threat_level: ThreatLevel::High,
        };

        let id = store.log_event(&payload, &decision).await.unwrap();
        assert!(id > 0);
    }

    #[tokio::test]
    async fn test_get_flagged_since() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let store = LogStore::new(&db_path).await.unwrap();

        // Log a flagged event
        let payload = RequestPayload::new(
            "GET".to_string(),
            "/suspicious".to_string(),
            HashMap::new(),
            None,
            HashMap::new(),
            Some("192.168.1.1".to_string()),
        );

        let decision = JudgeDecision::Flag {
            confidence: 0.65,
            reason: "Suspicious pattern".to_string(),
            suggested_rule: None,
        };

        store.log_event(&payload, &decision).await.unwrap();

        // Get flagged events
        let flagged = store.get_flagged_since(0).await.unwrap();
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].decision, "flag");
        assert_eq!(flagged[0].path, "/suspicious");
    }

    #[tokio::test]
    async fn test_get_blocked_since() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let store = LogStore::new(&db_path).await.unwrap();

        // Log blocked events
        for i in 0..3 {
            let payload = RequestPayload::new(
                "POST".to_string(),
                format!("/attack{}", i),
                HashMap::new(),
                None,
                HashMap::new(),
                None,
            );

            let decision = JudgeDecision::Block {
                confidence: 0.95,
                reason: "Attack detected".to_string(),
                threat_level: ThreatLevel::Critical,
            };

            store.log_event(&payload, &decision).await.unwrap();
        }

        // Get blocked events
        let blocked = store.get_blocked_since(0).await.unwrap();
        assert_eq!(blocked.len(), 3);
        assert!(blocked.iter().all(|e| e.decision == "block"));
    }

    #[tokio::test]
    async fn test_get_events_since_with_limit() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let store = LogStore::new(&db_path).await.unwrap();

        // Log 5 events
        for i in 0..5 {
            let payload = RequestPayload::new(
                "GET".to_string(),
                format!("/path{}", i),
                HashMap::new(),
                None,
                HashMap::new(),
                None,
            );

            let decision = JudgeDecision::Allow { confidence: 0.9 };
            store.log_event(&payload, &decision).await.unwrap();
        }

        // Get events with limit
        let events = store.get_events_since(0, 3).await.unwrap();
        assert_eq!(events.len(), 3);
    }

    #[tokio::test]
    async fn test_count_events_by_decision() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let store = LogStore::new(&db_path).await.unwrap();

        // Log different decision types
        let decisions = vec![
            JudgeDecision::Allow { confidence: 0.9 },
            JudgeDecision::Allow { confidence: 0.85 },
            JudgeDecision::Flag {
                confidence: 0.6,
                reason: "Suspicious".to_string(),
                suggested_rule: None,
            },
            JudgeDecision::Block {
                confidence: 0.95,
                reason: "Attack".to_string(),
                threat_level: ThreatLevel::High,
            },
        ];

        for (i, decision) in decisions.iter().enumerate() {
            let payload = RequestPayload::new(
                "GET".to_string(),
                format!("/test{}", i),
                HashMap::new(),
                None,
                HashMap::new(),
                None,
            );
            store.log_event(&payload, decision).await.unwrap();
        }

        // Count by decision
        let counts = store.count_events_by_decision(0).await.unwrap();
        
        let allow_count = counts.iter().find(|(d, _)| d == "allow").map(|(_, c)| *c);
        let flag_count = counts.iter().find(|(d, _)| d == "flag").map(|(_, c)| *c);
        let block_count = counts.iter().find(|(d, _)| d == "block").map(|(_, c)| *c);

        assert_eq!(allow_count, Some(2));
        assert_eq!(flag_count, Some(1));
        assert_eq!(block_count, Some(1));
    }

    #[tokio::test]
    async fn test_log_event_with_allow_decision() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let store = LogStore::new(&db_path).await.unwrap();

        let payload = RequestPayload::new(
            "GET".to_string(),
            "/legitimate".to_string(),
            HashMap::new(),
            None,
            HashMap::new(),
            None,
        );

        let decision = JudgeDecision::Allow { confidence: 0.95 };

        let id = store.log_event(&payload, &decision).await.unwrap();
        assert!(id > 0);

        // Verify it was logged
        let events = store.get_events_since(0, 10).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].decision, "allow");
        assert!(events[0].reason.is_none()); // Allow has no reason
    }

    #[tokio::test]
    async fn test_get_flagged_since_timestamp_filter() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let store = LogStore::new(&db_path).await.unwrap();

        // Log a flagged event
        let payload = RequestPayload::new(
            "GET".to_string(),
            "/old".to_string(),
            HashMap::new(),
            None,
            HashMap::new(),
            None,
        );

        let decision = JudgeDecision::Flag {
            confidence: 0.6,
            reason: "Old suspicious".to_string(),
            suggested_rule: None,
        };

        store.log_event(&payload, &decision).await.unwrap();

        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Query with future timestamp should return nothing
        let flagged = store.get_flagged_since(now + 1000).await.unwrap();
        assert_eq!(flagged.len(), 0);

        // Query with past timestamp should return the event
        let flagged = store.get_flagged_since(0).await.unwrap();
        assert_eq!(flagged.len(), 1);
    }
}
