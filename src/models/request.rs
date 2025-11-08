use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPayload {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub query_params: HashMap<String, String>,
    pub normalized_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_addr: Option<String>,
}

impl RequestPayload {
    pub fn new(
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: Option<String>,
        query_params: HashMap<String, String>,
        ip_addr: Option<String>,
    ) -> Self {
        let normalized_hash = Self::compute_hash(&method, &path, &body, &query_params);

        Self {
            method,
            path,
            headers,
            body,
            query_params,
            normalized_hash,
            ip_addr,
        }
    }

    pub fn compute_hash(
        method: &str,
        path: &str,
        body: &Option<String>,
        query_params: &HashMap<String, String>,
    ) -> String {
        let mut hasher = Sha256::new();

        hasher.update(method.as_bytes());
        hasher.update(path.as_bytes());

        if let Some(body_content) = body {
            hasher.update(body_content.as_bytes());
        }

        // Sort query params for consistent hashing
        let mut params: Vec<_> = query_params.iter().collect();
        params.sort_by_key(|(k, _)| *k);
        for (key, value) in params {
            hasher.update(key.as_bytes());
            hasher.update(value.as_bytes());
        }

        format!("{:x}", hasher.finalize())
    }

    pub fn get_user_agent(&self) -> Option<&String> {
        self.headers
            .get("user-agent")
            .or_else(|| self.headers.get("User-Agent"))
    }

    /// Extracts content-type header (case-insensitive) - used for content inspection
    #[allow(dead_code)]
    pub fn content_type(&self) -> Option<&String> {
        self.headers
            .get("content-type")
            .or_else(|| self.headers.get("Content-Type"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: i64,
    pub timestamp: i64,
    pub method: String,
    pub path: String,
    pub payload_hash: String,
    pub decision: String,
    pub confidence: f32,
    pub reason: Option<String>,
    pub ip_addr: Option<String>,
    pub user_agent: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_payload_new() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let mut query_params = HashMap::new();
        query_params.insert("id".to_string(), "123".to_string());

        let payload = RequestPayload::new(
            "POST".to_string(),
            "/api/users".to_string(),
            headers,
            Some(r#"{"name":"test"}"#.to_string()),
            query_params,
            Some("192.168.1.1".to_string()),
        );

        assert_eq!(payload.method, "POST");
        assert_eq!(payload.path, "/api/users");
        assert_eq!(payload.body, Some(r#"{"name":"test"}"#.to_string()));
        assert_eq!(payload.ip_addr, Some("192.168.1.1".to_string()));
        assert!(!payload.normalized_hash.is_empty());
    }

    #[test]
    fn test_compute_hash_consistency() {
        let mut query_params = HashMap::new();
        query_params.insert("a".to_string(), "1".to_string());
        query_params.insert("b".to_string(), "2".to_string());

        let hash1 = RequestPayload::compute_hash(
            "GET",
            "/test",
            &Some("body".to_string()),
            &query_params,
        );

        // Same params, different insertion order should produce same hash
        let mut query_params2 = HashMap::new();
        query_params2.insert("b".to_string(), "2".to_string());
        query_params2.insert("a".to_string(), "1".to_string());

        let hash2 = RequestPayload::compute_hash(
            "GET",
            "/test",
            &Some("body".to_string()),
            &query_params2,
        );

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_hash_different_for_different_requests() {
        let query_params = HashMap::new();

        let hash1 = RequestPayload::compute_hash("GET", "/path1", &None, &query_params);
        let hash2 = RequestPayload::compute_hash("GET", "/path2", &None, &query_params);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_hash_with_body() {
        let query_params = HashMap::new();

        let hash1 = RequestPayload::compute_hash(
            "POST",
            "/api",
            &Some("body1".to_string()),
            &query_params,
        );
        let hash2 = RequestPayload::compute_hash(
            "POST",
            "/api",
            &Some("body2".to_string()),
            &query_params,
        );

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_hash_without_body() {
        let query_params = HashMap::new();

        let hash1 = RequestPayload::compute_hash("GET", "/api", &None, &query_params);
        let hash2 = RequestPayload::compute_hash("GET", "/api", &None, &query_params);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_get_user_agent() {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());

        let payload = RequestPayload::new(
            "GET".to_string(),
            "/test".to_string(),
            headers,
            None,
            HashMap::new(),
            None,
        );

        assert_eq!(payload.get_user_agent(), Some(&"Mozilla/5.0".to_string()));
    }

    #[test]
    fn test_get_user_agent_case_insensitive() {
        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Chrome/91.0".to_string());

        let payload = RequestPayload::new(
            "GET".to_string(),
            "/test".to_string(),
            headers,
            None,
            HashMap::new(),
            None,
        );

        assert_eq!(payload.get_user_agent(), Some(&"Chrome/91.0".to_string()));
    }

    #[test]
    fn test_get_user_agent_missing() {
        let payload = RequestPayload::new(
            "GET".to_string(),
            "/test".to_string(),
            HashMap::new(),
            None,
            HashMap::new(),
            None,
        );

        assert_eq!(payload.get_user_agent(), None);
    }

    #[test]
    fn test_content_type() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let payload = RequestPayload::new(
            "POST".to_string(),
            "/api".to_string(),
            headers,
            Some("{}".to_string()),
            HashMap::new(),
            None,
        );

        assert_eq!(
            payload.content_type(),
            Some(&"application/json".to_string())
        );
    }

    #[test]
    fn test_content_type_case_insensitive() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/html".to_string());

        let payload = RequestPayload::new(
            "GET".to_string(),
            "/page".to_string(),
            headers,
            None,
            HashMap::new(),
            None,
        );

        assert_eq!(payload.content_type(), Some(&"text/html".to_string()));
    }

    #[test]
    fn test_content_type_missing() {
        let payload = RequestPayload::new(
            "GET".to_string(),
            "/test".to_string(),
            HashMap::new(),
            None,
            HashMap::new(),
            None,
        );

        assert_eq!(payload.content_type(), None);
    }

    #[test]
    fn test_request_payload_serialization() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer token".to_string());

        let payload = RequestPayload::new(
            "GET".to_string(),
            "/secure".to_string(),
            headers,
            None,
            HashMap::new(),
            Some("10.0.0.1".to_string()),
        );

        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: RequestPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(payload.method, deserialized.method);
        assert_eq!(payload.path, deserialized.path);
        assert_eq!(payload.normalized_hash, deserialized.normalized_hash);
        assert_eq!(payload.ip_addr, deserialized.ip_addr);
    }

    #[test]
    fn test_log_entry_structure() {
        let entry = LogEntry {
            id: 1,
            timestamp: 1234567890,
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            payload_hash: "abc123".to_string(),
            decision: "allow".to_string(),
            confidence: 0.95,
            reason: Some("Legitimate request".to_string()),
            ip_addr: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
        };

        assert_eq!(entry.id, 1);
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.decision, "allow");
        assert_eq!(entry.confidence, 0.95);
    }
}
