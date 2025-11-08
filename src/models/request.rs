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
