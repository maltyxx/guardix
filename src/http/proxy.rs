use crate::core::judge::Judge;
use crate::models::request::RequestPayload;
use crate::storage::logs::LogStore;
use axum::{
    body::Body,
    extract::State,
    http::{Request, Response, StatusCode, Uri},
    response::IntoResponse,
};
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub judge: Arc<Judge>,
    pub logs: Arc<LogStore>,
    pub upstream_url: String,
    pub upstream_client: Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
}

impl AppState {
    pub fn new(judge: Arc<Judge>, logs: Arc<LogStore>, upstream_url: String) -> Self {
        let upstream_client = Client::builder(TokioExecutor::new()).build_http();

        Self {
            judge,
            logs,
            upstream_url,
            upstream_client,
        }
    }
}

/// Main proxy handler - evaluates requests and forwards them upstream
pub async fn proxy_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    // Step 1: Extract and normalize the request
    let (parts, body) = req.into_parts();

    let payload = match extract_payload(&parts, body).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "Failed to extract payload");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Step 2: Judge evaluation
    let decision = state.judge.evaluate(payload.clone()).await;

    // Step 3: Log event asynchronously (non-blocking)
    let logs = Arc::clone(&state.logs);
    let payload_for_log = payload.clone();
    let decision_for_log = decision.clone();
    tokio::spawn(async move {
        if let Err(e) = logs.log_event(&payload_for_log, &decision_for_log).await {
            tracing::error!(error = %e, "Failed to log event");
        }
    });

    // Step 4: Act on decision
    match decision {
        crate::models::decision::JudgeDecision::Block { reason, .. } => {
            tracing::warn!(
                method = %payload.method,
                path = %payload.path,
                reason = %reason,
                "Request blocked"
            );

            Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "application/json; charset=utf-8")
                .body(Body::from(
                    serde_json::json!({
                        "error": "Request blocked by WAF",
                        "reason": reason
                    })
                    .to_string(),
                ))
                .unwrap())
        }
        _ => {
            // Allow or Flag - forward to upstream
            forward_to_upstream(&state, parts, payload).await
        }
    }
}

async fn extract_payload(
    parts: &http::request::Parts,
    body: Body,
) -> anyhow::Result<RequestPayload> {
    let method = parts.method.to_string();
    let path = parts.uri.path().to_string();

    // Extract headers
    let mut headers = HashMap::new();
    for (name, value) in &parts.headers {
        if let Ok(value_str) = value.to_str() {
            headers.insert(name.to_string(), value_str.to_string());
        }
    }

    // Extract query params
    let mut query_params = HashMap::new();
    if let Some(query) = parts.uri.query() {
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                query_params.insert(
                    key.to_string(),
                    urlencoding::decode(value).unwrap_or_default().to_string(),
                );
            }
        }
    }

    // Extract body
    let body_bytes = body.collect().await?.to_bytes();
    let body_str = if body_bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&body_bytes).to_string())
    };

    // Extract IP address
    let ip_addr = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("X-Forwarded-For"))
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());

    Ok(RequestPayload::new(
        method,
        path,
        headers,
        body_str,
        query_params,
        ip_addr,
    ))
}

async fn forward_to_upstream(
    state: &AppState,
    parts: http::request::Parts,
    payload: RequestPayload,
) -> Result<Response<Body>, StatusCode> {
    // Reconstruct the upstream URI
    let upstream_uri = format!(
        "{}{}{}",
        state.upstream_url,
        parts.uri.path(),
        parts
            .uri
            .query()
            .map(|q| format!("?{}", q))
            .unwrap_or_default()
    );

    let uri: Uri = upstream_uri.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

    // Reconstruct the request
    let mut upstream_req = Request::builder().method(parts.method).uri(uri);

    // Copy headers (except host)
    for (name, value) in &parts.headers {
        if name != "host" {
            upstream_req = upstream_req.header(name, value);
        }
    }

    // Reconstruct body
    let body = if let Some(body_content) = payload.body {
        Body::from(body_content)
    } else {
        Body::empty()
    };

    let upstream_req = upstream_req
        .body(body)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Forward the request
    match state.upstream_client.request(upstream_req).await {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            let body = body
                .map_err(std::io::Error::other)
                .boxed();
            let response = Response::from_parts(parts, Body::new(body));
            Ok(response)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to forward request to upstream");
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

/// Health check endpoint
pub async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_query_params() {
        let uri: Uri = "http://example.com/path?foo=bar&baz=qux".parse().unwrap();
        let query = uri.query().unwrap();

        let mut params = HashMap::new();
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                params.insert(key.to_string(), value.to_string());
            }
        }

        assert_eq!(params.get("foo"), Some(&"bar".to_string()));
        assert_eq!(params.get("baz"), Some(&"qux".to_string()));
    }

    #[tokio::test]
    async fn test_extract_payload_basic() {
        let uri: Uri = "/test/path".parse().unwrap();
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        let (parts, body) = request.into_parts();
        let payload = extract_payload(&parts, body).await.unwrap();

        assert_eq!(payload.method, "GET");
        assert_eq!(payload.path, "/test/path");
        assert!(payload.body.is_none());
        assert!(payload.query_params.is_empty());
    }

    #[tokio::test]
    async fn test_extract_payload_with_query_params() {
        let uri: Uri = "/search?q=test&limit=10".parse().unwrap();
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        let (parts, body) = request.into_parts();
        let payload = extract_payload(&parts, body).await.unwrap();

        assert_eq!(payload.method, "GET");
        assert_eq!(payload.path, "/search");
        assert_eq!(payload.query_params.get("q"), Some(&"test".to_string()));
        assert_eq!(payload.query_params.get("limit"), Some(&"10".to_string()));
    }

    #[tokio::test]
    async fn test_extract_payload_with_body() {
        let uri: Uri = "/api/users".parse().unwrap();
        let body_content = r#"{"name":"John","age":30}"#;
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body_content))
            .unwrap();

        let (parts, body) = request.into_parts();
        let payload = extract_payload(&parts, body).await.unwrap();

        assert_eq!(payload.method, "POST");
        assert_eq!(payload.path, "/api/users");
        assert_eq!(payload.body, Some(r#"{"name":"John","age":30}"#.to_string()));
        assert_eq!(
            payload.headers.get("content-type"),
            Some(&"application/json".to_string())
        );
    }

    #[tokio::test]
    async fn test_extract_payload_with_headers() {
        let uri: Uri = "/api/secure".parse().unwrap();
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .header("authorization", "Bearer token123")
            .header("user-agent", "TestClient/1.0")
            .body(Body::empty())
            .unwrap();

        let (parts, body) = request.into_parts();
        let payload = extract_payload(&parts, body).await.unwrap();

        assert_eq!(
            payload.headers.get("authorization"),
            Some(&"Bearer token123".to_string())
        );
        assert_eq!(
            payload.headers.get("user-agent"),
            Some(&"TestClient/1.0".to_string())
        );
    }

    #[tokio::test]
    async fn test_extract_payload_with_ip_from_x_forwarded_for() {
        let uri: Uri = "/".parse().unwrap();
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .header("x-forwarded-for", "192.168.1.100, 10.0.0.1")
            .body(Body::empty())
            .unwrap();

        let (parts, body) = request.into_parts();
        let payload = extract_payload(&parts, body).await.unwrap();

        // Should extract first IP from X-Forwarded-For
        assert_eq!(payload.ip_addr, Some("192.168.1.100".to_string()));
    }

    #[tokio::test]
    async fn test_extract_payload_with_encoded_query_params() {
        let uri: Uri = "/search?q=hello%20world&name=John%20Doe".parse().unwrap();
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        let (parts, body) = request.into_parts();
        let payload = extract_payload(&parts, body).await.unwrap();

        assert_eq!(payload.query_params.get("q"), Some(&"hello world".to_string()));
        assert_eq!(
            payload.query_params.get("name"),
            Some(&"John Doe".to_string())
        );
    }

    #[tokio::test]
    async fn test_extract_payload_normalized_hash() {
        let uri: Uri = "/test?a=1&b=2".parse().unwrap();
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .body(Body::from("test body"))
            .unwrap();

        let (parts, body) = request.into_parts();
        let payload = extract_payload(&parts, body).await.unwrap();

        // Hash should be deterministic and non-empty
        assert!(!payload.normalized_hash.is_empty());
        assert_eq!(payload.normalized_hash.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_app_state_creation() {
        use crate::core::judge::Judge;
        use crate::core::rulebook::Rulebook;
        use crate::llm::client::mock::MockLlmProvider;
        use crate::storage::logs::LogStore;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let llm = Arc::new(MockLlmProvider::new());
        let rulebook = Arc::new(RwLock::new(Rulebook::new()));
        let judge = Arc::new(Judge::new(
            llm,
            None,
            rulebook,
            std::time::Duration::from_secs(1),
            crate::config::FailMode::Open,
        ));

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let logs = runtime.block_on(async {
            let temp_dir = tempfile::tempdir().unwrap();
            let db_path = temp_dir.path().join("test.db");
            Arc::new(LogStore::new(&db_path).await.unwrap())
        });

        let state = AppState::new(judge, logs, "http://backend:3000".to_string());

        assert_eq!(state.upstream_url, "http://backend:3000");
    }

    #[tokio::test]
    async fn test_health_handler() {
        let response = health_handler().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
