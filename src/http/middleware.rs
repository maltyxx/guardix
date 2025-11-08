use axum::{
    body::Body,
    http::{Request, Response},
    middleware::Next,
};
use std::time::Instant;

/// Tracing middleware that logs request details and duration
pub async fn tracing_middleware(
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, axum::http::StatusCode> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let start = Instant::now();

    tracing::debug!(
        method = %method,
        uri = %uri,
        "Request started"
    );

    let response = next.run(req).await;

    let duration = start.elapsed();
    let status = response.status();

    tracing::info!(
        method = %method,
        uri = %uri,
        status = %status.as_u16(),
        duration_ms = duration.as_millis(),
        "Request completed"
    );

    Ok(response)
}

/// Normalize headers to lowercase for consistent processing
/// Reserved for future header normalization logic
#[allow(dead_code)]
pub async fn normalize_headers_middleware(
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, axum::http::StatusCode> {
    // Headers are already case-insensitive in HTTP/2, but we ensure consistency
    // This is mainly for logging and debugging purposes
    let response = next.run(req).await;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::{middleware, Router};
    use tower::ServiceExt;

    async fn test_handler() -> &'static str {
        "OK"
    }

    #[tokio::test]
    async fn test_tracing_middleware() {
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn(tracing_middleware));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), 200);
    }
}
