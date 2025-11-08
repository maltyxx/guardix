/// End-to-End Tests for Guardix
///
/// These tests verify that the WAF correctly detects and blocks real attacks
/// by running the full stack (backend + WAF) and sending actual HTTP requests.
///
/// Test categories:
/// 1. SQL Injection attacks → should be blocked (403)
/// 2. XSS attacks → should be blocked (403)
/// 3. Path traversal attacks → should be blocked (403)
/// 4. Command injection attacks → should be blocked (403)
/// 5. Legitimate requests → should pass (200)
/// 6. Edge cases → should handle gracefully

use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::time::sleep;

/// Test configuration
const WAF_PORT: u16 = 5000;
const BACKEND_PORT: u16 = 3000;
const STARTUP_WAIT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(35); // Must be > judge_timeout_ms (30s)

/// Helper struct to manage background processes
struct TestEnvironment {
    backend: Option<Child>,
    waf: Option<Child>,
    client: reqwest::Client,
}

impl TestEnvironment {
    /// Start the test environment (backend + WAF)
    async fn setup() -> Result<Self, Box<dyn std::error::Error>> {
        println!("🚀 Starting test environment...");

        // Start backend
        println!("  ↳ Starting backend on port {}", BACKEND_PORT);
        let backend = Command::new("cargo")
            .args(["run", "--example", "test_backend"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        // Wait a bit for backend to be ready
        sleep(Duration::from_secs(2)).await;

        // Start WAF
        println!("  ↳ Starting WAF on port {}", WAF_PORT);
        let waf = Command::new("cargo")
            .args(["run"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        // Wait for services to be ready
        println!("  ↳ Waiting {}s for services to be ready...", STARTUP_WAIT.as_secs());
        sleep(STARTUP_WAIT).await;

        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        // Verify WAF is responsive
        let health_check = client
            .get(format!("http://localhost:{}/health", WAF_PORT))
            .send()
            .await;

        if health_check.is_err() {
            return Err("WAF health check failed - services may not be ready".into());
        }

        println!("✅ Test environment ready!\n");

        Ok(Self {
            backend: Some(backend),
            waf: Some(waf),
            client,
        })
    }

    /// Send a GET request through the WAF
    async fn get(&self, path: &str) -> reqwest::Result<reqwest::Response> {
        self.client
            .get(format!("http://localhost:{}{}", WAF_PORT, path))
            .send()
            .await
    }

    /// Send a POST request through the WAF
    async fn post(&self, path: &str, body: &str) -> reqwest::Result<reqwest::Response> {
        self.client
            .post(format!("http://localhost:{}{}", WAF_PORT, path))
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        println!("\n🧹 Cleaning up test environment...");
        
        if let Some(mut waf) = self.waf.take() {
            let _ = waf.start_kill();
            println!("  ↳ WAF stopped");
        }
        
        if let Some(mut backend) = self.backend.take() {
            let _ = backend.start_kill();
            println!("  ↳ Backend stopped");
        }
    }
}

// ============================================================================
// SQL INJECTION TESTS
// ============================================================================

#[tokio::test]
#[ignore] // Run with: cargo test --test e2e_tests -- --ignored --test-threads=1
async fn test_sqli_classic_tautology() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🔴 Testing: SQL Injection - Classic tautology");
    let response = env.get("/users?id=1' OR '1'='1").await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        403,
        "Classic SQL injection should be blocked"
    );
    
    let body = response.text().await.unwrap();
    assert!(body.contains("blocked"), "Response should indicate blocking");
    println!("✅ BLOCKED as expected\n");
}

#[tokio::test]
#[ignore]
async fn test_sqli_union_select() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🔴 Testing: SQL Injection - UNION SELECT");
    let response = env.get("/users?id=1 UNION SELECT password FROM users--").await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        403,
        "UNION SELECT injection should be blocked"
    );
    println!("✅ BLOCKED as expected\n");
}

#[tokio::test]
#[ignore]
async fn test_sqli_drop_table() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🔴 Testing: SQL Injection - DROP TABLE");
    let response = env.get("/users?id=1'; DROP TABLE users--").await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        403,
        "DROP TABLE injection should be blocked"
    );
    println!("✅ BLOCKED as expected\n");
}

#[tokio::test]
#[ignore]
async fn test_sqli_in_post_body() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🔴 Testing: SQL Injection in POST body");
    let payload = r#"{"username":"admin","password":"' OR '1'='1"}"#;
    let response = env.post("/login", payload).await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        403,
        "SQL injection in POST body should be blocked"
    );
    println!("✅ BLOCKED as expected\n");
}

// ============================================================================
// XSS (Cross-Site Scripting) TESTS
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_xss_script_tag() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🔴 Testing: XSS - <script> tag");
    let response = env.get("/search?q=<script>alert('xss')</script>").await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        403,
        "XSS with <script> tag should be blocked"
    );
    println!("✅ BLOCKED as expected\n");
}

#[tokio::test]
#[ignore]
async fn test_xss_onerror() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🔴 Testing: XSS - onerror attribute");
    let response = env.get("/search?q=<img src=x onerror=alert(1)>").await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        403,
        "XSS with onerror should be blocked"
    );
    println!("✅ BLOCKED as expected\n");
}

#[tokio::test]
#[ignore]
async fn test_xss_javascript_protocol() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🔴 Testing: XSS - javascript: protocol");
    let response = env.get("/redirect?url=javascript:alert('xss')").await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        403,
        "XSS with javascript: protocol should be blocked"
    );
    println!("✅ BLOCKED as expected\n");
}

// ============================================================================
// PATH TRAVERSAL TESTS
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_path_traversal_etc_passwd() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🔴 Testing: Path Traversal - /etc/passwd");
    let response = env.get("/files?path=../../etc/passwd").await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        403,
        "Path traversal to /etc/passwd should be blocked"
    );
    println!("✅ BLOCKED as expected\n");
}

#[tokio::test]
#[ignore]
async fn test_path_traversal_in_url_path() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🔴 Testing: Path Traversal - in URL path");
    let response = env.get("/uploads/../../../etc/passwd").await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        403,
        "Path traversal in URL path should be blocked"
    );
    println!("✅ BLOCKED as expected\n");
}

// ============================================================================
// COMMAND INJECTION TESTS
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_command_injection_semicolon() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🔴 Testing: Command Injection - semicolon");
    let response = env.get("/ping?host=google.com; cat /etc/passwd").await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        403,
        "Command injection with semicolon should be blocked"
    );
    println!("✅ BLOCKED as expected\n");
}

#[tokio::test]
#[ignore]
async fn test_command_injection_pipe() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🔴 Testing: Command Injection - pipe");
    let response = env.get("/exec?cmd=ls | whoami").await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        403,
        "Command injection with pipe should be blocked"
    );
    println!("✅ BLOCKED as expected\n");
}

#[tokio::test]
#[ignore]
async fn test_command_injection_backticks() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🔴 Testing: Command Injection - backticks");
    let response = env.get("/exec?cmd=`id`").await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        403,
        "Command injection with backticks should be blocked"
    );
    println!("✅ BLOCKED as expected\n");
}

// ============================================================================
// LEGITIMATE REQUESTS (SHOULD PASS)
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_legitimate_get_root() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🟢 Testing: Legitimate GET /");
    let response = env.get("/").await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        200,
        "Legitimate request to / should pass"
    );
    println!("✅ ALLOWED as expected\n");
}

#[tokio::test]
#[ignore]
async fn test_legitimate_get_with_normal_params() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🟢 Testing: Legitimate GET with normal params");
    let response = env.get("/api/users?page=1&limit=10").await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        200,
        "Legitimate request with normal params should pass"
    );
    println!("✅ ALLOWED as expected\n");
}

#[tokio::test]
#[ignore]
async fn test_legitimate_post_json() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🟢 Testing: Legitimate POST with JSON");
    let payload = r#"{"name":"John Doe","email":"john@example.com"}"#;
    let response = env.post("/api/users", payload).await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        200,
        "Legitimate POST with clean JSON should pass"
    );
    println!("✅ ALLOWED as expected\n");
}

#[tokio::test]
#[ignore]
async fn test_legitimate_search_normal_query() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🟢 Testing: Legitimate search query");
    let response = env.get("/search?q=hello+world").await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        200,
        "Legitimate search query should pass"
    );
    println!("✅ ALLOWED as expected\n");
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_health_endpoint() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🔵 Testing: Health endpoint");
    let response = env.get("/health").await.unwrap();
    
    println!("   Status: {}", response.status());
    assert_eq!(
        response.status(),
        200,
        "Health endpoint should always be accessible"
    );
    println!("✅ HEALTHY\n");
}

#[tokio::test]
#[ignore]
async fn test_empty_request() {
    let env = TestEnvironment::setup().await.expect("Failed to setup environment");

    println!("🔵 Testing: Empty request");
    let response = env.get("/api/test").await.unwrap();
    
    println!("   Status: {}", response.status());
    // Should pass through (200) or return 404, but not block (403)
    assert_ne!(
        response.status(),
        403,
        "Empty request should not be blocked"
    );
    println!("✅ Not blocked\n");
}

