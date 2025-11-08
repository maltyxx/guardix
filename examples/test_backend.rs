/// Simple test backend server for WAF testing
/// Run with: cargo run --example test_backend
use axum::{
    http::{HeaderMap, Method, Uri},
    response::{Html, IntoResponse},
    routing::{any, get},
    Router,
};

async fn health() -> &'static str {
    "OK - Test Backend"
}


/// Displays all request information in a beautiful HTML page
async fn echo_request(
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // Extract query parameters
    let query_params: Vec<(String, String)> = uri
        .query()
        .map(|q| {
            q.split('&')
                .filter_map(|pair| {
                    let mut split = pair.split('=');
                    Some((
                        split.next()?.to_string(),
                        split.next().unwrap_or("").to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    // Format headers
    let headers_html: String = headers
        .iter()
        .map(|(name, value)| {
            format!(
                "<tr><td class='header-name'>{}</td><td class='header-value'>{}</td></tr>",
                name,
                value.to_str().unwrap_or("???")
            )
        })
        .collect();

    // Format query params
    let query_html: String = if query_params.is_empty() {
        "<tr><td colspan='2' class='empty'>Aucun paramètre</td></tr>".to_string()
    } else {
        query_params
            .iter()
            .map(|(key, val)| {
                format!(
                    "<tr><td class='param-key'>{}</td><td class='param-value'>{}</td></tr>",
                    key, val
                )
            })
            .collect()
    };

    // Body preview
    let body_preview = if body.is_empty() {
        "<span class='empty'>Aucun body</span>".to_string()
    } else if body.len() > 1000 {
        format!("{}... <span class='truncated'>(tronqué)</span>", &body[..1000])
    } else {
        body.clone()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔍 Request Inspector - Guardix Backend</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 2rem;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }}
        .header p {{
            opacity: 0.9;
            font-size: 1.1rem;
        }}
        .content {{
            padding: 2rem;
        }}
        .section {{
            margin-bottom: 2rem;
            background: #f8f9fa;
            border-radius: 12px;
            padding: 1.5rem;
            border-left: 4px solid #667eea;
        }}
        .section-title {{
            font-size: 1.5rem;
            color: #667eea;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .method {{
            display: inline-block;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-weight: bold;
            font-size: 1.2rem;
            color: white;
        }}
        .method.GET {{ background: #28a745; }}
        .method.POST {{ background: #007bff; }}
        .method.PUT {{ background: #ffc107; }}
        .method.DELETE {{ background: #dc3545; }}
        .method.PATCH {{ background: #6c757d; }}
        .uri {{
            font-family: 'Courier New', monospace;
            background: #e9ecef;
            padding: 1rem;
            border-radius: 8px;
            margin-top: 1rem;
            word-break: break-all;
            font-size: 1.1rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }}
        th {{
            background: #667eea;
            color: white;
            font-weight: 600;
        }}
        tr:hover {{
            background: #f1f3f5;
        }}
        .header-name, .param-key {{
            font-weight: 600;
            color: #495057;
            font-family: 'Courier New', monospace;
        }}
        .header-value, .param-value {{
            color: #6c757d;
            font-family: 'Courier New', monospace;
        }}
        .body-preview {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 1.5rem;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            line-height: 1.6;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .empty {{
            color: #adb5bd;
            font-style: italic;
        }}
        .truncated {{
            color: #ffc107;
            font-size: 0.9rem;
        }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.85rem;
            font-weight: 600;
            background: #e9ecef;
            color: #495057;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 1rem 2rem;
            text-align: center;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
        }}
        .emoji {{
            font-size: 1.3rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Request Inspector</h1>
            <p>Backend de test Guardix - Toutes les informations de la requête</p>
        </div>
        
        <div class="content">
            <!-- Method & URI -->
            <div class="section">
                <h2 class="section-title"><span class="emoji">📡</span> Méthode & URI</h2>
                <div>
                    <span class="method {}">{}</span>
                </div>
                <div class="uri">{}</div>
            </div>

            <!-- Headers -->
            <div class="section">
                <h2 class="section-title"><span class="emoji">📋</span> Headers <span class="badge">{} headers</span></h2>
                <table>
                    <thead>
                        <tr>
                            <th>Header</th>
                            <th>Valeur</th>
                        </tr>
                    </thead>
                    <tbody>
                        {}
                    </tbody>
                </table>
            </div>

            <!-- Query Parameters -->
            <div class="section">
                <h2 class="section-title"><span class="emoji">🔍</span> Query Parameters <span class="badge">{} params</span></h2>
                <table>
                    <thead>
                        <tr>
                            <th>Paramètre</th>
                            <th>Valeur</th>
                        </tr>
                    </thead>
                    <tbody>
                        {}
                    </tbody>
                </table>
            </div>

            <!-- Body -->
            <div class="section">
                <h2 class="section-title"><span class="emoji">📦</span> Body <span class="badge">{} bytes</span></h2>
                <div class="body-preview">{}</div>
            </div>
        </div>

        <div class="footer">
            <p>🛡️ <strong>Guardix Test Backend</strong> - Test environment for the AI-powered WAF</p>
        </div>
    </div>
</body>
</html>"#,
        method.as_str(),
        method.as_str(),
        uri,
        headers.len(),
        headers_html,
        query_params.len(),
        query_html,
        body.len(),
        body_preview
    );

    Html(html)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/health", get(health))
        .fallback(any(echo_request));

    let addr = "0.0.0.0:3000";
    tracing::info!("🎯 Test backend listening on http://{}", addr);
    tracing::info!("   This is an INTENTIONALLY VULNERABLE backend for WAF testing");
    tracing::info!("   DO NOT USE IN PRODUCTION");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
