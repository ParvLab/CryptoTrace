use std::sync::Arc;
use std::time::Duration;

/// Integration tests for the REST API server.
/// Spins up the server on a random port and makes HTTP requests.

struct TestServer {
    addr: String,
    client: reqwest::Client,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl TestServer {
    /// Start a server on a random port and return a handle.
    async fn start() -> Self {
        let state = Arc::new(cryptotrace::api::routes::AppState {
            startup_time: std::time::Instant::now(),
            engine_version: "0.1.0-test".to_string(),
            sig_db_version: "test".to_string(),
            sandbox: None,
            job_queue: None,
        });

        let rate_limiter = Arc::new(cryptotrace::api::auth::RateLimiter::new(1000));

        let mut router = axum::Router::new()
            .route("/health", axum::routing::get(cryptotrace::api::routes::health))
            .route("/version", axum::routing::get(cryptotrace::api::routes::version))
            .route("/analyze", axum::routing::post(cryptotrace::api::routes::analyze))
            .layer(axum::middleware::from_fn(cryptotrace::api::auth::auth_middleware));

        // Inject rate limiter
        router = router.layer(axum::middleware::from_fn(
            move |mut req: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| {
                let rl = rate_limiter.clone();
                async move {
                    req.extensions_mut().insert(rl);
                    next.run(req).await
                }
            },
        ));

        // Inject state
        router = router.layer(axum::middleware::from_fn(
            move |mut req: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| {
                let state = state.clone();
                async move {
                    req.extensions_mut().insert(state);
                    next.run(req).await
                }
            },
        ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let addr_str = format!("http://{}", addr);

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async { rx.await.ok(); })
                .await
                .ok();
        });

        // Give server a moment to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        Self {
            addr: addr_str,
            client,
            _shutdown: tx,
        }
    }
}

#[tokio::test]
async fn test_health_endpoint() {
    let server = TestServer::start().await;
    let resp = server
        .client
        .get(&format!("{}/health", server.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert!(body["uptime_seconds"].as_u64().is_some());
}

#[tokio::test]
async fn test_version_endpoint() {
    let server = TestServer::start().await;
    let resp = server
        .client
        .get(&format!("{}/version", server.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["engine"].as_str().is_some());
    assert!(body["signature_db"].as_str().is_some());
}

#[tokio::test]
async fn test_analyze_string() {
    let server = TestServer::start().await;
    let resp = server
        .client
        .post(&format!("{}/analyze", server.addr))
        .json(&serde_json::json!({
            "input": "5f4dcc3b5aa765d61d8327deb882cf99",
            "input_type": "string",
            "context": "forensics",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["detected_type"], "hash");
    assert_eq!(body["algorithm"], "MD5");
    assert!(body["confidence"].as_f64().unwrap() > 0.0);
}

#[tokio::test]
async fn test_analyze_base64() {
    let server = TestServer::start().await;
    // "hello" in base64
    let resp = server
        .client
        .post(&format!("{}/analyze", server.addr))
        .json(&serde_json::json!({
            "input": "aGVsbG8=",
            "input_type": "base64",
            "context": "forensics",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["entropy"].as_f64().unwrap() > 0.0);
}

#[tokio::test]
async fn test_analyze_bad_request() {
    let server = TestServer::start().await;
    let resp = server
        .client
        .post(&format!("{}/analyze", server.addr))
        .json(&serde_json::json!({
            "input": "/nonexistent/file.txt",
            "input_type": "file",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "bad_request");
}

#[tokio::test]
async fn test_health_with_auth() {
    let state = Arc::new(cryptotrace::api::routes::AppState {
        startup_time: std::time::Instant::now(),
        engine_version: "0.1.0-test".to_string(),
        sig_db_version: "test".to_string(),
        sandbox: None,
        job_queue: None,
    });

    let rate_limiter = Arc::new(cryptotrace::api::auth::RateLimiter::new(1000));

    let mut router = axum::Router::new()
        .route("/health", axum::routing::get(cryptotrace::api::routes::health))
        .route("/analyze", axum::routing::post(cryptotrace::api::routes::analyze))
        .layer(axum::middleware::from_fn(cryptotrace::api::auth::auth_middleware));

    // Inject API key
    let api_key = "test-key-123".to_string();
    router = router.layer(axum::middleware::from_fn(
        move |mut req: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| {
            let key = api_key.clone();
            async move {
                req.extensions_mut().insert(key);
                next.run(req).await
            }
        },
    ));

    router = router.layer(axum::middleware::from_fn(
        move |mut req: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| {
            let rl = rate_limiter.clone();
            async move {
                req.extensions_mut().insert(rl);
                next.run(req).await
            }
        },
    ));

    router = router.layer(axum::middleware::from_fn(
        move |mut req: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| {
            let state = state.clone();
            async move {
                req.extensions_mut().insert(state);
                next.run(req).await
            }
        },
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let addr_str = format!("http://{}", addr);

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async { rx.await.ok(); })
            .await
            .ok();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Request without API key should fail
    let resp = client
        .get(&format!("{}/health", addr_str))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Request with API key should succeed
    let resp = client
        .get(&format!("{}/health", addr_str))
        .header("Authorization", "Bearer test-key-123")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Request with X-API-Key header should succeed
    let resp = client
        .get(&format!("{}/health", addr_str))
        .header("X-API-Key", "test-key-123")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let _ = tx.send(());
}
