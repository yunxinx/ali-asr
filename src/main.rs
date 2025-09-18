mod error;
mod http_client;
mod routes;
mod services;
mod utils;

use axum::{routing::{get, post}, Router};
use axum::extract::DefaultBodyLimit;
use clap::Parser;
use tower_http::cors;
use std::net::SocketAddr;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "3000")]
    port: u16,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    tracing::info!("Starting ASR Proxy Server (DashScope only)");
    tracing::info!("Port: {}", args.port);

    // 为上传路由添加请求体大小限制：为了兼容multipart开销，这里给出10MB基础上适当余量
    let transcribe_router = Router::new()
        .route("/v1/audio/transcriptions", post(routes::transcribe))
        .layer(DefaultBodyLimit::max(routes::MAX_UPLOAD_BYTES + 256 * 1024));

    let app = Router::new()
        .route("/healthz", get(routes::health_check))
        .merge(transcribe_router)
        .layer(
            cors::CorsLayer::new()
                .allow_methods(cors::Any)
                .allow_headers(cors::Any)
                .allow_origin(cors::Any),
        );

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to port");
    tracing::info!("Server listening on {}", addr);
    axum::serve(listener, app).await.expect("Server failed");
}
