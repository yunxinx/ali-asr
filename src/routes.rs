use axum::{
    extract::Multipart,
    http::HeaderMap,
    response::Response,
};
use bytes::Bytes;

use crate::{
    error::{ApiError, AppResult},
    services::dashscope::handle_dashscope,
    utils::{extract_bearer_token, parse_model_config},
};

pub const MAX_UPLOAD_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

pub async fn transcribe(
    headers: HeaderMap,
    mut multipart: Multipart,
) -> AppResult<Response> {
    tracing::info!("Received transcription request");

    // 解析表单数据（内存中读取，快速释放）
    let mut file_data: Option<Bytes> = None;
    let mut filename = "upload".to_string();
    let mut language = "auto".to_string();
    let mut prompt = String::new();
    let mut model = String::new();

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        tracing::error!("Failed to parse multipart field: {}", e);
        ApiError::new(axum::http::StatusCode::BAD_REQUEST, format!("Invalid multipart data: {}", e))
    })? {
        match field.name().unwrap_or("") {
            "file" => {
                filename = field.file_name().unwrap_or("upload").to_string();
                let bytes = field.bytes().await.map_err(|e| {
                    tracing::error!("Failed to read file data: {}", e);
                    ApiError::new(axum::http::StatusCode::BAD_REQUEST, format!("Failed to read file data: {}", e))
                })?;
                if bytes.len() > MAX_UPLOAD_BYTES {
                    tracing::warn!(
                        "Uploaded file too large: {} ({} bytes > {} bytes)",
                        filename,
                        bytes.len(),
                        MAX_UPLOAD_BYTES
                    );
                    return Err(ApiError::new(
                        axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                        format!(
                            "File too large: {} bytes (max {} bytes)",
                            bytes.len(),
                            MAX_UPLOAD_BYTES
                        ),
                    ));
                }
                file_data = Some(bytes);
            }
            "language" => language = field.text().await.unwrap_or("auto".to_string()),
            "prompt" => prompt = field.text().await.unwrap_or_default(),
            "model" => model = field.text().await.unwrap_or_default(),
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    let file_data = file_data.ok_or_else(|| {
        tracing::error!("Missing file in request");
        ApiError::new(axum::http::StatusCode::BAD_REQUEST, "Missing file")
    })?;

    tracing::info!("File received: {} ({} bytes)", filename, file_data.len());

    // 解析模型配置
    let (clean_model, enable_itn, enable_stream) = parse_model_config(&model);
    let final_model = if clean_model.is_empty() { "qwen3-asr-flash" } else { clean_model };

    tracing::debug!(
        "Language: {}, Original Model: {}, Prompt length: {}",
        language,
        model,
        prompt.len()
    );
    tracing::debug!(
        "Using clean model: {}, ITN enabled: {}, Stream enabled: {}",
        final_model,
        enable_itn,
        enable_stream
    );

    // 检查必须的Bearer token
    let api_key = extract_bearer_token(&headers).ok_or_else(|| {
        tracing::error!("Missing required Bearer token");
        ApiError::new(
            axum::http::StatusCode::UNAUTHORIZED,
            "Authorization header with Bearer token is required",
        )
    })?;

    // 使用DashScope服务
    tracing::info!("Using DashScope service");
    let result = handle_dashscope(
        &api_key,
        &file_data,
        &filename,
        &language,
        &prompt,
        final_model,
        enable_itn,
        enable_stream,
    )
    .await;

    match &result {
        Ok(_) => tracing::info!("DashScope request completed successfully"),
        Err(e) => tracing::error!("DashScope request failed with status: {}", e.status),
    }

    result
}

pub async fn health_check() -> &'static str {
    "ok"
}
