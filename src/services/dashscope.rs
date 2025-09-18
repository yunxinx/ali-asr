use axum::{response::{IntoResponse, Response, Sse}, Json};
use futures_util::StreamExt;
use reqwest::multipart::{Form, Part};
use serde_json::{json, Value};
use bytes::Bytes;
use reqwest::Body;

use crate::{
    error::{ApiError, AppResult},
    http_client::HTTP_CLIENT,
};

#[derive(serde::Serialize)]
pub struct TranscriptionResponse {
    pub text: String,
}

pub async fn handle_dashscope(
    api_key: &str,
    file_data: &Bytes,
    filename: &str,
    language: &str,
    prompt: &str,
    model: &str,
    enable_itn: bool,
    stream: bool,
) -> AppResult<Response> {
    tracing::debug!("Starting DashScope processing");

    // 1. 获取上传策略 - 使用传入的模型名（已由上层清理）
    let policy_url = format!(
        "https://dashscope.aliyuncs.com/api/v1/uploads?action=getPolicy&model={}",
        urlencoding::encode(model)
    );

    tracing::debug!("Requesting upload policy: {}", policy_url);

    let policy_resp = HTTP_CLIENT
        .get(&policy_url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to get upload policy: {}", e);
            ApiError::new(axum::http::StatusCode::BAD_GATEWAY, format!("Failed to get upload policy: {}", e))
        })?;

    let policy: Value = policy_resp
        .json()
        .await
        .map_err(|e| {
            tracing::error!("Failed to parse policy response: {}", e);
            ApiError::new(axum::http::StatusCode::BAD_GATEWAY, format!("Failed to parse policy response: {}", e))
        })?;

    let policy_data = policy["data"].as_object().ok_or_else(|| {
        tracing::error!("Invalid policy response format");
        ApiError::new(axum::http::StatusCode::BAD_GATEWAY, "Invalid policy response")
    })?;

    tracing::debug!("Upload policy received successfully");

    // 2. 上传文件
    let upload_host = policy_data
        .get("upload_host")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::new(axum::http::StatusCode::BAD_GATEWAY, "Missing upload_host in policy response"))?
        .to_string();
    let upload_dir = policy_data.get("upload_dir").and_then(|v| v.as_str()).unwrap_or("");
    let key = if upload_dir.is_empty() {
        filename.to_string()
    } else {
        format!("{}/{}", upload_dir.trim_end_matches('/'), filename)
    };

    tracing::info!("Uploading file to OSS: {} -> {}", filename, key);

    // 按照OSS要求的字段顺序构建表单
    let mut form = Form::new();

    // 1. 首先添加policy相关字段
    let oss_access_key_id = policy_data
        .get("oss_access_key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::new(axum::http::StatusCode::BAD_GATEWAY, "Missing oss_access_key_id in policy response"))?
        .to_string();
    form = form.text("OSSAccessKeyId", oss_access_key_id);

    let signature = policy_data
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::new(axum::http::StatusCode::BAD_GATEWAY, "Missing signature in policy response"))?
        .to_string();
    form = form.text("Signature", signature);

    let policy_str = policy_data
        .get("policy")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::new(axum::http::StatusCode::BAD_GATEWAY, "Missing policy in policy response"))?
        .to_string();
    form = form.text("policy", policy_str);

    // 2. 添加所有可选的x-oss-*字段
    if let Some(acl) = policy_data.get("x_oss_object_acl").and_then(|v| v.as_str()) {
        form = form.text("x-oss-object-acl", acl.to_string());
    }
    if let Some(forbid_overwrite) = policy_data.get("x_oss_forbid_overwrite").and_then(|v| v.as_str()) {
        form = form.text("x-oss-forbid-overwrite", forbid_overwrite.to_string());
    }
    if let Some(security_token) = policy_data.get("x_oss_security_token").and_then(|v| v.as_str()) {
        form = form.text("x-oss-security-token", security_token.to_string());
    }

    // 3. 添加key和success_action_status
    form = form.text("key", key.clone());
    form = form.text("success_action_status", "200");

    // 4. 最后添加文件（这个顺序很重要）。直接使用 Bytes，近似零拷贝。
    let body = Body::from(file_data.clone());
    form = form.part("file", Part::stream(body).file_name(filename.to_string()));

    let upload_response = HTTP_CLIENT
        .post(upload_host)
        .multipart(form)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to upload file to OSS: {}", e);
            ApiError::new(axum::http::StatusCode::BAD_GATEWAY, format!("Failed to upload file to OSS: {}", e))
        })?;

    let upload_status = upload_response.status();
    if !upload_status.is_success() {
        let error_body = upload_response.text().await.unwrap_or_default();
        tracing::error!("OSS upload failed with status: {}, body: {}", upload_status, error_body);
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            format!("OSS upload failed: {}", error_body),
        ));
    }

    tracing::info!("File uploaded to OSS successfully");
    tracing::debug!("OSS upload response status: {}", upload_status);

    // 3. 调用 ASR
    let oss_url = format!("oss://{}", key);
    let asr_body = json!({
        "model": model,
        "result_format": "message",
        "input": {
            "messages": [
                {
                    "role": "system",
                    "content": [{"text": if prompt.trim().is_empty() { "" } else { prompt }}]
                },
                {
                    "role": "user",
                    "content": [{"audio": oss_url}]
                }
            ]
        },
        "parameters": {
            "asr_options": {
                "enable_lid": true,
                "enable_itn": enable_itn,
                "language": if language == "auto" { Value::Null } else { json!(language) }
            },
            "incremental_output": stream
        }
    });

    tracing::info!("Calling DashScope ASR API (stream: {})", stream);
    tracing::debug!("Sending ASR request to DashScope");

    let mut request = HTTP_CLIENT
        .post("https://dashscope.aliyuncs.com/api/v1/services/aigc/multimodal-generation/generation")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .header("X-DashScope-OssResourceResolve", "enable");

    if stream {
        request = request.header("X-DashScope-SSE", "enable");
    }

    let response = request
        .json(&asr_body)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to call DashScope ASR API: {}", e);
            ApiError::new(axum::http::StatusCode::BAD_GATEWAY, format!("Failed to call DashScope ASR API: {}", e))
        })?;

    tracing::debug!("DashScope API response status: {}", response.status());

    // 先检查响应状态，如果是错误就不按流式处理
    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        tracing::error!("DashScope API error: {}", error_text);

        // 尝试解析错误JSON
        if let Ok(error_json) = serde_json::from_str::<Value>(&error_text) {
            if let Some(error_code) = error_json.get("code").and_then(|c| c.as_str()) {
                let error_message = error_json.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
                return Err(ApiError::new(
                    axum::http::StatusCode::BAD_GATEWAY,
                    format!("DashScope API error: {} - {}", error_code, error_message),
                ));
            }
        }

        return Err(ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            format!("DashScope API error: {}", error_text),
        ));
    }

    if stream {
        tracing::info!("Processing streaming response");
        // 流式响应
        let stream = response.bytes_stream().map(|chunk| -> Result<axum::response::sse::Event, std::convert::Infallible> {
            match chunk {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);

                    // 解析SSE格式的数据，寻找data:行
                    for line in text.lines() {
                        if let Some(data) = line.strip_prefix("data:") {
                            let data = data.trim();

                            // 跳过空数据和结束标志
                            if data.is_empty() || data == "[DONE]" {
                                continue;
                            }

                            if let Ok(json) = serde_json::from_str::<Value>(data) {
                                // 检查是否是结束事件
                                if let Some(finish_reason) = json
                                    .get("output")
                                    .and_then(|o| o.get("choices"))
                                    .and_then(|c| c.as_array())
                                    .and_then(|arr| arr.first())
                                    .and_then(|choice| choice.get("finish_reason"))
                                    .and_then(|fr| fr.as_str())
                                {
                                    if finish_reason == "stop" {
                                        tracing::debug!("Stream finished");
                                        continue;
                                    }
                                }

                                // 提取文本内容
                                let text = extract_text_from_response(&json);
                                if !text.is_empty() {
                                    tracing::debug!("Extracted text from stream: {}", text);
                                    return Ok(axum::response::sse::Event::default().data(json!({"text": text}).to_string()));
                                }
                            }
                        }
                    }

                    // 如果没有提取到有效文本，返回空事件
                    Ok(axum::response::sse::Event::default().data(""))
                }
                Err(e) => {
                    tracing::error!("Stream error: {}", e);
                    Ok(axum::response::sse::Event::default().data(json!({"error": e.to_string()}).to_string()))
                }
            }
        });

        Ok(Sse::new(stream).into_response())
    } else {
        tracing::info!("Processing non-streaming response");
        // 非流式响应
        let result: Value = response
            .json()
            .await
            .map_err(|e| {
                tracing::error!("Failed to parse DashScope response: {}", e);
                ApiError::new(axum::http::StatusCode::BAD_GATEWAY, format!("Failed to parse DashScope response: {}", e))
            })?;

        // 检查DashScope是否返回了错误
        if let Some(error_code) = result.get("code").and_then(|c| c.as_str()) {
            let error_message = result.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
            tracing::error!("DashScope API error - Code: {}, Message: {}", error_code, error_message);
            return Err(ApiError::new(
                axum::http::StatusCode::BAD_GATEWAY,
                format!("DashScope API error: {} - {}", error_code, error_message),
            ));
        }

        let text = extract_text_from_response(&result);
        tracing::info!("Transcription completed, text length: {}", text.len());

        if text.is_empty() {
            tracing::warn!("Empty transcription result");
        } else {
            tracing::debug!("Transcription result: {}", text);
        }

        Ok(Json(TranscriptionResponse { text }).into_response())
    }
}

fn extract_text_from_response(json: &Value) -> String {
    // 先尝试获取 message 对象
    let message = json
        .get("output")
        .and_then(|o| o.get("choices"))
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|choice| choice.get("message"));

    // 检查 content 是否是数组
    if let Some(message) = message {
        if let Some(content_array) = message.get("content").and_then(|c| c.as_array()) {
        // 如果content数组为空，返回空字符串而不是None
            if content_array.is_empty() {
                return String::new();
            }

            // 查找包含 text 字段的第一个元素
            for item in content_array {
                if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                    return text.to_string();
                }
            }

            // 如果content数组不为空但没找到text字段，返回空字符串
            return String::new();
        }

        // 如果没找到，尝试直接从 message 中获取 text
        return message
            .get("text")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();
    }

    String::new()
}
