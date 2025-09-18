use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub type AppResult<T> = Result<T, ApiError>;

pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }
}

impl<E: std::fmt::Display> From<(StatusCode, E)> for ApiError {
    fn from(value: (StatusCode, E)) -> Self {
        ApiError::new(value.0, value.1.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse { error: self.message });
        (self.status, body).into_response()
    }
}

// 统一错误结构后，移除对 anyhow 的适配，调用处直接构造 ApiError 即可。
