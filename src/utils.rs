use axum::http::{header, HeaderMap};

pub fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?
        .trim()
        .to_string()
        .into()
}


// 解析模型名，返回 (clean_model, enable_itn, enable_stream)
pub fn parse_model_config<'a>(model: &'a str) -> (&'a str, bool, bool) {
    // 统一小写用于判定（避免重复分配）
    let lower = model.to_lowercase();
    let mut lower_view: &str = &lower;

    let enable_itn = lower_view.contains(":itn");
    let enable_stream = lower_view.ends_with(":stream");

    // 按顺序无关地移除可选后缀（大小写不敏感）
    let mut clean_model: &str = model;
    if enable_stream {
        clean_model = &clean_model[..clean_model.len() - ":stream".len()];
        lower_view = &lower_view[..lower_view.len() - ":stream".len()];
    }
    if lower_view.ends_with(":itn") {
        clean_model = &clean_model[..clean_model.len() - ":itn".len()];
    }

    tracing::debug!(
        "Model parsing: '{}' -> clean: '{}', itn: {}, stream: {}",
        model,
        clean_model,
        enable_itn,
        enable_stream
    );

    (clean_model, enable_itn, enable_stream)
}
