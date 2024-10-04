use std::sync::Arc;

use axum::{response::IntoResponse, Extension, Json};

use crate::{error::HttpError, AppState};

pub async fn greet(
    Extension(_app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    Ok(Json("Hello from SecureShare".to_string()))
}
