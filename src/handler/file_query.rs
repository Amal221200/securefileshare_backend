use std::sync::Arc;

use axum::{extract::Query, response::IntoResponse, routing::get, Extension, Json, Router};
use uuid::Uuid;
use validator::Validate;

use crate::{
    db::UserExt,
    dtos::{
        RequestQueryDto, UserReceiveFileDto, UserReceiveFileListResponseDto, UserSendFileDto,
        UserSendFileListResponseDto,
    },
    error::HttpError,
    middleware::JWTAuthMiddleware,
    AppState,
};

pub fn get_file_list_handler() -> Router {
    Router::new()
        .route("/send", get(get_user_shared_files))
        .route("/receive", get(get_user_receive_shared_files))
}

pub async fn get_user_shared_files(
    Query(query_params): Query<RequestQueryDto>,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
) -> Result<impl IntoResponse, HttpError> {
    query_params
        .validate()
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = &user.user;
    let user_id = Uuid::parse_str(&user.id.to_string()).unwrap();

    let page = query_params.page.unwrap_or(1);
    let limit = query_params.limit.unwrap_or(10);

    let (shared_files, total_count) = app_state
        .db_client
        .get_sent_files(user_id, page as u32, limit)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let filter_send_files = UserSendFileDto::filter_send_user_files(&shared_files);

    let response = UserSendFileListResponseDto {
        files: filter_send_files,
        results: total_count,
        status: "success".to_string(),
    };
    Ok(Json(response))
}

pub async fn get_user_receive_shared_files(
    Query(query_params): Query<RequestQueryDto>,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
) -> Result<impl IntoResponse, HttpError> {
    query_params
        .validate()
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = &user.user;
    let user_id = Uuid::parse_str(&user.id.to_string()).unwrap();

    let page = query_params.page.unwrap_or(1);
    let limit = query_params.limit.unwrap_or(10);

    let (recieve_files, total_count) = app_state
        .db_client
        .get_recieved_files(user_id, page as u32, limit)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let filter_receive_files = UserReceiveFileDto::filter_receive_user_files(&recieve_files);

    let response = UserReceiveFileListResponseDto {
        files: filter_receive_files,
        results: total_count,
        status: "success".to_string(),
    };
    Ok(Json(response))
}
