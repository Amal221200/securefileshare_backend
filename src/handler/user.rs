use std::sync::Arc;

use axum::{
    extract::Query,
    response::IntoResponse,
    routing::{get, put},
    Extension, Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use crate::{
    db::UserExt,
    dtos::{
        EmailListResponseDto, FilterEmailDto, FilterUserDto, NameUpdateDto, Response,
        SearchQueryByEmailDTO, UserData, UserPasswordUpdateDto, UserResponseDto,
    },
    error::{ErrorMessage, HttpError},
    middleware::JWTAuthMiddleware,
    utils::password,
    AppState,
};

pub fn user_handler() -> Router {
    Router::new()
        .route("/me", get(get_me))
        .route("/name", put(update_user_name))
        .route("/password", put(update_user_password))
        .route("/search-email", get(search_by_email))
}

pub async fn get_me(
    Extension(_app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
) -> Result<impl IntoResponse, HttpError> {
    let filtered_user = FilterUserDto::filter_user(&user.user);

    let response_data = UserResponseDto {
        data: UserData {
            user: filtered_user,
        },
        status: "success".to_string(),
    };
    Ok(Json(response_data))
}

pub async fn update_user_name(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<NameUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;
    let user_id = Uuid::parse_str(&user.id.to_string()).unwrap();

    let result = app_state
        .db_client
        .update_user_name(user_id.clone(), body.name)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let filtered_user = FilterUserDto::filter_user(&result);
    let response_data = UserResponseDto {
        data: UserData {
            user: filtered_user,
        },
        status: "success".to_string(),
    };

    Ok(Json(response_data))
}

pub async fn update_user_password(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<UserPasswordUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;
    let user_id = Uuid::parse_str(&user.id.to_string()).unwrap();

    let result = app_state
        .db_client
        .get_user(Some(user_id.clone()), None, None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::bad_request(
        ErrorMessage::InvalidToken.to_string(),
    ))?;

    let verify_password = password::compare(&body.old_password, &user.password)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    if !verify_password {
        return Err(HttpError::bad_request(
            "Old password is not correct".to_string(),
        ));
    }

    let new_hashed_password =
        password::hash(&body.new_password).map_err(|e| HttpError::server_error(e.to_string()))?;

    app_state
        .db_client
        .update_user_password(user_id.clone(), new_hashed_password)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response_data = Response {
        message: "User password updated successfully".to_string(),
        status: "success",
    };

    Ok(Json(response_data))
}

pub async fn search_by_email(
    Query(params): Query<SearchQueryByEmailDTO>,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
) -> Result<impl IntoResponse, HttpError> {
    params
        .validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let query_pattern = format!("%{}%", params.query);

    let user = &user.user;
    let user_id = Uuid::parse_str(&user.id.to_string()).unwrap();

    let result = app_state
        .db_client
        .search_by_email(user_id.clone(), query_pattern.clone())
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let filtered_emails = FilterEmailDto::filter_emails(&result);

    let response_data = EmailListResponseDto {
        emails: filtered_emails,
        status: "success".to_string(),
    };
    Ok(Json(response_data))
}
