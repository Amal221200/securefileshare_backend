use crate::{
    db::UserExt,
    dtos::{LoginUserDto, RegisterUserDto, Response, UserLoginResponseDto},
    error::{ErrorMessage, HttpError},
    utils::{cookie::handle_cookie, keys::generate_key, password, token},
    AppState,
};
use axum::{http::StatusCode, response::IntoResponse, routing::post, Extension, Json, Router};
use std::sync::Arc;
use validator::Validate;

pub fn auth_handler() -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
}

pub async fn register(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<RegisterUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;
    let hash_password = password::hash(body.password.clone())
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let result = app_state
        .db_client
        .save_user(&body.name, &body.email, &hash_password)
        .await;

    match result {
        Ok(user) => {
            let _key_result = generate_key(app_state, user).await?;
            Ok((
                StatusCode::CREATED,
                Json(Response {
                    message: "Registration successfull".to_string(),
                    status: "success",
                }),
            ))
        }
        Err(sqlx::Error::Database(db_error)) => {
            if db_error.is_unique_violation() {
                Err(HttpError::unique_constraint_violation(
                    ErrorMessage::EmailExist.to_string(),
                ))
            } else {
                Err(HttpError::server_error(db_error.to_string()))
            }
        }

        Err(e) => Err(HttpError::server_error(e.to_string())),
    }
}

pub async fn login(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<LoginUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let result = app_state
        .db_client
        .get_user(None, None, Some(&body.email))
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::bad_request(
        ErrorMessage::WrongCredentials.to_string(),
    ))?;

    let verify_password = password::compare(&body.password, &user.password)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    if !verify_password {
        return Err(HttpError::bad_request(
            ErrorMessage::WrongCredentials.to_string(),
        ));
    }

    let token = token::create_token(
        &user.id.to_string(),
        app_state.env.jwt_secret.as_bytes(),
        app_state.env.jwt_max_age,
    )
    .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = Json(UserLoginResponseDto {
        token: token.clone(),
        status: "success".to_string(),
    });

    let response = handle_cookie(token, app_state.env.jwt_max_age, response.into_response());

    Ok(response)
}
