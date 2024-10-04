use std::sync::Arc;

use axum::{middleware, routing::get, Extension, Router};
use tower_http::trace::TraceLayer;

use crate::{
    handler::{
        auth::auth_handler, file::file_handler, file_query::get_file_list_handler, greet::greet,
        user::user_handler,
    },
    middleware::auth,
    AppState,
};

pub fn create_router(app_state: Arc<AppState>) -> Router {
    let api_route = Router::new()
        .route("/", get(greet))
        .nest("/auth", auth_handler())
        .nest("/users", user_handler().layer(middleware::from_fn(auth)))
        .nest("/file", file_handler().layer(middleware::from_fn(auth)))
        .nest(
            "/list",
            get_file_list_handler().layer(middleware::from_fn(auth)),
        )
        .layer(TraceLayer::new_for_http())
        .layer(Extension(app_state));

    Router::new().nest("/api", api_route)
}
