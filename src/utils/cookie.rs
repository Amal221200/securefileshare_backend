use axum::{http::{header, HeaderMap}, response::{IntoResponse, Response}};
use axum_extra::extract::cookie::Cookie;


pub fn handle_cookie(token: String, duration: i64,  response: Response) -> Response {
    let cookie_duration = time::Duration::minutes(duration);

    let cookie = Cookie::build(("token", token.clone()))
        .path("/")
        .max_age(cookie_duration)
        .http_only(true)
        .build();

        let mut headers = HeaderMap::new();

        headers.append(header::SET_COOKIE, cookie.to_string().parse().unwrap());
    
        let mut response = response.into_response();
        response.headers_mut().extend(headers);

        response
}
