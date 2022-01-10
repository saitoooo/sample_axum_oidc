use anyhow::{Error};
use axum::{response::IntoResponse, body, http::StatusCode};

pub struct WebError(Error);

impl<T> From<T> for WebError where T:Into<anyhow::Error> + Send{
    fn from(item: T) -> Self {
        let e:anyhow::Error = item.into();

        Self(e)
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> axum::response::Response {
        let body = body::boxed(body::Full::from(self.0.to_string()));

        let x = axum::response::Response::builder();
        let p = x.status(StatusCode::INTERNAL_SERVER_ERROR).header("Content-Type", "text/plain; charset=UTF-8")  .body(body).unwrap();

        p
    }
}