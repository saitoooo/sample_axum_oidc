mod oidc_util;
mod web_error;

use std::{collections::HashMap, net::SocketAddr};

use anyhow::Error;
use axum::{
    extract::{Extension, Query},
    http::Uri,
    response::Redirect,
    routing::get,
    AddExtensionLayer, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use oauth2::TokenResponse;
use oidc_util::OpenIdConnectUtil;
use tower_cookies::{Cookies, CookieManagerLayer};
use web_error::WebError;
use dotenv::dotenv;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Error> {
    dotenv().ok();

    // OpenIDConnectの設定
    let oidc_util = OpenIdConnectUtil::new(
        env::var("OIDC_ISSUER_URL").unwrap(),
        env::var("OIDC_CLIENT_ID").unwrap(),
        env::var("OIDC_CLIENT_SECRET").unwrap(),
        env::var("OIDC_SCOPE").unwrap(),
        env::var("OIDC_REDIRECT_URL").unwrap(),
        None,
        None,
    )
    .await?;

    // /googleの設定
    let google_auth = Router::new()
        .route("/signin", get(signin_redirect))
        .route("/signin_finish", get(sample_finish))
        .layer(AddExtensionLayer::new(oidc_util));

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .nest("/google", google_auth)
        .layer(CookieManagerLayer::new());

    // Run app on local server
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));

    let config = RustlsConfig::from_pem_file(r"./localhost.crt", r"./localhost.pem").await?;

    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

pub async fn signin_redirect(
    Extension(oidc_util): Extension<OpenIdConnectUtil>,
    cookies: Cookies,
) -> Result<Redirect, WebError> {
    let r = oidc_util.signin_redirect(&cookies).await?;
    Ok(Redirect::temporary(r.parse::<Uri>()?))
}

pub async fn sample_finish(
    Extension(oidc_util): Extension<OpenIdConnectUtil>,
    cookies: Cookies,
    Query(params): Query<HashMap<String, String>>,
) -> Result<String, WebError> {
    // 検証して問題なければトークンを取得、問題があればエラーとなるので ? で返す
    let (token, claims) = oidc_util.verify(&cookies, &params).await?;

    // アクセストークン、リフレッシュトークンを取得
    let access_token = token.access_token().secret();
    let refresh_token = token.refresh_token().map(|i| i.secret());

    println!("{:?}", claims);
    println!("{:?}", access_token);
    println!("{:?}", refresh_token);

    // とりあえずログインできたよメッセージを返す
    Ok("ログインできました".to_string())
}
