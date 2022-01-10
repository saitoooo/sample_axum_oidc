use anyhow::anyhow;
use anyhow::Result;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use oauth2::{
    basic::{BasicErrorResponseType, BasicTokenType},
    EmptyExtraTokenFields, RevocationErrorResponseType, StandardErrorResponse,
    StandardRevocableToken, StandardTokenIntrospectionResponse, TokenResponse,
};
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreClient, CoreGenderClaim,
    CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm, CoreProviderMetadata,
};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken,
    EmptyAdditionalClaims, IdTokenClaims, IdTokenFields, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, StandardTokenResponse,
    TokenResponse as TokenResponseOIDC,
};
use std::collections::HashMap;
use tower_cookies::{Cookie, Cookies};
use uuid::Uuid;


#[derive(Clone, Debug)]
pub struct OpenIdConnectUtil {
    scope: Vec<String>,
    cookie_name: String,
    encrypt_key: String,
    client: Client<
        EmptyAdditionalClaims,
        CoreAuthDisplay,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        CoreJsonWebKey,
        CoreAuthPrompt,
        StandardErrorResponse<BasicErrorResponseType>,
        StandardTokenResponse<
            IdTokenFields<
                EmptyAdditionalClaims,
                EmptyExtraTokenFields,
                CoreGenderClaim,
                CoreJweContentEncryptionAlgorithm,
                CoreJwsSigningAlgorithm,
                CoreJsonWebKeyType,
            >,
            BasicTokenType,
        >,
        BasicTokenType,
        StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
        StandardRevocableToken,
        StandardErrorResponse<RevocationErrorResponseType>,
    >,
}

impl OpenIdConnectUtil {
    pub async fn new(
        issuer_url: String,
        client_id: String,
        client_secret: String,
        scope: String,
        redirect_url: String,
        cookie_name: Option<String>,
        encrypt_key: Option<String>,
    ) -> Result<Self> {
        // cookie名の設定
        let cookie_name = cookie_name.unwrap_or(Uuid::new_v4().to_string());

        // 暗号化のキーを設定
        let encrypt_key = encrypt_key.unwrap_or(Uuid::new_v4().to_string());

        let scope: Vec<String> = scope
            .split(' ')
            .map(|s| s.trim().to_string())
            .filter(|s| s != "")
            .collect();

        let provider_metadata =
            CoreProviderMetadata::discover_async(IssuerUrl::new(issuer_url)?, async_http_client)
                .await?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(RedirectUrl::new(redirect_url)?);

        Ok(Self {
            scope: scope,
            cookie_name,
            encrypt_key,
            client,
        })
    }

    pub async fn signin_redirect(&self, cookies: &Cookies) -> Result<String> {
        // Generate a PKCE challenge.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate the full authorization URL.
        let mut c = self.client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for s in &self.scope {
            c = c.add_scope(Scope::new(s.clone()))
        }
        let (auth_url, csrf_token, nonce) = c.set_pkce_challenge(pkce_challenge).url();

        // Googleの場合、RefreshTokenが必要な場合下記をコメントアウトする
        // {
        //     let mut x = auth_url.query_pairs_mut();
        //     x.append_pair("access_type", "offline");
        // }

        // Cookie設定
        let mc = new_magic_crypt!(&self.encrypt_key, 256);
        let cookie_values = serde_json::to_string(&(nonce, csrf_token, pkce_verifier))?;
        let cookie_values = mc.encrypt_str_to_base64(cookie_values);
        cookies.add(Cookie::new(self.cookie_name.clone(), cookie_values));

        Ok(auth_url.to_string())
    }

    pub async fn verify(
        &self,
        cookies: &Cookies,
        query_params: &HashMap<String, String>,
    ) -> Result<(
        StandardTokenResponse<
            IdTokenFields<
                EmptyAdditionalClaims,
                EmptyExtraTokenFields,
                CoreGenderClaim,
                CoreJweContentEncryptionAlgorithm,
                CoreJwsSigningAlgorithm,
                CoreJsonWebKeyType,
            >,
            BasicTokenType,
        >,
        IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>,
    )> {
        let cookie_value = cookies
            .get(&self.cookie_name)
            .ok_or(anyhow!("cookieが正しく設定されていません"))?;
        cookies.remove(Cookie::new(self.cookie_name.clone(), "")); // 取得されたクッキーは不要なので削除

        let mc = new_magic_crypt!(&self.encrypt_key, 256);
        let cookie_value = mc.decrypt_base64_to_string(cookie_value.value())?;
        let (c_nonce, c_state, c_pkce_verifier): (Nonce, String, PkceCodeVerifier) =
            serde_json::from_str(&cookie_value)?;

        if Some(&c_state) != query_params.get("state") {
            return Err(anyhow!("stateエラー"));
        }

        let code = query_params.get("code").ok_or(anyhow!("パラメータ不正"))?;

        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            // Set the PKCE code verifier.
            .set_pkce_verifier(c_pkce_verifier)
            .request_async(async_http_client)
            .await?;

        let t = token_response.clone();
        let id_token = t
            .id_token()
            .ok_or_else(|| anyhow!("Server did not return an ID token"))?;
        let claims = id_token.claims(&self.client.id_token_verifier(), &c_nonce)?;

        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                &id_token.signing_alg()?,
            )?;
            if actual_access_token_hash != *expected_access_token_hash {
                return Err(anyhow!("Invalid access token"));
            }
        }

        Ok((token_response, claims.clone()))
    }
}
