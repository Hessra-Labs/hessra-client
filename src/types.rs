use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenRequest {
    pub resource: String,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenResponse {
    pub response_msg: String,
    pub token: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyTokenRequest {
    pub token: String,
    pub subject: String,
    pub resource: String,
    pub operation: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyTokenResponse {
    pub response_msg: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicKeyResponse {
    pub response_msg: String,
    pub public_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MintIdentityTokenRequest {
    pub subject: String,
    pub duration: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MintIdentityTokenResponse {
    pub response_msg: String,
    pub token: Option<String>,
    pub expires_in: Option<u64>,
    pub identity: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdentityTokenRequest {
    pub identifier: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdentityTokenResponse {
    pub response_msg: String,
    pub token: Option<String>,
    pub expires_in: Option<u64>,
    pub identity: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RefreshIdentityTokenRequest {
    pub current_token: String,
    pub identifier: Option<String>,
}
