use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Token request failed: {0}")]
    TokenRequest(String),

    #[error("Token verification failed: {0}")]
    TokenVerification(String),

    #[error("Configuration error: {0}")]
    Config(String),
}
