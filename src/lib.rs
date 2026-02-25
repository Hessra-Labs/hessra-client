pub mod error;
pub mod types;

use error::ClientError;
use hessra_token_core::PublicKey;
use tokio::sync::OnceCell;
use types::*;

/// Parse a server address string into (host, port) components.
///
/// Handles various formats: IP:Port, hostname:port, IPv6 with brackets,
/// URLs with protocol prefix and path.
fn parse_server_address(address: &str) -> (String, Option<u16>) {
    let address = address.trim();

    let without_protocol = address
        .strip_prefix("https://")
        .or_else(|| address.strip_prefix("http://"))
        .unwrap_or(address);

    let host_port = without_protocol
        .split('/')
        .next()
        .unwrap_or(without_protocol);

    if host_port.starts_with('[') {
        if let Some(bracket_end) = host_port.find(']') {
            let host = &host_port[1..bracket_end];
            let after_bracket = &host_port[bracket_end + 1..];

            if let Some(port_str) = after_bracket.strip_prefix(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    return (host.to_string(), Some(port));
                }
            }
            return (host.to_string(), None);
        }
        return (host_port.trim_start_matches('[').to_string(), None);
    }

    let colon_count = host_port.chars().filter(|c| *c == ':').count();

    if colon_count == 1 {
        let parts: Vec<&str> = host_port.splitn(2, ':').collect();
        if parts.len() == 2 {
            if let Ok(port) = parts[1].parse::<u16>() {
                return (parts[0].to_string(), Some(port));
            }
        }
    }

    (host_port.to_string(), None)
}

/// Format a base URL with optional port for HTTPS requests.
fn format_base_url(base_url: &str, port: Option<u16>) -> String {
    let (host, embedded_port) = parse_server_address(base_url);
    let resolved_port = port.or(embedded_port);
    match resolved_port {
        Some(p) => format!("https://{host}:{p}"),
        None => format!("https://{host}"),
    }
}

/// HTTP client for communicating with a Hessra authorization node.
pub struct HessraClient {
    client: reqwest::Client,
    base_url: String,
    public_key: OnceCell<PublicKey>,
}

impl HessraClient {
    /// Create a new builder for constructing a client.
    pub fn builder() -> HessraClientBuilder {
        HessraClientBuilder::default()
    }

    /// Fetch and cache the server's public key (PEM format).
    ///
    /// The key is fetched once and cached for the lifetime of the client.
    /// Returns the parsed `PublicKey` suitable for local token verification.
    pub async fn fetch_public_key(&self) -> Result<PublicKey, ClientError> {
        self.public_key
            .get_or_try_init(|| async {
                let url = format!("{}/public_key", self.base_url);
                let response = self
                    .client
                    .get(&url)
                    .send()
                    .await
                    .map_err(ClientError::Http)?;

                if !response.status().is_success() {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_default();
                    return Err(ClientError::InvalidResponse(format!(
                        "HTTP {status}: {text}"
                    )));
                }

                let body: PublicKeyResponse = response.json().await.map_err(ClientError::Http)?;

                PublicKey::from_pem(&body.public_key).map_err(|e| {
                    ClientError::InvalidResponse(format!("Failed to parse public key PEM: {e}"))
                })
            })
            .await
            .copied()
    }

    /// Request a capability token (mTLS-authenticated).
    pub async fn request_token(&self, request: &TokenRequest) -> Result<TokenResponse, ClientError> {
        self.post("request_token", request).await
    }

    /// Request a capability token using an identity token for authentication.
    pub async fn request_token_with_identity(
        &self,
        request: &TokenRequest,
        identity_token: &str,
    ) -> Result<TokenResponse, ClientError> {
        self.post_with_auth("request_token", request, identity_token)
            .await
    }

    /// Verify a token remotely via the authorization service.
    pub async fn verify_token(
        &self,
        request: &VerifyTokenRequest,
    ) -> Result<VerifyTokenResponse, ClientError> {
        self.post("verify_token", request).await
    }

    /// Mint a namespace-restricted identity token.
    pub async fn mint_identity_token(
        &self,
        request: &MintIdentityTokenRequest,
    ) -> Result<MintIdentityTokenResponse, ClientError> {
        self.post("mint_identity_token", request).await
    }

    /// Request an identity token (mTLS-authenticated).
    pub async fn request_identity_token(
        &self,
        request: &IdentityTokenRequest,
    ) -> Result<IdentityTokenResponse, ClientError> {
        self.post("request_identity_token", request).await
    }

    /// Refresh an existing identity token.
    pub async fn refresh_identity_token(
        &self,
        request: &RefreshIdentityTokenRequest,
    ) -> Result<IdentityTokenResponse, ClientError> {
        self.post("refresh_identity_token", request).await
    }

    /// Health check.
    pub async fn health(&self) -> Result<HealthResponse, ClientError> {
        let url = format!("{}/health", self.base_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(ClientError::Http)?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ClientError::InvalidResponse(format!(
                "HTTP {status}: {text}"
            )));
        }

        response.json().await.map_err(ClientError::Http)
    }

    /// POST a JSON request body to an endpoint and deserialize the response.
    async fn post<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        body: &T,
    ) -> Result<R, ClientError> {
        let url = format!("{}/{endpoint}", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(ClientError::Http)?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ClientError::InvalidResponse(format!(
                "HTTP {status}: {text}"
            )));
        }

        response.json().await.map_err(ClientError::Http)
    }

    /// POST with a Bearer token in the Authorization header.
    async fn post_with_auth<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        body: &T,
        bearer_token: &str,
    ) -> Result<R, ClientError> {
        let url = format!("{}/{endpoint}", self.base_url);
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {bearer_token}"))
            .json(body)
            .send()
            .await
            .map_err(ClientError::Http)?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(ClientError::InvalidResponse(format!(
                "HTTP {status}: {text}"
            )));
        }

        response.json().await.map_err(ClientError::Http)
    }
}

/// Builder for constructing an `HessraClient`.
#[derive(Default)]
pub struct HessraClientBuilder {
    base_url: String,
    port: Option<u16>,
    mtls_cert: Option<String>,
    mtls_key: Option<String>,
    server_ca: Option<String>,
}

impl HessraClientBuilder {
    /// Set the base URL (e.g., "infra.hessra.net").
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Set the port (overrides any port embedded in the URL).
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the mTLS client certificate (PEM).
    pub fn mtls_cert(mut self, cert: impl Into<String>) -> Self {
        self.mtls_cert = Some(cert.into());
        self
    }

    /// Set the mTLS client private key (PEM).
    pub fn mtls_key(mut self, key: impl Into<String>) -> Self {
        self.mtls_key = Some(key.into());
        self
    }

    /// Set the server CA certificate (PEM).
    pub fn server_ca(mut self, ca: impl Into<String>) -> Self {
        self.server_ca = Some(ca.into());
        self
    }

    /// Build the client.
    pub fn build(self) -> Result<HessraClient, ClientError> {
        let server_ca = self
            .server_ca
            .ok_or_else(|| ClientError::Config("server_ca is required".into()))?;

        let certs = reqwest::Certificate::from_pem_bundle(server_ca.as_bytes()).map_err(|e| {
            ClientError::TlsConfig(format!("Failed to parse CA certificate chain: {e}"))
        })?;

        let mut builder = reqwest::ClientBuilder::new().use_rustls_tls();

        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }

        if let (Some(cert), Some(key)) = (&self.mtls_cert, &self.mtls_key) {
            let identity_pem = format!("{cert}{key}");
            let identity =
                reqwest::Identity::from_pem(identity_pem.as_bytes()).map_err(|e| {
                    ClientError::TlsConfig(format!(
                        "Failed to create identity from cert and key: {e}"
                    ))
                })?;
            builder = builder.identity(identity);
        }

        let client = builder
            .build()
            .map_err(|e| ClientError::TlsConfig(e.to_string()))?;

        let base_url = format_base_url(&self.base_url, self.port);

        Ok(HessraClient {
            client,
            base_url,
            public_key: OnceCell::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_server_address_ip_with_port() {
        let (host, port) = parse_server_address("127.0.0.1:4433");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, Some(4433));
    }

    #[test]
    fn test_parse_server_address_hostname_only() {
        let (host, port) = parse_server_address("test.hessra.net");
        assert_eq!(host, "test.hessra.net");
        assert_eq!(port, None);
    }

    #[test]
    fn test_parse_server_address_with_protocol() {
        let (host, port) = parse_server_address("https://example.com:8443/path");
        assert_eq!(host, "example.com");
        assert_eq!(port, Some(8443));
    }

    #[test]
    fn test_parse_server_address_ipv6() {
        let (host, port) = parse_server_address("[::1]:8443");
        assert_eq!(host, "::1");
        assert_eq!(port, Some(8443));
    }

    #[test]
    fn test_format_base_url() {
        assert_eq!(
            format_base_url("infra.hessra.net", None),
            "https://infra.hessra.net"
        );
        assert_eq!(
            format_base_url("infra.hessra.net", Some(443)),
            "https://infra.hessra.net:443"
        );
        assert_eq!(
            format_base_url("127.0.0.1:4433", Some(8080)),
            "https://127.0.0.1:8080"
        );
        assert_eq!(
            format_base_url("127.0.0.1:4433", None),
            "https://127.0.0.1:4433"
        );
    }
}
