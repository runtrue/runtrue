//! Hardened browser OIDC transport, sealed-cookie state, and bounded metrics.

mod claims;
mod client;
mod cookies;
mod error;
mod github;
mod jwt;
mod metrics;
mod model;
mod network;

pub use client::{HardenedHumanOidcClient, HumanOidcAdapter};
pub use cookies::CookieSealer;
pub use error::HumanOidcError;
pub use github::{GitHubOauthAdapter, HardenedGitHubOauthClient};
pub use metrics::{HumanAuthMetrics, HumanAuthMetricsSnapshot};
pub use model::{
    validate_human_oidc_public_origin, GitHubAccessToken, GitHubUserCatalog, GitHubUserRepository,
    HumanOidcLimits, VerifiedGitHubIdentity, VerifiedHumanIdentity, ID_TOKEN_CLOCK_SKEW_SECONDS,
    MAX_AUTHORIZATION_CODE_BYTES, MAX_HUMAN_JWKS_BYTES, MAX_HUMAN_JWKS_KEYS, MAX_ID_TOKEN_BYTES,
    MAX_ID_TOKEN_LIFETIME_SECONDS, MAX_OIDC_RESPONSE_HEADER_BYTES, MAX_SEALED_COOKIE_BYTES,
    MAX_TOKEN_RESPONSE_BYTES,
};
pub(crate) use network::encode_query_component;

#[cfg(test)]
mod tests {
    use super::*;
    use super::{jwt::verify_id_token, network::is_public_ip};
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use ed25519_dalek::{Signer as _, SigningKey};
    use runtrue_control_plane::TenantOidcProviderConfiguration;
    use runtrue_model::ContentDigest;
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use zeroize::Zeroizing;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct CookieFixture {
        transaction_id: String,
        verifier: String,
    }

    #[test]
    fn sealed_cookie_is_confidential_bound_and_tamper_evident() {
        let sealer = CookieSealer::new(&[7; 32]).expect("sealer");
        let fixture = CookieFixture {
            transaction_id: "login-1".to_owned(),
            verifier: "plaintext-verifier".to_owned(),
        };
        let sealed = sealer.seal("runtrue_login", &fixture).expect("seal");
        assert!(!sealed.contains(&fixture.transaction_id));
        assert!(!sealed.contains(&fixture.verifier));
        assert_eq!(
            sealer
                .open::<CookieFixture>("runtrue_login", &sealed)
                .expect("open"),
            fixture
        );
        assert_eq!(
            sealer.open::<CookieFixture>("runtrue_access", &sealed),
            Err(HumanOidcError::InvalidCookie)
        );
        let mut tampered = sealed.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert_eq!(
            sealer.open::<CookieFixture>(
                "runtrue_login",
                std::str::from_utf8(&tampered).expect("base64 text")
            ),
            Err(HumanOidcError::InvalidCookie)
        );
    }

    #[test]
    fn github_access_tokens_are_redacted_from_diagnostics() {
        let token = GitHubAccessToken::new("github-secret-token".to_owned());
        assert_eq!(format!("{token:?}"), "GitHubAccessToken([REDACTED])");
        assert!(!format!("{token:?}").contains("github-secret-token"));
    }

    #[test]
    fn public_resolver_predicate_rejects_special_ranges() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "198.51.100.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            assert!(!is_public_ip(address.parse().expect("IP")), "{address}");
        }
        assert!(is_public_ip("8.8.8.8".parse().expect("public IP")));
        assert!(is_public_ip(
            "2606:4700:4700::1111".parse().expect("public IPv6")
        ));
    }

    #[test]
    fn github_oauth_client_rejects_insecure_origins_and_redacts_secret() {
        let secret = Zeroizing::new("a-production-client-secret".to_owned());
        assert!(HardenedGitHubOauthClient::new(
            "http://github.example.com",
            "https://github.example.com/api/v3",
            "client-id".to_owned(),
            secret.clone(),
            HumanOidcLimits::default(),
        )
        .is_err());
        let client = HardenedGitHubOauthClient::new(
            "https://github.example.com",
            "https://github.example.com/api/v3",
            "client-id".to_owned(),
            secret,
            HumanOidcLimits::default(),
        )
        .expect("valid GHES OAuth client");
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("production-client-secret"));
        assert!(!rendered.contains("client-id"));
    }

    fn provider() -> TenantOidcProviderConfiguration {
        let mut provider = TenantOidcProviderConfiguration {
            id: "provider-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            issuer: "https://identity.example".to_owned(),
            client_id: "runtrue-browser".to_owned(),
            authorization_endpoint: "https://identity.example/authorize".to_owned(),
            token_endpoint: "https://identity.example/token".to_owned(),
            jwks_uri: "https://identity.example/jwks".to_owned(),
            redirect_uri: "https://runtrue.example/auth/oidc/callback".to_owned(),
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
            mfa_claim: json!({"claim": "amr", "value": "mfa"}),
            status: "active".to_owned(),
            configuration_digest: ContentDigest::sha256(b"placeholder"),
            created_unix_ms: 1,
            updated_unix_ms: 1,
            version: 1,
        };
        provider.configuration_digest = provider
            .expected_configuration_digest()
            .expect("configuration digest");
        provider
    }

    fn signed_token(signing_key: &SigningKey, algorithm: &str, audience: &str) -> String {
        let header = Base64UrlUnpadded::encode_string(
            &serde_json::to_vec(&json!({"alg": algorithm, "kid": "key-1", "typ": "JWT"}))
                .expect("header"),
        );
        let claims = Base64UrlUnpadded::encode_string(
            &serde_json::to_vec(&json!({
                "iss": "https://identity.example",
                "sub": "subject-1",
                "aud": audience,
                "iat": 90,
                "exp": 200,
                "nonce": "nonce-1",
                "email": "user@example.test",
                "name": "User",
                "amr": ["pwd", "mfa"]
            }))
            .expect("claims"),
        );
        let input = format!("{header}.{claims}");
        let signature = signing_key.sign(input.as_bytes());
        format!(
            "{input}.{}",
            Base64UrlUnpadded::encode_string(&signature.to_bytes())
        )
    }

    fn jwks(signing_key: &SigningKey) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "keys": [{
                "kty": "OKP",
                "kid": "key-1",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "x": Base64UrlUnpadded::encode_string(signing_key.verifying_key().as_bytes())
            }]
        }))
        .expect("JWKS")
    }

    #[test]
    fn id_token_signature_claims_algorithm_and_mfa_mapping_fail_closed() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let provider = provider();
        let verified = verify_id_token(
            &signed_token(&signing_key, "EdDSA", "runtrue-browser"),
            &jwks(&signing_key),
            &provider,
            100,
        )
        .expect("verified token");
        assert_eq!(verified.issuer, provider.issuer);
        assert_eq!(verified.subject, "subject-1");
        assert_eq!(verified.nonce, "nonce-1");
        assert!(verified.mfa_authenticated);

        assert_eq!(
            verify_id_token(
                &signed_token(&signing_key, "RS256", "runtrue-browser"),
                &jwks(&signing_key),
                &provider,
                100,
            ),
            Err(HumanOidcError::UnsupportedIdTokenAlgorithm)
        );
        assert_eq!(
            verify_id_token(
                &signed_token(&signing_key, "EdDSA", "substituted-client"),
                &jwks(&signing_key),
                &provider,
                100,
            ),
            Err(HumanOidcError::InvalidIdTokenClaims)
        );

        let mut duplicate: Value = serde_json::from_slice(&jwks(&signing_key)).expect("JWKS");
        let key = duplicate["keys"][0].clone();
        duplicate["keys"].as_array_mut().expect("keys").push(key);
        assert_eq!(
            verify_id_token(
                &signed_token(&signing_key, "EdDSA", "runtrue-browser"),
                &serde_json::to_vec(&duplicate).expect("duplicate JWKS"),
                &provider,
                100,
            ),
            Err(HumanOidcError::InvalidJwks)
        );
    }

    #[test]
    fn public_origin_is_an_exact_https_origin() {
        assert!(validate_human_oidc_public_origin("https://runtrue.example").is_ok());
        for invalid in [
            "http://runtrue.example",
            "https://runtrue.example/",
            "https://runtrue.example/path",
            "https://user@runtrue.example",
            "https://runtrue.example?query=1",
            "https://runtrue.example#fragment",
        ] {
            assert_eq!(
                validate_human_oidc_public_origin(invalid),
                Err(HumanOidcError::InvalidConfiguration),
                "{invalid}"
            );
        }
    }
}
