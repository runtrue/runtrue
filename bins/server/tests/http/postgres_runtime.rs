use super::support::*;
use runtrue_control_plane::{
    PostgresDatabaseConfig, PostgresInstallationStore, TenantIdentityStore as _,
    POSTGRES_SCHEMA_VERSION,
};
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn postgres_store_backs_runtime_router_read_write_smoke() {
    let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
        return;
    };
    let now = unix_ms_now();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after Unix epoch")
        .as_nanos();
    let suffix = format!("{}_{unique}", std::process::id());
    let schema = format!("runtrue_http_{suffix}");
    let installation_id = format!("pg-http-{suffix}");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect to the test PostgreSQL database for schema isolation");
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .expect("create the isolated PostgreSQL server smoke-test schema");
    let separator = if url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{url}{separator}options=-csearch_path%3D{schema}");
    let config = PostgresDatabaseConfig::parse(&scoped_url)
        .expect("RUNTRUE_TEST_POSTGRES_URL must be a valid test PostgreSQL URL")
        .with_maximum_connections(4);

    // Exercise the same lifecycle as a deployed server: an explicit migration
    // step followed by a DDL-free runtime connection.
    PostgresInstallationStore::connect_and_migrate(config.clone(), &installation_id, now)
        .await
        .expect("initialize the PostgreSQL server smoke-test database")
        .close()
        .await;
    let store = Arc::new(
        PostgresInstallationStore::connect_existing(config, &installation_id)
            .await
            .expect("connect the PostgreSQL runtime store"),
    );

    let tenant_id = format!("tenant-http-pg-{suffix}");
    let repository_id = format!("repo-http-pg-{suffix}");
    store
        .put_tenant_identity(
            &TenantIdentityRecord {
                id: tenant_id.clone(),
                slug: tenant_id.clone(),
                name: "PostgreSQL HTTP smoke tenant".to_owned(),
                status: "active".to_owned(),
                settings: json!({}),
                created_unix_ms: now,
                updated_unix_ms: now,
                version: 1,
            },
            None,
        )
        .await
        .expect("seed the repository tenant prerequisite");

    let state = AppState::new(store.clone(), TOKEN, None).expect("build PostgreSQL app state");
    let application = router(state);

    let readiness = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request PostgreSQL-backed readiness");
    assert_eq!(readiness.status(), StatusCode::OK);
    assert_eq!(
        json_body(readiness).await,
        json!({
            "status": "ready",
            "backend": "postgres",
            "schema_version": POSTGRES_SCHEMA_VERSION,
            "installation_id": installation_id,
            "fencing_epoch": 1
        })
    );

    let created = application
        .clone()
        .oneshot(api_request(
            "POST",
            "/api/v1/repositories",
            serde_json::to_vec(&json!({
                "id": repository_id,
                "tenant_id": tenant_id,
                "owner": "runtrue-smoke",
                "name": suffix,
                "default_branch": "main",
                "visibility": "private"
            }))
            .unwrap(),
        ))
        .await
        .expect("create a repository through the PostgreSQL-backed router");
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = json_body(created).await;
    assert_eq!(created["id"], repository_id);
    assert_eq!(created["owner"], "runtrue-smoke");
    assert_eq!(created["name"], suffix);

    let fetched = application
        .clone()
        .oneshot(api_request(
            "GET",
            &format!("/api/v1/repositories/{repository_id}"),
            Body::empty(),
        ))
        .await
        .expect("read the repository through the PostgreSQL-backed router");
    assert_eq!(fetched.status(), StatusCode::OK);
    assert_eq!(json_body(fetched).await, created);

    drop(application);
    Arc::try_unwrap(store)
        .expect("router releases the PostgreSQL store")
        .close()
        .await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove the isolated PostgreSQL server smoke-test schema");
    admin.close().await;
}
