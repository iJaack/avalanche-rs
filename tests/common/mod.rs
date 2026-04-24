use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::OnceLock;
use std::time::Duration;

static TEST_DB_NAME: OnceLock<String> = OnceLock::new();

pub fn test_database_name(prefix: &str) -> String {
    TEST_DB_NAME
        .get_or_init(|| format!("{}_{}", prefix, std::process::id()))
        .clone()
}

pub fn test_database_url(prefix: &str) -> String {
    format!("postgresql:///{}", test_database_name(prefix))
}

async fn ensure_test_database(db_name: &str) -> bool {
    let admin_pool = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect("postgresql:///postgres")
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("Skipping DB-backed test: failed to connect to postgres admin db: {e}");
            return false;
        }
    };

    let exists: Option<(i32,)> =
        match sqlx::query_as("SELECT 1 FROM pg_database WHERE datname = $1")
            .bind(db_name)
            .fetch_optional(&admin_pool)
            .await
        {
            Ok(exists) => exists,
            Err(e) => {
                eprintln!("Skipping DB-backed test: failed to check test database existence: {e}");
                admin_pool.close().await;
                return false;
            }
        };

    if exists.is_none() {
        if let Err(e) = sqlx::query(&format!("CREATE DATABASE \"{}\"", db_name))
            .execute(&admin_pool)
            .await
        {
            eprintln!("Skipping DB-backed test: failed to create test database: {e}");
            admin_pool.close().await;
            return false;
        }
    }

    admin_pool.close().await;
    true
}

async fn reset_indexer_tables(pool: &PgPool, seed_last_indexed_block: bool) {
    let _ = sqlx::query("DELETE FROM logs").execute(pool).await;
    let _ = sqlx::query("DELETE FROM transactions").execute(pool).await;
    let _ = sqlx::query("DELETE FROM blocks").execute(pool).await;
    let _ = sqlx::query("DELETE FROM address_balances")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM indexer_state WHERE key NOT IN ('indexer_version')")
        .execute(pool)
        .await;

    if seed_last_indexed_block {
        let _ = sqlx::query(
            "INSERT INTO indexer_state (key, value_int, updated_at) VALUES ('last_indexed_block', 0, NOW()) ON CONFLICT (key) DO UPDATE SET value_int = 0, updated_at = NOW()",
        )
        .execute(pool)
        .await;
    }
}

pub async fn setup_indexer_pool(prefix: &str, seed_last_indexed_block: bool) -> Option<PgPool> {
    let db_name = test_database_name(prefix);
    if !ensure_test_database(&db_name).await {
        return None;
    }

    let pool = match PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&test_database_url(prefix))
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("Skipping DB-backed test: failed to connect to test database: {e}");
            return None;
        }
    };

    if let Err(e) = sqlx::migrate!("./migrations").run(&pool).await {
        eprintln!("Skipping DB-backed test: failed to run migrations: {e}");
        return None;
    }

    reset_indexer_tables(&pool, seed_last_indexed_block).await;
    Some(pool)
}
