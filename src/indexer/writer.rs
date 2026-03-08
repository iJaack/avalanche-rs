use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

pub struct IndexerWriter {
    pool: PgPool,
}

impl IndexerWriter {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .min_connections(5)
            .max_connections(20)
            .acquire_timeout(Duration::from_secs(10))
            .connect(database_url)
            .await?;

        // Run migrations
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await?;

        Ok(Self { pool })
    }

    pub async fn close(self) {
        self.pool.close().await;
    }
}
