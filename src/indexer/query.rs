use sqlx::PgPool;

#[allow(dead_code)]
pub struct IndexerQuery {
    pool: PgPool,
}

impl IndexerQuery {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
