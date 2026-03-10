use sqlx::PgPool;
use tracing::info;

use super::writer::IndexedBlock;

/// Compute AVAX balance deltas from a block's transactions and apply them.
///
/// For each transaction:
/// - Sender: balance -= (value + gas_used * gas_price)  [fee burn]
/// - Receiver: balance += value
///
/// Uses PostgreSQL NUMERIC(78,0) arithmetic for wei-precision.
pub async fn apply_balance_updates(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    block: &IndexedBlock,
) -> Result<usize, sqlx::Error> {
    let mut updates = 0usize;

    for txn in &block.transactions {
        // Compute gas fee: gas_used * gas_price
        let gas_fee = match (txn.gas_used, txn.gas_price) {
            (Some(used), Some(price)) => {
                // Both are i64, product fits in u128
                let fee = used as u128 * price as u128;
                fee.to_string()
            }
            _ => "0".to_string(),
        };

        // Debit sender: subtract value + gas fee
        sqlx::query(
            "INSERT INTO address_balances (address, balance, nonce, last_updated_block, last_updated_at)
             VALUES ($1, -($2::numeric + $3::numeric), COALESCE($4, 0), $5, $6)
             ON CONFLICT (address) DO UPDATE SET
                 balance = address_balances.balance - ($2::numeric + $3::numeric),
                 nonce = GREATEST(address_balances.nonce, COALESCE($4, address_balances.nonce)),
                 last_updated_block = GREATEST(address_balances.last_updated_block, $5),
                 last_updated_at = CASE WHEN $5 > address_balances.last_updated_block
                     THEN $6 ELSE address_balances.last_updated_at END",
        )
        .bind(&txn.from_address)
        .bind(&txn.value)
        .bind(&gas_fee)
        .bind(txn.nonce)
        .bind(txn.block_number)
        .bind(txn.timestamp)
        .execute(&mut **tx)
        .await?;
        updates += 1;

        // Credit receiver: add value (no gas fee)
        if let Some(ref to_addr) = txn.to_address {
            sqlx::query(
                "INSERT INTO address_balances (address, balance, nonce, last_updated_block, last_updated_at)
                 VALUES ($1, $2::numeric, 0, $3, $4)
                 ON CONFLICT (address) DO UPDATE SET
                     balance = address_balances.balance + $2::numeric,
                     last_updated_block = GREATEST(address_balances.last_updated_block, $3),
                     last_updated_at = CASE WHEN $3 > address_balances.last_updated_block
                         THEN $4 ELSE address_balances.last_updated_at END",
            )
            .bind(to_addr)
            .bind(&txn.value)
            .bind(txn.block_number)
            .bind(txn.timestamp)
            .execute(&mut **tx)
            .await?;
            updates += 1;
        }
    }

    Ok(updates)
}

/// Recompute all balances from scratch by scanning the transactions table.
/// Useful for recovery or verification. Runs as a single atomic operation.
///
/// For billion-scale: this uses a single SQL aggregation rather than
/// iterating rows in Rust.
pub async fn recompute_all_balances(pool: &PgPool) -> Result<u64, sqlx::Error> {
    info!("Recomputing all AVAX balances from transaction history...");

    let mut tx = pool.begin().await?;

    // Truncate and rebuild from aggregation
    sqlx::query("DELETE FROM address_balances")
        .execute(&mut *tx)
        .await?;

    // Compute net balance per address in SQL only:
    // - sender debits aggregate value + gas fees
    // - receiver credits aggregate value
    // This avoids Rust-side iteration for billion-row rebuilds.
    let result = sqlx::query(
        "INSERT INTO address_balances (address, balance, nonce, last_updated_block, last_updated_at)
         SELECT
             addr,
             SUM(delta) AS balance,
             COALESCE(MAX(max_nonce), 0) AS nonce,
             MAX(max_block) AS last_updated_block,
             MAX(max_ts) AS last_updated_at
         FROM (
             -- Debits: sender pays value + gas across all sent txs
             SELECT
                 from_address AS addr,
                 -SUM(value + (COALESCE(gas_used, 0)::numeric * COALESCE(gas_price, 0)::numeric)) AS delta,
                 MAX(nonce) AS max_nonce,
                 MAX(block_number) AS max_block,
                 MAX(timestamp) AS max_ts
             FROM transactions
             GROUP BY from_address

             UNION ALL

             -- Credits: receiver gets transferred value
             SELECT
                 to_address AS addr,
                 SUM(value) AS delta,
                 NULL::bigint AS max_nonce,
                 MAX(block_number) AS max_block,
                 MAX(timestamp) AS max_ts
             FROM transactions
             WHERE to_address IS NOT NULL
             GROUP BY to_address
         ) AS combined
         GROUP BY addr",
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let rows = result.rows_affected();
    info!("Recomputed balances for {} addresses", rows);
    Ok(rows)
}
