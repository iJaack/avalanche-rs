use sqlx::PgPool;
use std::time::Instant;
use tracing::{error, info, warn};

use super::metrics::IndexerMetrics;

/// Catchup configuration for historical sync.
pub struct CatchupConfig {
    /// Batch size for historical block processing (larger = faster but more memory)
    pub batch_size: usize,
    /// Target chain height to catch up to
    pub target_height: i64,
}

impl Default for CatchupConfig {
    fn default() -> Self {
        Self {
            batch_size: 500,
            target_height: 0,
        }
    }
}

/// Result of gap detection.
#[derive(Debug, Clone)]
pub struct GapInfo {
    /// Ranges of missing blocks: [(start, end), ...]
    pub gaps: Vec<(i64, i64)>,
    /// Total missing blocks
    pub total_missing: i64,
    /// Highest block in DB
    pub db_height: i64,
}

/// Detect gaps in indexed blocks by comparing against a contiguous range.
pub async fn detect_gaps(pool: &PgPool, target_height: i64) -> Result<GapInfo, sqlx::Error> {
    let db_height = get_db_height(pool).await?;
    let scan_to = if target_height > 0 {
        target_height
    } else {
        db_height
    };

    if scan_to == 0 {
        return Ok(GapInfo {
            gaps: vec![],
            total_missing: 0,
            db_height: 0,
        });
    }

    // Find gaps using a window function approach
    // For billion-scale: we only check for gaps in indexed range, not full scan
    let gap_rows: Vec<(i64, i64)> = sqlx::query_as(
        "WITH block_numbers AS (
            SELECT DISTINCT number FROM blocks ORDER BY number
        ),
        gaps AS (
            SELECT
                number + 1 AS gap_start,
                LEAD(number) OVER (ORDER BY number) - 1 AS gap_end
            FROM block_numbers
        )
        SELECT gap_start, gap_end FROM gaps
        WHERE gap_end IS NOT NULL AND gap_end >= gap_start
        ORDER BY gap_start
        LIMIT 1000",
    )
    .fetch_all(pool)
    .await?;

    // Also check if we're missing blocks from 0 to first indexed block
    let first_block: Option<(i64,)> = sqlx::query_as("SELECT MIN(number) FROM blocks")
        .fetch_optional(pool)
        .await?;

    let mut gaps = Vec::new();
    let mut total_missing = 0i64;

    // Gap before first indexed block (if any)
    if let Some((first,)) = first_block {
        if first > 1 {
            let gap = (1, first - 1);
            total_missing += gap.1 - gap.0 + 1;
            gaps.push(gap);
        }
    }

    // Interior gaps
    for (start, end) in &gap_rows {
        total_missing += end - start + 1;
        gaps.push((*start, *end));
    }

    // Gap after last indexed block to target
    if db_height < scan_to {
        let gap = (db_height + 1, scan_to);
        total_missing += gap.1 - gap.0 + 1;
        gaps.push(gap);
    }

    Ok(GapInfo {
        gaps,
        total_missing,
        db_height,
    })
}

/// Get the highest indexed block number.
pub async fn get_db_height(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let row: (Option<i64>,) = sqlx::query_as("SELECT MAX(number) FROM blocks")
        .fetch_one(pool)
        .await?;
    Ok(row.0.unwrap_or(0))
}

/// Update the indexer_state tracking table.
pub async fn update_indexer_state(pool: &PgPool, block_number: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO indexer_state (key, value_int, updated_at)
         VALUES ('last_indexed_block', $1, NOW())
         ON CONFLICT (key) DO UPDATE SET value_int = $1, updated_at = NOW()",
    )
    .bind(block_number)
    .execute(pool)
    .await?;
    Ok(())
}

/// Progress tracker for catchup sync.
pub struct CatchupProgress {
    start_time: Instant,
    start_height: i64,
    target_height: i64,
    current_height: i64,
    blocks_processed: u64,
}

impl CatchupProgress {
    pub fn new(start_height: i64, target_height: i64) -> Self {
        Self {
            start_time: Instant::now(),
            start_height,
            target_height,
            current_height: start_height,
            blocks_processed: 0,
        }
    }

    pub fn update(&mut self, height: i64, batch_count: u64) {
        self.current_height = height;
        self.blocks_processed += batch_count;

        let metrics = IndexerMetrics::global();
        let remaining = self.target_height - self.current_height;
        metrics.catchup_blocks_remaining.set(remaining.max(0));

        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            let bps = self.blocks_processed as f64 / elapsed;
            metrics.catchup_blocks_per_sec.set(bps as i64);
        }
    }

    pub fn log_progress(&self) {
        let elapsed = self.start_time.elapsed();
        let remaining = self.target_height - self.current_height;
        let total = self.target_height - self.start_height;
        let progress_pct = if total > 0 {
            ((self.current_height - self.start_height) as f64 / total as f64) * 100.0
        } else {
            100.0
        };

        let bps = if elapsed.as_secs() > 0 {
            self.blocks_processed as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        let eta_secs = if bps > 0.0 {
            remaining as f64 / bps
        } else {
            0.0
        };

        info!(
            "Catchup: {:.1}% | block {} / {} | {:.0} blocks/s | {} remaining | ETA {:.0}s",
            progress_pct, self.current_height, self.target_height, bps, remaining, eta_secs
        );
    }

    pub fn is_complete(&self) -> bool {
        self.current_height >= self.target_height
    }
}

/// Manually trigger compression of chunks older than the given interval.
/// Useful after catchup to immediately reclaim space.
pub async fn compress_old_chunks(pool: &PgPool, older_than_days: i32) -> Result<u64, sqlx::Error> {
    let interval = format!("{} days", older_than_days);
    let mut compressed = 0u64;

    for table in &["blocks", "transactions", "logs"] {
        match sqlx::query(&format!(
            "SELECT compress_chunk(c) FROM show_chunks('{}', older_than => INTERVAL '{}') c
             WHERE NOT EXISTS (
                SELECT 1 FROM timescaledb_information.chunks
                WHERE chunk_name = c::text AND is_compressed = true
             )",
            table, interval
        ))
        .execute(pool)
        .await
        {
            Ok(result) => {
                compressed += result.rows_affected();
                info!(
                    "Compressed {} chunks for table '{}'",
                    result.rows_affected(),
                    table
                );
            }
            Err(e) => {
                warn!("Failed to compress chunks for '{}': {}", table, e);
            }
        }
    }

    Ok(compressed)
}

/// Run startup catchup: detect gaps, log status, update metrics.
/// Returns the gap info for the caller to process (actual block fetching
/// depends on the node's chain access).
pub async fn startup_catchup(pool: &PgPool, chain_height: i64) -> Result<GapInfo, sqlx::Error> {
    info!(
        "Indexer catchup: scanning for gaps (chain height: {})",
        chain_height
    );

    let gap_info = detect_gaps(pool, chain_height).await?;

    if gap_info.gaps.is_empty() {
        info!(
            "Indexer catchup: no gaps detected, fully synced at block {}",
            gap_info.db_height
        );
    } else {
        info!(
            "Indexer catchup: found {} gaps totaling {} missing blocks (DB height: {}, chain height: {})",
            gap_info.gaps.len(),
            gap_info.total_missing,
            gap_info.db_height,
            chain_height
        );
        for (i, (start, end)) in gap_info.gaps.iter().enumerate().take(10) {
            info!(
                "  Gap {}: blocks {} to {} ({} blocks)",
                i + 1,
                start,
                end,
                end - start + 1
            );
        }
        if gap_info.gaps.len() > 10 {
            info!("  ... and {} more gaps", gap_info.gaps.len() - 10);
        }

        let metrics = IndexerMetrics::global();
        metrics.catchup_blocks_remaining.set(gap_info.total_missing);
        metrics
            .indexer_lag_blocks
            .set(chain_height - gap_info.db_height);
    }

    // Compress any old uncompressed chunks on startup
    match compress_old_chunks(pool, 7).await {
        Ok(n) if n > 0 => info!("Startup: compressed {} old chunks", n),
        Ok(_) => {}
        Err(e) => error!("Startup compression failed: {}", e),
    }

    Ok(gap_info)
}
