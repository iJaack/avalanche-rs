use prometheus::{Histogram, HistogramOpts, IntCounter, IntGauge, Registry};
use std::sync::OnceLock;

static INDEXER_METRICS: OnceLock<IndexerMetrics> = OnceLock::new();

/// Prometheus metrics for the indexer pipeline.
pub struct IndexerMetrics {
    pub blocks_indexed: IntCounter,
    pub transactions_indexed: IntCounter,
    pub logs_indexed: IntCounter,
    pub batches_flushed: IntCounter,
    pub batch_size: Histogram,
    pub batch_write_duration: Histogram,
    pub indexer_height: IntGauge,
    pub indexer_lag_blocks: IntGauge,
    pub queue_depth: IntGauge,
    pub write_errors: IntCounter,
    pub storage_bytes_estimate: IntGauge,
    pub catchup_blocks_remaining: IntGauge,
    pub catchup_blocks_per_sec: IntGauge,
}

impl IndexerMetrics {
    pub fn global() -> &'static IndexerMetrics {
        INDEXER_METRICS.get_or_init(|| IndexerMetrics::new(&Registry::new()))
    }

    pub fn init(registry: &Registry) -> &'static IndexerMetrics {
        INDEXER_METRICS.get_or_init(|| IndexerMetrics::new(registry))
    }

    fn new(registry: &Registry) -> Self {
        let blocks_indexed = IntCounter::new(
            "indexer_blocks_indexed_total",
            "Total blocks written to PostgreSQL",
        )
        .unwrap();

        let transactions_indexed = IntCounter::new(
            "indexer_transactions_indexed_total",
            "Total transactions written",
        )
        .unwrap();

        let logs_indexed =
            IntCounter::new("indexer_logs_indexed_total", "Total event logs written").unwrap();

        let batches_flushed =
            IntCounter::new("indexer_batches_flushed_total", "Total batch flushes").unwrap();

        let batch_size = Histogram::with_opts(
            HistogramOpts::new("indexer_batch_size", "Number of blocks per batch flush")
                .buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0]),
        )
        .unwrap();

        let batch_write_duration = Histogram::with_opts(
            HistogramOpts::new(
                "indexer_batch_write_duration_seconds",
                "Time to write a batch to PostgreSQL",
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        )
        .unwrap();

        let indexer_height =
            IntGauge::new("indexer_height", "Highest block number indexed").unwrap();

        let indexer_lag_blocks = IntGauge::new(
            "indexer_lag_blocks",
            "Blocks behind chain tip (0 = caught up)",
        )
        .unwrap();

        let queue_depth = IntGauge::new(
            "indexer_queue_depth",
            "Blocks waiting in the indexer channel",
        )
        .unwrap();

        let write_errors =
            IntCounter::new("indexer_write_errors_total", "Total batch write failures").unwrap();

        let storage_bytes_estimate = IntGauge::new(
            "indexer_storage_bytes_estimate",
            "Estimated storage usage in bytes",
        )
        .unwrap();

        let catchup_blocks_remaining = IntGauge::new(
            "indexer_catchup_blocks_remaining",
            "Blocks remaining in catchup sync",
        )
        .unwrap();

        let catchup_blocks_per_sec = IntGauge::new(
            "indexer_catchup_blocks_per_sec",
            "Catchup sync throughput (blocks/sec)",
        )
        .unwrap();

        let _ = registry.register(Box::new(blocks_indexed.clone()));
        let _ = registry.register(Box::new(transactions_indexed.clone()));
        let _ = registry.register(Box::new(logs_indexed.clone()));
        let _ = registry.register(Box::new(batches_flushed.clone()));
        let _ = registry.register(Box::new(batch_size.clone()));
        let _ = registry.register(Box::new(batch_write_duration.clone()));
        let _ = registry.register(Box::new(indexer_height.clone()));
        let _ = registry.register(Box::new(indexer_lag_blocks.clone()));
        let _ = registry.register(Box::new(queue_depth.clone()));
        let _ = registry.register(Box::new(write_errors.clone()));
        let _ = registry.register(Box::new(storage_bytes_estimate.clone()));
        let _ = registry.register(Box::new(catchup_blocks_remaining.clone()));
        let _ = registry.register(Box::new(catchup_blocks_per_sec.clone()));

        Self {
            blocks_indexed,
            transactions_indexed,
            logs_indexed,
            batches_flushed,
            batch_size,
            batch_write_duration,
            indexer_height,
            indexer_lag_blocks,
            queue_depth,
            write_errors,
            storage_bytes_estimate,
            catchup_blocks_remaining,
            catchup_blocks_per_sec,
        }
    }
}
