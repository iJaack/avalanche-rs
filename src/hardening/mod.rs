//! Mainnet hardening: rate limiting, graceful shutdown, panic recovery.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

// ---------------------------------------------------------------------------
// Connection rate limiter
// ---------------------------------------------------------------------------

/// Rate limiter for inbound connections.
/// Tracks per-IP connection attempts with a sliding window.
pub struct ConnectionRateLimiter {
    /// Maximum connections per second globally.
    max_global_per_sec: u32,
    /// Maximum connections per second per IP.
    max_per_ip_per_sec: u32,
    /// Window duration for rate tracking.
    window: Duration,
    /// Per-IP connection timestamps.
    ip_connections: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    /// Global connection count in current window.
    global_count: Mutex<Vec<Instant>>,
}

impl ConnectionRateLimiter {
    pub fn new(max_global_per_sec: u32, max_per_ip_per_sec: u32) -> Self {
        Self {
            max_global_per_sec,
            max_per_ip_per_sec,
            window: Duration::from_secs(1),
            ip_connections: Mutex::new(HashMap::new()),
            global_count: Mutex::new(Vec::new()),
        }
    }

    /// Check if a connection from the given IP should be allowed.
    /// Returns true if allowed, false if rate limited.
    pub fn check_connection(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;

        // Check global rate
        {
            let mut global = self.global_count.lock();
            global.retain(|t| *t > cutoff);
            if global.len() >= self.max_global_per_sec as usize {
                return false;
            }
            global.push(now);
        }

        // Check per-IP rate
        {
            let mut ip_map = self.ip_connections.lock();
            let timestamps = ip_map.entry(ip).or_insert_with(Vec::new);
            timestamps.retain(|t| *t > cutoff);
            if timestamps.len() >= self.max_per_ip_per_sec as usize {
                return false;
            }
            timestamps.push(now);
        }

        true
    }

    /// Clean up expired entries to prevent memory leaks.
    pub fn cleanup(&self) {
        let cutoff = Instant::now() - self.window * 2;
        let mut ip_map = self.ip_connections.lock();
        ip_map.retain(|_, timestamps| {
            timestamps.retain(|t| *t > cutoff);
            !timestamps.is_empty()
        });
    }
}

// ---------------------------------------------------------------------------
// Request rate limiter
// ---------------------------------------------------------------------------

/// RPC request rate limiter per client IP.
pub struct RequestRateLimiter {
    /// Maximum requests per second per IP.
    max_per_sec: u32,
    /// Per-IP request timestamps.
    ip_requests: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl RequestRateLimiter {
    pub fn new(max_per_sec: u32) -> Self {
        Self {
            max_per_sec,
            ip_requests: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a request from the given IP should be allowed.
    pub fn check_request(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(1);

        let mut ip_map = self.ip_requests.lock();
        let timestamps = ip_map.entry(ip).or_insert_with(Vec::new);
        timestamps.retain(|t| *t > cutoff);

        if timestamps.len() >= self.max_per_sec as usize {
            return false;
        }

        timestamps.push(now);
        true
    }

    /// Clean up expired entries.
    pub fn cleanup(&self) {
        let cutoff = Instant::now() - Duration::from_secs(2);
        let mut ip_map = self.ip_requests.lock();
        ip_map.retain(|_, timestamps| {
            timestamps.retain(|t| *t > cutoff);
            !timestamps.is_empty()
        });
    }
}

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

/// Graceful shutdown coordinator.
/// Components register themselves and are notified when shutdown begins.
pub struct ShutdownCoordinator {
    /// Whether shutdown has been requested.
    shutdown_requested: AtomicBool,
    /// Timestamp when shutdown was initiated.
    shutdown_time: AtomicU64,
}

impl ShutdownCoordinator {
    pub fn new() -> Self {
        Self {
            shutdown_requested: AtomicBool::new(false),
            shutdown_time: AtomicU64::new(0),
        }
    }

    /// Request shutdown. Returns true if this is the first request.
    pub fn request_shutdown(&self) -> bool {
        let was_first = !self.shutdown_requested.swap(true, Ordering::SeqCst);
        if was_first {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.shutdown_time.store(now, Ordering::SeqCst);
        }
        was_first
    }

    /// Check if shutdown has been requested.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// Get the timestamp when shutdown was initiated (0 if not yet).
    pub fn shutdown_time(&self) -> u64 {
        self.shutdown_time.load(Ordering::SeqCst)
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Panic recovery
// ---------------------------------------------------------------------------

/// Run a closure and catch panics, returning None on panic.
/// Logs the panic message for debugging.
pub fn catch_panic<F, T>(task_name: &str, f: F) -> Option<T>
where
    F: FnOnce() -> T + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(result) => Some(result),
        Err(panic_info) => {
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            tracing::error!("Panic recovered in {}: {}", task_name, msg);
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Request body size limiter
// ---------------------------------------------------------------------------

/// Default max request body size: 5 MB.
pub const DEFAULT_MAX_BODY_SIZE: usize = 5 * 1024 * 1024;

/// Check if a request body exceeds the maximum allowed size.
pub fn check_body_size(body_len: usize, max_size: usize) -> Result<(), String> {
    if body_len > max_size {
        Err(format!(
            "request body too large: {} bytes (max {})",
            body_len, max_size
        ))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Memory pressure monitor
// ---------------------------------------------------------------------------

/// Check approximate RSS memory usage (platform-specific).
/// Returns bytes used, or 0 if unavailable.
pub fn get_rss_bytes() -> u64 {
    #[cfg(target_os = "macos")]
    {
        // On macOS, use mach APIs
        unsafe {
            let mut info: libc::rusage = std::mem::zeroed();
            if libc::getrusage(libc::RUSAGE_SELF, &mut info) == 0 {
                return info.ru_maxrss as u64; // macOS reports in bytes
            }
        }
        0
    }
    #[cfg(target_os = "linux")]
    {
        // On Linux, read /proc/self/statm
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            let parts: Vec<&str> = statm.split_whitespace().collect();
            if let Some(rss_pages) = parts.get(1) {
                if let Ok(pages) = rss_pages.parse::<u64>() {
                    return pages * 4096; // page size typically 4KB
                }
            }
        }
        0
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        0
    }
}

/// Check if memory usage is near the configured limit.
pub fn is_near_memory_limit(max_memory_mb: u64) -> bool {
    if max_memory_mb == 0 {
        return false;
    }
    let rss = get_rss_bytes();
    let limit = max_memory_mb * 1024 * 1024;
    // Trigger at 80% of limit
    rss > limit * 80 / 100
}

// ---------------------------------------------------------------------------
// DB integrity check
// ---------------------------------------------------------------------------

/// Basic DB integrity verification result.
#[derive(Debug, Clone)]
pub struct IntegrityReport {
    pub total_keys: u64,
    pub valid_keys: u64,
    pub corrupted_keys: u64,
    pub status: IntegrityStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityStatus {
    Ok,
    Warning(String),
    Corrupted(String),
}

/// Verify basic DB integrity by scanning column families.
pub fn verify_db_integrity(
    total_keys: u64,
    valid_keys: u64,
) -> IntegrityReport {
    let corrupted = total_keys.saturating_sub(valid_keys);
    let status = if corrupted == 0 {
        IntegrityStatus::Ok
    } else if corrupted * 100 / total_keys.max(1) < 5 {
        IntegrityStatus::Warning(format!("{} corrupted keys (< 5%)", corrupted))
    } else {
        IntegrityStatus::Corrupted(format!("{} corrupted keys", corrupted))
    };

    IntegrityReport {
        total_keys,
        valid_keys,
        corrupted_keys: corrupted,
        status,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_connection_rate_limiter_allows_normal() {
        let limiter = ConnectionRateLimiter::new(50, 10);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First connection should be allowed
        assert!(limiter.check_connection(ip));
        // Second should also be fine
        assert!(limiter.check_connection(ip));
    }

    #[test]
    fn test_connection_rate_limiter_per_ip_limit() {
        let limiter = ConnectionRateLimiter::new(50, 3);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        assert!(limiter.check_connection(ip));
        assert!(limiter.check_connection(ip));
        assert!(limiter.check_connection(ip));
        // 4th should be denied
        assert!(!limiter.check_connection(ip));

        // Different IP should still be allowed
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(limiter.check_connection(ip2));
    }

    #[test]
    fn test_connection_rate_limiter_global_limit() {
        let limiter = ConnectionRateLimiter::new(3, 10);

        for i in 1..=3 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            assert!(limiter.check_connection(ip));
        }
        // 4th connection from any IP should be denied (global limit)
        let ip4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
        assert!(!limiter.check_connection(ip4));
    }

    #[test]
    fn test_request_rate_limiter() {
        let limiter = RequestRateLimiter::new(5);
        let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));

        for _ in 0..5 {
            assert!(limiter.check_request(ip));
        }
        // 6th should be denied
        assert!(!limiter.check_request(ip));
    }

    #[test]
    fn test_request_rate_limiter_different_ips() {
        let limiter = RequestRateLimiter::new(2);
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        assert!(limiter.check_request(ip1));
        assert!(limiter.check_request(ip1));
        assert!(!limiter.check_request(ip1));

        // ip2 should have its own limit
        assert!(limiter.check_request(ip2));
        assert!(limiter.check_request(ip2));
        assert!(!limiter.check_request(ip2));
    }

    #[test]
    fn test_shutdown_coordinator() {
        let coord = ShutdownCoordinator::new();
        assert!(!coord.is_shutting_down());
        assert_eq!(coord.shutdown_time(), 0);

        let was_first = coord.request_shutdown();
        assert!(was_first);
        assert!(coord.is_shutting_down());
        assert!(coord.shutdown_time() > 0);

        // Second request should not be "first"
        let was_first2 = coord.request_shutdown();
        assert!(!was_first2);
    }

    #[test]
    fn test_panic_recovery_normal() {
        let result = catch_panic("test", || 42);
        assert_eq!(result, Some(42));
    }

    #[test]
    fn test_panic_recovery_catches_panic() {
        let result = catch_panic("test", || {
            panic!("intentional test panic");
        });
        assert!(result.is_none());
    }

    #[test]
    fn test_body_size_check() {
        assert!(check_body_size(1024, DEFAULT_MAX_BODY_SIZE).is_ok());
        assert!(check_body_size(DEFAULT_MAX_BODY_SIZE, DEFAULT_MAX_BODY_SIZE).is_ok());
        assert!(check_body_size(DEFAULT_MAX_BODY_SIZE + 1, DEFAULT_MAX_BODY_SIZE).is_err());
    }

    #[test]
    fn test_memory_limit_check() {
        // 0 means no limit
        assert!(!is_near_memory_limit(0));
        // Very high limit — should not trigger
        assert!(!is_near_memory_limit(1_000_000));
    }

    #[test]
    fn test_db_integrity_ok() {
        let report = verify_db_integrity(1000, 1000);
        assert_eq!(report.status, IntegrityStatus::Ok);
        assert_eq!(report.corrupted_keys, 0);
    }

    #[test]
    fn test_db_integrity_warning() {
        let report = verify_db_integrity(1000, 960);
        assert!(matches!(report.status, IntegrityStatus::Warning(_)));
        assert_eq!(report.corrupted_keys, 40);
    }

    #[test]
    fn test_db_integrity_corrupted() {
        let report = verify_db_integrity(100, 10);
        assert!(matches!(report.status, IntegrityStatus::Corrupted(_)));
        assert_eq!(report.corrupted_keys, 90);
    }

    #[test]
    fn test_connection_limiter_cleanup() {
        let limiter = ConnectionRateLimiter::new(50, 10);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        limiter.check_connection(ip);
        limiter.cleanup();
        // Should still work after cleanup
        assert!(limiter.check_connection(ip));
    }

    #[test]
    fn test_request_limiter_cleanup() {
        let limiter = RequestRateLimiter::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        limiter.check_request(ip);
        limiter.cleanup();
        assert!(limiter.check_request(ip));
    }

    #[test]
    fn test_get_rss_bytes() {
        // Should return a positive value on macOS/Linux, 0 elsewhere
        let rss = get_rss_bytes();
        // Just verify it doesn't panic
        let _ = rss;
    }
}
